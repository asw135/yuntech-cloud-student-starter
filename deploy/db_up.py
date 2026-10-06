#!/usr/bin/env python3
"""Create the explicitly scoped W5 private PostgreSQL resources."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab

MANIFEST = ROOT / ".local/resources.json"
DB_ENV = ROOT / ".local/db.env"
VPC_ID = "vpc-0de66d6e37108bab4"
INSTANCE_ID = "i-00e72275020e7d588"
PRIVATE_SUBNETS = (
    ("172.31.96.0/24", "us-east-1a", "a"),
    ("172.31.97.0/24", "us-east-1b", "b"),
)
DB_INSTANCE_ID = "w05-inspection-aabbcc-w3-lab"
DB_SUBNET_GROUP = "w05-inspection-aabbcc-w3-lab"
DB_SECURITY_GROUP_NAME = "w05-db-aabbcc-w3-lab"
W5_MANIFEST_KEYS = {
    "w05_private_subnet_ids",
    "w05_route_table_id",
    "w05_route_table_association_ids",
    "w05_db_security_group_id",
    "w05_db_subnet_group_name",
    "w05_db_instance_identifier",
}


def aws(args, region):
    return lab.run_aws(args, region)


def tags(week="w05", suffix=None):
    values = {
        "course": lab.COURSE,
        "week": week,
        "group": "aabbcc",
        "owner": "W3_Lab",
    }
    if suffix:
        values["Name"] = suffix
    return [{"Key": key, "Value": value} for key, value in values.items()]


def tag_spec(resource_type, values):
    return json.dumps(
        [{"ResourceType": resource_type, "Tags": values}], separators=(",", ":")
    )


def read_context():
    if MANIFEST.parent.is_symlink() or MANIFEST.is_symlink() or not MANIFEST.is_file():
        raise lab.LabError("STOP: .local/resources.json must be a regular file.")
    try:
        resources = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise lab.LabError("STOP: resource manifest is unreadable or invalid.") from None
    if (
        resources.get("region") != "us-east-1"
        or resources.get("course") != lab.COURSE
        or resources.get("week") != "w04"
        or resources.get("group") != "aabbcc"
        or resources.get("owner") != "W3_Lab"
        or resources.get("instance_id") != INSTANCE_ID
        or resources.get("security_group_id") != "sg-086f87b7a14679638"
    ):
        raise lab.LabError("STOP: resource manifest does not match the approved W4 host.")
    if W5_MANIFEST_KEYS.intersection(resources):
        raise lab.LabError(
            "STOP: W5 resource IDs already exist in the manifest; inspect them before retrying."
        )
    return resources


def write_manifest(resources):
    if MANIFEST.is_symlink() or MANIFEST.parent.is_symlink():
        raise lab.LabError("STOP: refusing a symlinked resource manifest.")
    fd, temp_name = tempfile.mkstemp(prefix=".resources-w05-", dir=MANIFEST.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(resources, stream, indent=2)
            stream.write("\n")
        os.replace(temp_name, MANIFEST)
        os.chmod(MANIFEST, 0o600)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def build_plan(context, resources):
    region = context["region"]
    instance = aws(
        [
            "ec2",
            "describe-instances",
            "--instance-ids",
            INSTANCE_ID,
            "--query",
            "Reservations[].Instances[].{Id:InstanceId,State:State.Name,Vpc:VpcId,Subnet:SubnetId,Groups:SecurityGroups[].GroupId,Tags:Tags}",
        ],
        region,
    )
    if len(instance) != 1:
        raise lab.LabError("STOP: expected exactly one recorded EC2 host.")
    host = instance[0]
    host_tags = {item["Key"]: item["Value"] for item in host.get("Tags", [])}
    if (
        host["State"] != "running"
        or host["Vpc"] != VPC_ID
        or "sg-086f87b7a14679638" not in host["Groups"]
        or host_tags.get("course") != lab.COURSE
        or host_tags.get("group") != "aabbcc"
        or host_tags.get("owner") != "W3_Lab"
    ):
        raise lab.LabError("STOP: EC2 host is not running with the expected ownership/network.")

    vpcs = aws(
        [
            "ec2",
            "describe-vpcs",
            "--vpc-ids",
            VPC_ID,
            "--query",
            "Vpcs[].{Id:VpcId,State:State,Cidrs:CidrBlockAssociationSet[?CidrBlockState.State=='associated'].CidrBlock}",
        ],
        region,
    )
    if len(vpcs) != 1 or vpcs[0]["State"] != "available" or "172.31.0.0/16" not in vpcs[0]["Cidrs"]:
        raise lab.LabError("STOP: the approved VPC is missing or changed.")

    subnets = aws(
        [
            "ec2",
            "describe-subnets",
            "--filters",
            f"Name=vpc-id,Values={VPC_ID}",
            "--query",
            "Subnets[].{Id:SubnetId,Cidr:CidrBlock,AZ:AvailabilityZone,State:State}",
        ],
        region,
    )
    networks = [ipaddress.ip_network(item["Cidr"]) for item in subnets]
    for cidr, az, _ in PRIVATE_SUBNETS:
        candidate = ipaddress.ip_network(cidr)
        if not any(candidate.overlaps(existing) for existing in networks):
            continue
        raise lab.LabError(f"STOP: candidate private subnet {cidr} now overlaps an existing subnet.")

    zones = aws(
        [
            "ec2",
            "describe-availability-zones",
            "--filters",
            "Name=zone-name,Values=us-east-1a,us-east-1b",
            "--query",
            "AvailabilityZones[].{Name:ZoneName,State:State}",
        ],
        region,
    )
    available_zones = {item["Name"] for item in zones if item["State"] == "available"}
    if not {az for _, az, _ in PRIVATE_SUBNETS}.issubset(available_zones):
        raise lab.LabError("STOP: an approved Availability Zone is unavailable.")

    dbs = aws(
        [
            "rds",
            "describe-db-instances",
            "--query",
            "DBInstances[].DBInstanceIdentifier",
        ],
        region,
    )
    if DB_INSTANCE_ID in dbs:
        raise lab.LabError("STOP: the planned RDS identifier already exists; inspect before retrying.")
    subnet_groups = aws(
        ["rds", "describe-db-subnet-groups", "--query", "DBSubnetGroups[].DBSubnetGroupName"],
        region,
    )
    if DB_SUBNET_GROUP in subnet_groups:
        raise lab.LabError("STOP: the planned DB subnet group name already exists.")
    existing_db_groups = aws(
        [
            "ec2",
            "describe-security-groups",
            "--filters",
            f"Name=vpc-id,Values={VPC_ID}",
            f"Name=group-name,Values={DB_SECURITY_GROUP_NAME}",
            "--query",
            "SecurityGroups[].GroupId",
        ],
        region,
    )
    if existing_db_groups:
        raise lab.LabError("STOP: the planned DB security group name already exists.")
    owned_filters = [
        f"Name=vpc-id,Values={VPC_ID}",
        f"Name=tag:course,Values={lab.COURSE}",
        "Name=tag:week,Values=w05",
        "Name=tag:group,Values=aabbcc",
        "Name=tag:owner,Values=W3_Lab",
    ]
    resource_queries = {
        "subnets": ("Subnets", "SubnetId"),
        "route-tables": ("RouteTables", "RouteTableId"),
        "security-groups": ("SecurityGroups", "GroupId"),
    }
    for operation, (response_key, id_key) in resource_queries.items():
        owned_resources = aws(
            [
                "ec2",
                f"describe-{operation}",
                "--filters",
                *owned_filters,
                "--query",
                f"{response_key}[].{id_key}",
            ],
            region,
        )
        if owned_resources:
            raise lab.LabError(
                f"STOP: existing W5-owned {operation} were found; inspect before creating duplicates."
            )
    if DB_ENV.is_symlink() or os.path.lexists(DB_ENV):
        raise lab.LabError("STOP: .local/db.env already exists; refusing to overwrite database credentials.")
    if resources.get("w05_db_instance_identifier"):
        raise lab.LabError("STOP: a W5 database is already recorded.")
    return {
        "instance_id": INSTANCE_ID,
        "vpc_id": VPC_ID,
        "host_security_group_id": "sg-086f87b7a14679638",
        "subnets": [
            {"cidr": cidr, "az": az, "suffix": suffix}
            for cidr, az, suffix in PRIVATE_SUBNETS
        ],
        "db_subnet_group": DB_SUBNET_GROUP,
        "db_security_group": DB_SECURITY_GROUP_NAME,
        "db_instance_identifier": DB_INSTANCE_ID,
        "rds": {
            "engine": "postgres",
            "class": "db.t3.micro",
            "storage_gib": 20,
            "storage_type": "gp3",
            "encrypted": True,
            "multi_az": False,
            "publicly_accessible": False,
            "database": "inspection",
            "master_username": "inspection_admin",
            "backup_retention_days": 1,
        },
        "region": region,
    }


def show_plan(plan):
    print("Planned W5 resources (no changes have been made yet):")
    print(json.dumps(plan, indent=2))
    print("Network exposure: private subnets have only the VPC local route.")
    print("DB ingress: TCP 5432 from EC2 security group only; no public DB, NAT, or IAM changes.")
    print("Estimated on-demand RDS cost using the discussed assumptions: about $0.018 per running hour")
    print("plus about $2.30 per 730-hour month for 20 GiB storage (~$15.44 at 730 running hours); not a billing cap.")
    print("Cleanup: stop only this DB and the recorded EC2 for W5 retention; retain subnet/network resources.")
    print("RDS restarts automatically after at most 7 stopped days; storage/backup charges continue while stopped.")


def make_tags(name):
    return tags(suffix=name)


def create_subnet(plan, subnet):
    response = aws(
        [
            "ec2",
            "create-subnet",
            "--vpc-id",
            VPC_ID,
            "--cidr-block",
            subnet["cidr"],
            "--availability-zone",
            subnet["az"],
            "--tag-specifications",
            tag_spec("subnet", make_tags(f"w05-db-aabbcc-W3_Lab-{subnet['suffix']}")),
        ],
        plan["region"],
    )
    subnet_id = response["Subnet"]["SubnetId"]
    aws(
        [
            "ec2",
            "modify-subnet-attribute",
            "--subnet-id",
            subnet_id,
            "--no-map-public-ip-on-launch",
        ],
        plan["region"],
    )
    return subnet_id


def create_route_table(plan):
    response = aws(
        [
            "ec2",
            "create-route-table",
            "--vpc-id",
            VPC_ID,
            "--tag-specifications",
            tag_spec("route-table", make_tags("w05-db-aabbcc-W3_Lab-private")),
        ],
        plan["region"],
    )
    route_table_id = response["RouteTable"]["RouteTableId"]
    route_table = aws(
        [
            "ec2",
            "describe-route-tables",
            "--route-table-ids",
            route_table_id,
            "--query",
            "RouteTables[].{Id:RouteTableId,Routes:Routes[].{DestinationCidrBlock:DestinationCidrBlock,GatewayId:GatewayId,State:State},Associations:Associations}",
        ],
        plan["region"],
    )[0]
    expected = [{"DestinationCidrBlock": "172.31.0.0/16", "GatewayId": "local", "State": "active"}]
    if (
        route_table["Routes"] != expected
        or any(item.get("Main") is True for item in route_table["Associations"])
    ):
        raise lab.LabError("STOP: newly created private route table does not contain only the local route.")
    return route_table_id


def create_db_security_group(plan):
    response = aws(
        [
            "ec2",
            "create-security-group",
            "--group-name",
            DB_SECURITY_GROUP_NAME,
            "--description",
            "W5 private inspection PostgreSQL; ingress only from the recorded EC2 security group",
            "--vpc-id",
            VPC_ID,
            "--tag-specifications",
            tag_spec("security-group", make_tags(DB_SECURITY_GROUP_NAME)),
        ],
        plan["region"],
    )
    group_id = response["GroupId"]
    groups = aws(
        ["ec2", "describe-security-groups", "--group-ids", group_id],
        plan["region"],
    )["SecurityGroups"]
    for permission in groups[0].get("IpPermissionsEgress", []):
        aws(
            [
                "ec2",
                "revoke-security-group-egress",
                "--group-id",
                group_id,
                "--ip-permissions",
                json.dumps(permission, separators=(",", ":")),
            ],
            plan["region"],
        )
    aws(
        [
            "ec2",
            "authorize-security-group-ingress",
            "--group-id",
            group_id,
            "--ip-permissions",
            json.dumps(
                [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "UserIdGroupPairs": [
                            {"GroupId": plan["host_security_group_id"]}
                        ],
                    }
                ],
                separators=(",", ":"),
            ),
        ],
        plan["region"],
    )
    return group_id


def verify_private_network(plan, subnet_ids, route_table_id, association_ids):
    subnets = aws(
        [
            "ec2",
            "describe-subnets",
            "--subnet-ids",
            *subnet_ids,
            "--query",
            "Subnets[].{Id:SubnetId,Vpc:VpcId,Cidr:CidrBlock,AZ:AvailabilityZone,State:State,MapPublicIpOnLaunch:MapPublicIpOnLaunch}",
        ],
        plan["region"],
    )
    expected_subnets = {
        (item["cidr"], item["az"]) for item in plan["subnets"]
    }
    actual_subnets = {
        (item["Cidr"], item["AZ"])
        for item in subnets
        if item["Vpc"] == VPC_ID
        and item["State"] == "available"
        and item["MapPublicIpOnLaunch"] is False
    }
    if len(subnets) != 2 or actual_subnets != expected_subnets:
        raise lab.LabError("STOP: private subnet read-back did not match the approved CIDRs/AZs.")

    route_table = aws(
        [
            "ec2",
            "describe-route-tables",
            "--route-table-ids",
            route_table_id,
            "--query",
            "RouteTables[].{Routes:Routes[].{DestinationCidrBlock:DestinationCidrBlock,GatewayId:GatewayId,State:State},Associations:Associations[].{Id:RouteTableAssociationId,SubnetId:SubnetId,State:AssociationState.State,Main:Main}}",
        ],
        plan["region"],
    )[0]
    expected_route = [
        {
            "DestinationCidrBlock": "172.31.0.0/16",
            "GatewayId": "local",
            "State": "active",
        }
    ]
    expected_associations = set(zip(association_ids, subnet_ids))
    actual_associations = {
        (item["Id"], item["SubnetId"])
        for item in route_table["Associations"]
        if item["State"] == "associated" and item.get("Main") is not True
    }
    if (
        route_table["Routes"] != expected_route
        or actual_associations != expected_associations
    ):
        raise lab.LabError("STOP: route table is not local-only or subnet associations differ.")


def verify_db_security_group(plan, security_group_id):
    groups = aws(
        ["ec2", "describe-security-groups", "--group-ids", security_group_id],
        plan["region"],
    )["SecurityGroups"]
    if len(groups) != 1:
        raise lab.LabError("STOP: DB security group read-back did not return exactly one group.")
    group = groups[0]
    permissions = group.get("IpPermissions", [])
    pairs = permissions[0].get("UserIdGroupPairs", []) if len(permissions) == 1 else []
    if (
        group.get("VpcId") != VPC_ID
        or group.get("GroupName") != DB_SECURITY_GROUP_NAME
        or len(permissions) != 1
        or permissions[0].get("IpProtocol") != "tcp"
        or permissions[0].get("FromPort") != 5432
        or permissions[0].get("ToPort") != 5432
        or len(pairs) != 1
        or pairs[0].get("GroupId") != plan["host_security_group_id"]
        or permissions[0].get("IpRanges")
        or permissions[0].get("Ipv6Ranges")
        or permissions[0].get("PrefixListIds")
        or group.get("IpPermissionsEgress")
    ):
        raise lab.LabError("STOP: DB security group rules differ from the approved least-privilege rules.")


def write_db_env(password, host=None):
    if DB_ENV.is_symlink() or os.path.lexists(DB_ENV):
        raise lab.LabError("STOP: .local/db.env already exists; refusing to overwrite it.")
    content = (
        f"DB_HOST={host or 'pending'}\n"
        "DB_NAME=inspection\n"
        "DB_USER=inspection_admin\n"
        f"DB_PASSWORD={password}\n"
    )
    fd = os.open(DB_ENV, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)


def create_rds(plan, security_group_id):
    password = "".join(
        secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        for _ in range(40)
    )
    write_db_env(password)
    request = {
        "DBInstanceIdentifier": DB_INSTANCE_ID,
        "AllocatedStorage": 20,
        "DBInstanceClass": "db.t3.micro",
        "Engine": "postgres",
        "DBName": "inspection",
        "MasterUsername": "inspection_admin",
        "MasterUserPassword": password,
        "VpcSecurityGroupIds": [security_group_id],
        "DBSubnetGroupName": DB_SUBNET_GROUP,
        "BackupRetentionPeriod": 1,
        "StorageType": "gp3",
        "StorageEncrypted": True,
        "MultiAZ": False,
        "PubliclyAccessible": False,
        "DeletionProtection": False,
        "Tags": make_tags(DB_INSTANCE_ID),
    }
    fd, config_name = tempfile.mkstemp(prefix=".w05-rds-", suffix=".json", dir=ROOT / ".local")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(request, stream)
        result = aws(
            ["rds", "create-db-instance", "--cli-input-json", f"file://{config_name}"],
            plan["region"],
        )
    finally:
        if os.path.exists(config_name):
            os.unlink(config_name)
    return result["DBInstance"]["DBInstanceIdentifier"]


def persist_ids(resources, key, value):
    resources[key] = value
    write_manifest(resources)


def main():
    if sys.argv[1:] not in ([], ["--plan"]):
        raise lab.LabError("Usage: deploy/db-up.sh [--plan]")
    ctx = lab.verify()
    resources = read_context()
    plan = build_plan(ctx, resources)
    show_plan(plan)
    if sys.argv[1:] == ["--plan"]:
        print("Plan only: no AWS resources were created.")
        return
    if not sys.stdin.isatty():
        raise lab.LabError("STOP: resource creation requires interactive approval in a terminal.")
    approval = "CREATE " + plan["db_instance_identifier"]
    if input(f"Type exactly {approval} to create these resources: ").strip() != approval:
        print("Cancelled; no changes made.")
        return

    subnet_ids = []
    for subnet in plan["subnets"]:
        subnet_id = create_subnet(plan, subnet)
        subnet_ids.append(subnet_id)
        persist_ids(resources, "w05_private_subnet_ids", subnet_ids)
        print(f"Created private subnet {subnet['cidr']} ({subnet['az']}): {subnet_id}")

    route_table_id = create_route_table(plan)
    persist_ids(resources, "w05_route_table_id", route_table_id)
    association_ids = []
    for subnet_id in subnet_ids:
        association = aws(
            [
                "ec2",
                "associate-route-table",
                "--route-table-id",
                route_table_id,
                "--subnet-id",
                subnet_id,
            ],
            plan["region"],
        )
        association_ids.append(association["AssociationId"])
        persist_ids(resources, "w05_route_table_association_ids", association_ids)
    print(f"Created local-only route table: {route_table_id}")
    verify_private_network(plan, subnet_ids, route_table_id, association_ids)

    security_group_id = create_db_security_group(plan)
    persist_ids(resources, "w05_db_security_group_id", security_group_id)
    verify_db_security_group(plan, security_group_id)
    subnet_group = aws(
        [
            "rds",
            "create-db-subnet-group",
            "--db-subnet-group-name",
            DB_SUBNET_GROUP,
            "--db-subnet-group-description",
            "W5 private PostgreSQL subnets for aabbcc W3_Lab",
            "--subnet-ids",
            *subnet_ids,
            "--tags",
            json.dumps(make_tags(DB_SUBNET_GROUP), separators=(",", ":")),
        ],
        plan["region"],
    )
    subnet_group_name = subnet_group["DBSubnetGroup"]["DBSubnetGroupName"]
    persist_ids(resources, "w05_db_subnet_group_name", subnet_group_name)
    subnet_group_readback = aws(
        [
            "rds",
            "describe-db-subnet-groups",
            "--db-subnet-group-name",
            subnet_group_name,
        ],
        plan["region"],
    )["DBSubnetGroups"]
    if (
        len(subnet_group_readback) != 1
        or subnet_group_readback[0]["VpcId"] != VPC_ID
        or subnet_group_readback[0]["SubnetGroupStatus"] != "Complete"
        or {
            item["SubnetIdentifier"]
            for item in subnet_group_readback[0]["Subnets"]
            if item["SubnetStatus"] == "Active"
        }
        != set(subnet_ids)
    ):
        raise lab.LabError("STOP: DB subnet group read-back did not match the two private subnets.")

    db_instance_identifier = create_rds(plan, security_group_id)
    persist_ids(resources, "w05_db_instance_identifier", db_instance_identifier)
    print("RDS creation started; waiting for available status (password not displayed).")
    deadline = time.monotonic() + 45 * 60
    while time.monotonic() < deadline:
        databases = aws(
            [
                "rds",
                "describe-db-instances",
                "--db-instance-identifier",
                DB_INSTANCE_ID,
            ],
            plan["region"],
        )["DBInstances"]
        if len(databases) != 1:
            raise lab.LabError("STOP: RDS read-back did not return exactly one database.")
        db = databases[0]
        status = db["DBInstanceStatus"]
        print(f"RDS status: {status}", flush=True)
        if status == "available":
            if db["PubliclyAccessible"] is not False:
                raise lab.LabError("STOP: RDS unexpectedly reports PubliclyAccessible=true.")
            if db.get("StorageEncrypted") is not True or db.get("MultiAZ") is not False:
                raise lab.LabError("STOP: RDS encryption or Single-AZ setting failed read-back.")
            endpoint = db.get("Endpoint", {}).get("Address")
            if not endpoint:
                raise lab.LabError("STOP: available RDS instance has no endpoint.")
            secret = DB_ENV.read_text(encoding="utf-8")
            DB_ENV.write_text(secret.replace("DB_HOST=pending\n", f"DB_HOST={endpoint}\n"), encoding="utf-8")
            os.chmod(DB_ENV, 0o600)
            print(
                json.dumps(
                    {
                        "db_instance_identifier": DB_INSTANCE_ID,
                        "status": status,
                        "publicly_accessible": db["PubliclyAccessible"],
                        "storage_encrypted": db["StorageEncrypted"],
                        "multi_az": db["MultiAZ"],
                        "endpoint": endpoint,
                        "db_env_mode": oct(DB_ENV.stat().st_mode & 0o777),
                    },
                    indent=2,
                )
            )
            return
        if status in {"failed", "incompatible-parameters", "incompatible-network", "storage-full"}:
            raise lab.LabError(f"STOP: RDS entered terminal status {status}; inspect recorded resources.")
        time.sleep(20)
    raise lab.LabError(
        "STOP: RDS did not become available within 45 minutes; resource IDs remain recorded, do not rerun blindly."
    )


if __name__ == "__main__":
    try:
        main()
    except lab.LabError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
