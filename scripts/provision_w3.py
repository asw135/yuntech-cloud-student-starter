#!/usr/bin/env python3
"""Create the explicitly scoped W4 inspection host through the course AWS wrapper."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab

VPC_ID = "vpc-0de66d6e37108bab4"
SUBNET_ID = "subnet-0eb278481e2bd97ed"
AMI_ID = "ami-0b2c9d1f3edcfd709"
KEY_NAME = "w03-ec2-key"
KEY_PUBLIC = Path.home() / ".ssh/w03-ec2.pub"
KEY_PRIVATE = Path.home() / ".ssh/w03-ec2"
MANIFEST = ROOT / ".local/resources.json"


def aws(args, region):
    return lab.run_aws(args, region)


def current_public_ip():
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as response:
        return response.read().decode("ascii").strip()


def verify_plan(group, owner, source_cidr, commit):
    if group != "aabbcc" or owner != "W3_Lab":
        raise lab.LabError("Group/owner differ from the confirmed deployment plan.")
    if str(ipaddress.ip_network(source_cidr, strict=True)) != "23.97.62.135/32":
        raise lab.LabError("Source CIDR differs from the confirmed deployment plan.")
    if current_public_ip() + "/32" != source_cidr:
        raise lab.LabError("Codespace public IP changed; stop and review the new /32.")
    context = lab.verify()
    if context["region"] != "us-east-1":
        raise lab.LabError("Confirmed plan is restricted to us-east-1.")
    existing = None
    if MANIFEST.is_symlink():
        raise lab.LabError("Refusing a symlinked resource manifest.")
    if MANIFEST.exists():
        if not MANIFEST.is_file():
            raise lab.LabError("Resource manifest is not a regular file.")
        try:
            existing = json.loads(MANIFEST.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise lab.LabError("Resource manifest is unreadable or invalid JSON.") from None
        expected_manifest = {
            "region": context["region"], "course": lab.COURSE, "week": "w04",
            "group": group, "owner": owner,
        }
        if any(existing.get(key) != value for key, value in expected_manifest.items()):
            raise lab.LabError("Existing resource manifest does not match this approved deployment.")
        if existing.get("commit") != commit or existing.get("instance_id") is not None:
            raise lab.LabError("Manifest already records another commit or an instance; refusing duplicate launch.")
        previous_source = existing.get("source_cidr")
        if previous_source not in ("23.97.62.118/32", source_cidr):
            raise lab.LabError("Manifest source CIDR is not the exact previously approved value.")
        security_group_id = existing.get("security_group_id", "")
        if not re.fullmatch(r"sg-[0-9a-f]+", security_group_id):
            raise lab.LabError("Manifest has no valid security group ID.")
        groups = aws(["ec2", "describe-security-groups", "--group-ids", security_group_id,
                      "--query", "SecurityGroups[].{Id:GroupId,Name:GroupName,Vpc:VpcId,Tags:Tags,Ingress:IpPermissions,Egress:IpPermissionsEgress}"], context["region"])
        if len(groups) != 1:
            raise lab.LabError("Recorded security group could not be read back.")
        security_group = groups[0]
        group_name = f"w04-inspection-{group}-{owner}"
        actual_tags = {tag["Key"]: tag["Value"] for tag in security_group.get("Tags", [])}
        expected_tags = {"course": lab.COURSE, "week": "w04", "group": group, "owner": owner}
        ingress = set()
        for permission in security_group.get("Ingress", []):
            if permission.get("IpProtocol") != "tcp" or permission.get("FromPort") != permission.get("ToPort"):
                raise lab.LabError("Recorded security group has unexpected ingress rules.")
            if permission.get("Ipv6Ranges") or permission.get("PrefixListIds") or permission.get("UserIdGroupPairs"):
                raise lab.LabError("Recorded security group has unexpected ingress sources.")
            ingress.update(("tcp", permission["FromPort"], item.get("CidrIp")) for item in permission.get("IpRanges", []))
        egress = security_group.get("Egress", [])
        if not (
            security_group.get("Name") == group_name
            and security_group.get("Vpc") == VPC_ID
            and actual_tags == expected_tags
            and ingress == {("tcp", 22, previous_source), ("tcp", 80, previous_source)}
            and len(egress) == 1 and egress[0].get("IpProtocol") == "-1"
            and [item.get("CidrIp") for item in egress[0].get("IpRanges", [])] == ["0.0.0.0/0"]
            and not egress[0].get("Ipv6Ranges")
        ):
            raise lab.LabError("Recorded security group does not exactly match the approved ownership and network plan.")
        instances = aws(["ec2", "describe-instances", "--filters",
                         f"Name=tag:course,Values={lab.COURSE}", "Name=tag:week,Values=w04",
                         f"Name=tag:group,Values={group}", f"Name=tag:owner,Values={owner}",
                         "--query", "Reservations[].Instances[].InstanceId"], context["region"])
        if instances:
            raise lab.LabError("An instance already exists for this deployment; refusing duplicate launch.")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise lab.LabError("Deployment commit must be a full Git SHA.")
    if not KEY_PRIVATE.is_file() or KEY_PRIVATE.is_symlink() or KEY_PRIVATE.stat().st_mode & 0o777 != 0o600:
        raise lab.LabError("Expected ~/.ssh/w03-ec2 with mode 600.")
    if not KEY_PUBLIC.is_file() or KEY_PUBLIC.is_symlink():
        raise lab.LabError("Expected the matching public key at ~/.ssh/w03-ec2.pub.")

    vpcs = aws(["ec2", "describe-vpcs", "--vpc-ids", VPC_ID, "--query", "Vpcs[].{Id:VpcId,Default:IsDefault,State:State}"], context["region"])
    if len(vpcs) != 1 or vpcs[0].get("Default") is not True or vpcs[0].get("State") != "available":
        raise lab.LabError("The approved default VPC is unavailable or no longer default.")
    subnets = aws(["ec2", "describe-subnets", "--subnet-ids", SUBNET_ID,
                   "--query", "Subnets[].{Id:SubnetId,Vpc:VpcId,AZ:AvailabilityZone,Default:DefaultForAz,Public:MapPublicIpOnLaunch,State:State}"], context["region"])
    if len(subnets) != 1 or subnets[0] != {"Id": SUBNET_ID, "Vpc": VPC_ID, "AZ": "us-east-1a", "Default": True, "Public": True, "State": "available"}:
        raise lab.LabError("The approved default public subnet no longer matches the plan.")
    route_tables = aws(["ec2", "describe-route-tables", "--filters", f"Name=vpc-id,Values={VPC_ID}",
                        "--query", "RouteTables[].{Main:Associations[?Main==`true`].Main|[0],Routes:Routes[?DestinationCidrBlock==`0.0.0.0/0`].{Gateway:GatewayId,State:State}}"], context["region"])
    if not any(table.get("Main") is True and any(route.get("Gateway", "").startswith("igw-") and route.get("State") == "active" for route in table.get("Routes", [])) for table in route_tables):
        raise lab.LabError("The approved default route to an internet gateway is unavailable.")
    images = aws(["ec2", "describe-images", "--image-ids", AMI_ID,
                  "--query", "Images[].{Id:ImageId,Name:Name,Arch:Architecture,State:State,Root:RootDeviceName}"], context["region"])
    if len(images) != 1 or images[0].get("Arch") != "x86_64" or images[0].get("State") != "available":
        raise lab.LabError("The approved AL2023 x86_64 AMI is unavailable.")
    keys = aws(["ec2", "describe-key-pairs", "--key-names", KEY_NAME,
                "--query", "KeyPairs[].{Name:KeyName,Fingerprint:KeyFingerprint}"], context["region"])
    fingerprint = subprocess.check_output(["ssh-keygen", "-E", "sha256", "-lf", str(KEY_PUBLIC)], text=True).split()[1].removeprefix("SHA256:") + "="
    if len(keys) != 1 or keys[0].get("Name") != KEY_NAME or keys[0].get("Fingerprint") != fingerprint:
        raise lab.LabError("Local SSH public-key fingerprint does not match the existing AWS key pair.")
    return context, subnets[0], images[0], existing, bool(existing and existing.get("source_cidr") != source_cidr)


def save_manifest(resources):
    MANIFEST.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if MANIFEST.parent.is_symlink():
        raise lab.LabError("Refusing a symlinked .local directory.")
    os.chmod(MANIFEST.parent, 0o700)
    lab.atomic_write(MANIFEST, json.dumps(resources, indent=2) + "\n")


def create(args):
    commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=ROOT, text=True).strip()
    context, subnet, image, existing, needs_source_update = verify_plan(args.group, args.owner, args.source_cidr, commit)
    sys.path.insert(0, str(ROOT / "deploy"))
    import make_user_data
    packaged_commit, user_data = make_user_data.build(commit)
    if packaged_commit != commit or len(user_data) >= 16 * 1024:
        raise lab.LabError("Committed user data failed the course size/version check.")

    group_name = f"w04-inspection-{args.group}-{args.owner}"
    tags = [
        {"Key": "course", "Value": lab.COURSE},
        {"Key": "week", "Value": "w04"},
        {"Key": "group", "Value": args.group},
        {"Key": "owner", "Value": args.owner},
    ]
    plan_state = "will update the recorded security group source and create one instance" if needs_source_update else ("will reuse the recorded security group; no instance exists" if existing else "no resources have been created yet")
    print(f"Confirmed plan ({plan_state}):")
    plan = {
        "account_suffix": context["account"][-4:], "region": context["region"],
        "vpc_id": VPC_ID, "subnet_id": subnet["Id"], "availability_zone": subnet["AZ"],
        "ami_id": image["Id"], "ami_name": image["Name"], "instance_type": "t3.micro",
        "security_group_name": group_name, "inbound": [
            {"protocol": "tcp", "port": 22, "source": args.source_cidr},
            {"protocol": "tcp", "port": 80, "source": args.source_cidr},
        ],
        "egress": "IPv4 internet, needed for AL2023 package installation",
        "root_volume": {"size_gib": 8, "type": "gp3", "encrypted": True, "delete_on_termination": True},
        "metadata_tokens": "required", "existing_key_pair": KEY_NAME,
        "tags": {tag["Key"]: tag["Value"] for tag in tags},
        "commit": commit, "estimated_cost": "not available (AWS Price List denied); user accepted under-$10 is not guaranteed",
        "recovery": "terminate the recorded instance ID; verify its volume/ENI are gone; delete only the recorded new SG ID",
    }
    if needs_source_update:
        plan["security_group_source_change"] = {"from": existing["source_cidr"], "to": args.source_cidr}
    print(json.dumps(plan, indent=2))
    lab.approve("", "CREATE")

    if existing:
        resources = existing
        security_group_id = resources["security_group_id"]
        if needs_source_update:
            new_permissions = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                                "IpRanges": [{"CidrIp": args.source_cidr, "Description": "Codespace /32"}]}
                               for port in (22, 80)]
            old_permissions = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                                "IpRanges": [{"CidrIp": resources["source_cidr"], "Description": "Codespace /32"}]}
                               for port in (22, 80)]
            aws(["ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
                 "--ip-permissions", json.dumps(new_permissions)], context["region"])
            aws(["ec2", "revoke-security-group-ingress", "--group-id", security_group_id,
                 "--ip-permissions", json.dumps(old_permissions)], context["region"])
            resources["source_cidr"] = args.source_cidr
            save_manifest(resources)
    else:
        tag_specifications = json.dumps([{"ResourceType": "security-group", "Tags": tags}])
        created_group = aws(["ec2", "create-security-group", "--group-name", group_name,
                             "--description", "W4 inspection host for aabbcc W3_Lab",
                             "--vpc-id", VPC_ID, "--tag-specifications", tag_specifications], context["region"])
        security_group_id = created_group["GroupId"]
        resources = {
            "region": context["region"], "course": lab.COURSE, "week": "w04",
            "group": args.group, "owner": args.owner, "source_cidr": args.source_cidr,
            "commit": commit, "instance_id": None, "security_group_id": security_group_id,
            "root_volume_id": None, "network_interface_id": None,
            "key_name": KEY_NAME, "key_pair_created": False,
        }
        save_manifest(resources)
        permissions = [{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                        "IpRanges": [{"CidrIp": args.source_cidr, "Description": "Codespace /32"}]}
                       for port in (22, 80)]
        aws(["ec2", "authorize-security-group-ingress", "--group-id", security_group_id,
             "--ip-permissions", json.dumps(permissions)], context["region"])

    block_devices = [{"DeviceName": image["Root"], "Ebs": {
        "VolumeSize": 8, "VolumeType": "gp3", "Encrypted": True, "DeleteOnTermination": True,
    }}]
    instance_tags = tags + [{"Key": "Name", "Value": group_name}]
    run_tags = json.dumps([
        {"ResourceType": resource_type, "Tags": instance_tags}
        for resource_type in ("instance", "volume", "network-interface")
    ])
    launched = aws([
        "ec2", "run-instances", "--image-id", image["Id"], "--instance-type", "t3.micro",
        "--count", "1", "--key-name", KEY_NAME,
        "--subnet-id", SUBNET_ID, "--security-group-ids", security_group_id,
        "--metadata-options", json.dumps({"HttpTokens": "required", "HttpEndpoint": "enabled", "HttpPutResponseHopLimit": 1}),
        "--block-device-mappings", json.dumps(block_devices), "--tag-specifications", run_tags,
        "--user-data", user_data.decode("utf-8"),
    ], context["region"])
    resources["instance_id"] = launched["Instances"][0]["InstanceId"]
    save_manifest(resources)

    details = aws(["ec2", "describe-instances", "--instance-ids", resources["instance_id"],
                   "--query", "Reservations[].Instances[].{State:State.Name,PublicIp:PublicIpAddress,Volumes:BlockDeviceMappings[].Ebs.VolumeId,Enis:NetworkInterfaces[].NetworkInterfaceId}"], context["region"])[0]
    resources["root_volume_id"] = (details.get("Volumes") or [None])[0]
    resources["network_interface_id"] = (details.get("Enis") or [None])[0]
    save_manifest(resources)
    print(json.dumps({"instance_id": resources["instance_id"], "state": details["State"],
                      "public_ip": details.get("PublicIp"), "resource_manifest": ".local/resources.json"}, indent=2))
    print("The instance may still be bootstrapping. Record the first /health result, then verify the deployed commit before W4 deployment.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    up = subparsers.add_parser("up", help="create the confirmed W4 host and its dedicated security group")
    up.add_argument("--group", required=True)
    up.add_argument("--owner", required=True)
    up.add_argument("--source-cidr", required=True)
    up.set_defaults(func=create)
    args = parser.parse_args()
    try:
        args.func(args)
    except (lab.LabError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print("STOP: " + (str(exc) if isinstance(exc, lab.LabError) else type(exc).__name__), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())