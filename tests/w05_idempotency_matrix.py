#!/usr/bin/env python3
"""Run the five-row W5 database idempotency matrix against the recorded EC2 host."""
from datetime import datetime, timezone
from getpass import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab

MANIFEST = ROOT / ".local/resources.json"


def read_manifest():
    if MANIFEST.is_symlink() or not MANIFEST.is_file():
        raise lab.LabError("STOP: .local/resources.json must be a regular file.")
    try:
        resources = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise lab.LabError("STOP: resource manifest is unreadable or invalid.") from None
    if (
        resources.get("region") != "us-east-1"
        or resources.get("course") != lab.COURSE
        or resources.get("group") != "aabbcc"
        or resources.get("owner") != "W3_Lab"
        or resources.get("instance_id") != "i-00e72275020e7d588"
        or resources.get("w05_db_instance_identifier")
        != "w05-inspection-aabbcc-w3-lab"
    ):
        raise lab.LabError("STOP: resource manifest does not match this W5 deployment.")
    return resources


def get_host(region, instance_id):
    instances = lab.run_aws(
        [
            "ec2",
            "describe-instances",
            "--instance-ids",
            instance_id,
            "--query",
            "Reservations[].Instances[].{State:State.Name,Ip:PublicIpAddress,Key:KeyName,Tags:Tags}",
        ],
        region,
    )
    if len(instances) != 1 or instances[0]["State"] != "running":
        raise lab.LabError("STOP: recorded EC2 instance is not running.")
    tags = {tag["Key"]: tag["Value"] for tag in instances[0].get("Tags", [])}
    if tags.get("course") != lab.COURSE or tags.get("group") != "aabbcc" or tags.get("owner") != "W3_Lab":
        raise lab.LabError("STOP: EC2 ownership tags do not match the W5 manifest.")
    return instances[0]


def request(base_url, path, method="GET", token=None, body=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())


def display_row(number, status, body, secrets_to_redact):
    rendered = json.dumps(body, ensure_ascii=False, sort_keys=True)
    for secret in secrets_to_redact:
        if secret:
            rendered = rendered.replace(secret, "[REDACTED]")
    print(f"#{number} HTTP {status} {rendered}", flush=True)


def ssh_options(key_file):
    return [
        "ssh",
        "-i",
        str(key_file),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
    ]


def run():
    context = lab.verify()
    resources = read_manifest()
    host = get_host(context["region"], resources["instance_id"])
    public_ip = host["Ip"]
    if not public_ip:
        raise lab.LabError("STOP: EC2 has no public IPv4 address.")
    key_paths = {
        "w03-ec2-key": Path.home() / ".ssh/w03-ec2",
        "w04-ec2-key-aabbcc": Path.home() / ".ssh/w04-ec2",
    }
    key_file = key_paths.get(host["Key"])
    if key_file is None or key_file.is_symlink() or not key_file.is_file() or key_file.stat().st_mode & 0o777 != 0o600:
        raise lab.LabError("STOP: SSH key is missing or does not have mode 600.")

    base_url = "http://" + public_ip
    status, health = request(base_url, "/health")
    if status != 200:
        raise lab.LabError("STOP: /health did not return HTTP 200.")
    print("version: " + str(health.get("version")))
    print("db_configured: " + str(health.get("db_configured")).lower())
    if health.get("db_configured") is not True:
        raise lab.LabError("STOP: service does not report db_configured=true.")

    reporter_token = getpass("Reporter token (hidden): ")
    operator_token = getpass("Operator token (hidden): ")
    if not reporter_token or not operator_token:
        raise lab.LabError("STOP: both tokens are required.")
    secrets_to_redact = (reporter_token, operator_token)

    suffix = uuid.uuid4().hex[:10]
    event_id = f"aabbcc-W3_Lab-{suffix}"
    event = {
        "event_id": event_id,
        "device_id": "aabbcc-d01",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "type": "test",
        "note": "W5 idempotency matrix",
    }

    status, body = request(base_url, "/events", "POST", reporter_token, event)
    display_row(1, status, body, secrets_to_redact)
    if status != 201:
        raise lab.LabError("STOP: matrix row #1 did not return HTTP 201.")

    status, body = request(base_url, "/events", "POST", reporter_token, event)
    display_row(2, status, body, secrets_to_redact)
    if status != 200:
        raise lab.LabError("STOP: matrix row #2 did not return HTTP 200.")

    changed_event = dict(event, note="W5 idempotency matrix changed payload")
    status, body = request(base_url, "/events", "POST", reporter_token, changed_event)
    display_row(3, status, body, secrets_to_redact)
    if status != 409:
        raise lab.LabError("STOP: matrix row #3 did not return HTTP 409.")

    command = ssh_options(key_file) + [
        f"ec2-user@{public_ip}",
        "sudo systemctl restart inspection",
    ]
    try:
        subprocess.run(command, check=True, timeout=60)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise lab.LabError("STOP: remote inspection restart failed.") from None

    status, body = request(base_url, "/events/" + event_id, token=operator_token)
    display_row(4, status, body, secrets_to_redact)
    if status != 200 or body.get("event_id") != event_id:
        raise lab.LabError("STOP: matrix row #4 did not find the event after restart.")

    remote_sql = "SELECT count(*) FROM events WHERE event_id = :'event_id';\n"
    remote_command = (
        "sudo bash -c 'set -a; . /etc/inspection/db.env; set +a; "
        "export PGPASSWORD=\"$DB_PASSWORD\"; "
        "psql \"host=$DB_HOST dbname=$DB_NAME user=$DB_USER "
        "sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem\" "
        f"-X -A -t -v event_id={event_id}'"
    )
    try:
        result = subprocess.run(
            ssh_options(key_file) + [f"ec2-user@{public_ip}", remote_command],
            input=remote_sql,
            text=True,
            capture_output=True,
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise lab.LabError("STOP: remote psql query failed to run.") from None
    if result.returncode != 0:
        raise lab.LabError(
            f"STOP: remote psql query failed (exit {result.returncode}); inspect the host locally without sharing secrets."
        )
    count = result.stdout.strip()
    if not re.fullmatch(r"\d+", count):
        raise lab.LabError("STOP: remote psql returned an unexpected result.")
    display_row(5, 200, {"event_id": event_id, "psql_count": int(count)}, secrets_to_redact)
    if count != "1":
        raise lab.LabError("STOP: matrix row #5 expected exactly one stored row.")


if __name__ == "__main__":
    try:
        run()
    except lab.LabError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
