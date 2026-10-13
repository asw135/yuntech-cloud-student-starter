#!/usr/bin/env python3
"""Reconcile one W6 MQTT run with consumer logs, PostgreSQL, and the filter API."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from iot_support import CODE_RE, get_code

sys.path.insert(0, str(ROOT / "scripts"))
import lab

RUN_RE = re.compile(r"r[1-9][0-9]*\Z")
PREFIX_RE = re.compile(r"[A-Za-z0-9-]{1,40}\Z")
COUNT_RE = re.compile(r"^\s*(\d+)\s+result=(created|duplicate|rejected|error)\s*$")


def _load_run_record(expected_prefix):
    path = ROOT / ".local" / "w06-last-run.json"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("missing regular .local/w06-last-run.json; run gateway_sim.py first")
    with path.open(encoding="utf-8") as stream:
        record = json.load(stream)
    if record.get("prefix") != expected_prefix:
        raise RuntimeError("run record prefix does not match this reconciliation request")
    if type(record.get("puback_ok")) is not int or not 0 <= record["puback_ok"] <= 32:
        raise RuntimeError("run record has no valid PUBACK count")
    return record


def _find_host(context, resources):
    instances = lab.run_aws(
        [
            "ec2", "describe-instances", "--instance-ids", resources["instance_id"],
            "--query", "Reservations[].Instances[].{State:State.Name,Ip:PublicIpAddress,Tags:Tags}",
        ],
        context["region"],
    )
    if len(instances) != 1:
        raise RuntimeError("W6 host lookup did not return exactly one instance")
    instance = instances[0]
    tags = {item["Key"]: item["Value"] for item in instance.get("Tags", [])}
    if instance.get("State") != "running" or not instance.get("Ip"):
        raise RuntimeError("W6 host is not running with a public IPv4 address")
    if tags.get("group") != resources.get("group") or tags.get("owner") != resources.get("owner"):
        raise RuntimeError("W6 host ownership tags do not match the local resource manifest")
    return instance["Ip"]


def _ssh_options(resources):
    key_names = {
        "w03-ec2-key": Path.home() / ".ssh" / "w03-ec2",
        "w04-ec2-key-aabbcc": Path.home() / ".ssh" / "w04-ec2",
    }
    key = key_names.get(resources.get("key_name"))
    if (key is None or key.is_symlink() or not key.is_file()
            or key.stat().st_mode & 0o777 != 0o600):
        raise RuntimeError("the expected SSH private key is missing or not mode 600")
    return ["ssh", "-i", str(key), "-o", "IdentitiesOnly=yes", "-o",
            "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]


def _remote_reconcile(ssh_options, public_ip, prefix):
    remote_script = r"""set -euo pipefail
prefix=$1
sudo journalctl -u inspection-consumer -o cat --no-pager \
  | grep -F -- "event_id=${prefix}-" \
  | grep -o 'result=[a-z]*' \
  | sort | uniq -c || true
sudo bash -c 'set -a; . /etc/inspection/app.env; . /etc/inspection/db.env; set +a
  PGPASSWORD="$DB_PASSWORD" psql -At "host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem" \
    -v prefix="$1"' _ "${prefix}-" <<'SQL'
SELECT count(*) FROM events WHERE left(event_id, length(:'prefix')) = :'prefix';
SQL
"""
    result = subprocess.run(
        [*ssh_options, f"ec2-user@{public_ip}", "sudo bash -s --", prefix],
        input=remote_script,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("SSH reconciliation failed; verify host reachability and service state")
    counts = {"created": 0, "duplicate": 0, "rejected": 0, "error": 0}
    database_count = None
    for line in result.stdout.splitlines():
        match = COUNT_RE.fullmatch(line)
        if match:
            counts[match.group(2)] += int(match.group(1))
        elif re.fullmatch(r"\s*\d+\s*", line):
            database_count = int(line.strip())
    if database_count is None:
        raise RuntimeError("the remote psql query returned no event count")
    return counts, database_count


def _filtered_events(public_ip, code, prefix):
    device_id = f"{code}-d01"
    url = f"http://{public_ip}/events?device_id={quote(device_id, safe='')}"
    curl_script = r"""set -euo pipefail
set -a
. .local/app.env
set +a
    printf 'Authorization: Bearer %s\n' "$OPERATOR_TOKEN" \
      | curl --header @- --fail --silent --show-error --max-time 10 "$1"
"""
    response = subprocess.run(
        ["bash", "-c", curl_script, "bash", url],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    if response.returncode:
        raise RuntimeError("device-filter API request failed")
    try:
        data = json.loads(response.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("device-filter API returned invalid JSON") from None
    events = [
        item for item in data.get("events", [])
        if (isinstance(item, dict) and isinstance(item.get("event_id"), str)
            and item["event_id"].startswith(prefix + "-"))
    ]
    return [item.get("event_id", "") for item in events]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    manifest, code = get_code()
    if not CODE_RE.fullmatch(args.code) or args.code != code:
        parser.error("--code must match iot_code in .local/resources.json")
    if not RUN_RE.fullmatch(args.run):
        parser.error("--run must be r1, r2, and so on")
    prefix = f"{code}-{args.run}"
    if not PREFIX_RE.fullmatch(prefix):
        parser.error("combined prefix must match ^[A-Za-z0-9-]{1,40}$")
    record = _load_run_record(prefix)
    subprocess.run(["bash", "scripts/verify-aws.sh"], cwd=ROOT, check=True)
    context = lab.verify()
    public_ip = _find_host(context, manifest)
    health_request = Request(f"http://{public_ip}/health")
    try:
        with urlopen(health_request, timeout=10) as response:
            health = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise RuntimeError("host /health request failed") from None
    if health.get("db_configured") is not True:
        raise RuntimeError("host reports db_configured=false")

    print(f"version={health.get('version')}")
    print(f"db_configured={str(health['db_configured']).lower()}")
    print(f"prefix={prefix}")
    print(f"puback_ok={record['puback_ok']}/32")

    ssh_options = _ssh_options(manifest)
    counts = {"created": 0, "duplicate": 0, "rejected": 0, "error": 0}
    database_count = 0
    deadline = time.monotonic() + 60
    while True:
        counts, database_count = _remote_reconcile(ssh_options, public_ip, prefix)
        if sum(counts.values()) >= 32 or time.monotonic() >= deadline:
            break
        time.sleep(5)
    print(
        "consumer="
        f"created:{counts['created']} duplicate:{counts['duplicate']} "
        f"rejected:{counts['rejected']} error:{counts['error']}"
    )
    print(f"database_count={database_count}")
    event_ids = _filtered_events(public_ip, code, prefix)
    print(f"device_id={code}-d01 prefix_count={len(event_ids)}")
    for event_id in event_ids:
        print(f"event_id={event_id}")


if __name__ == "__main__":
    try:
        main()
    except (lab.LabError, OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        raise SystemExit(1)
