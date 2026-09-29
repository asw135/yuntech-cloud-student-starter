#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

manifest=.local/resources.json
secret_file=.local/app.env

[[ -f "$manifest" && ! -L "$manifest" ]] || { echo "STOP: missing regular .local/resources.json" >&2; exit 1; }
key_name=$(python3 - "$manifest" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("key_name", ""))
PY
)
case "$key_name" in
    w03-ec2-key) key_file="$HOME/.ssh/w03-ec2" ;;
    w04-ec2-key-aabbcc) key_file="$HOME/.ssh/w04-ec2" ;;
    *) echo "STOP: unrecognized key_name in resource manifest" >&2; exit 1 ;;
esac
[[ -f "$secret_file" && ! -L "$secret_file" ]] || { echo "STOP: missing regular .local/app.env" >&2; exit 1; }
[[ "$(stat -c '%a' "$secret_file")" == 600 ]] || { echo "STOP: .local/app.env must have mode 600" >&2; exit 1; }
[[ -f "$key_file" && ! -L "$key_file" && "$(stat -c '%a' "$key_file")" == 600 ]] || {
    echo "STOP: SSH private key for $key_name is missing or does not have mode 600" >&2
    exit 1
}

bash scripts/verify-aws.sh
commit=$(git rev-parse --verify HEAD)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "STOP: HEAD is not a commit" >&2; exit 1; }
git diff --quiet HEAD -- app/service.py deploy/nginx.conf || {
    echo "STOP: commit app/service.py and deploy/nginx.conf before deployment" >&2
    exit 1
}

target=$(python3 - "$manifest" <<'PY'
import json
import contextlib
import re
import sys

sys.path.insert(0, "scripts")
import lab

with open(sys.argv[1], encoding="utf-8") as stream:
    resources = json.load(stream)
instance_id = resources.get("instance_id", "")
if not re.fullmatch(r"i-[0-9a-f]+", instance_id):
    raise SystemExit("STOP: resource manifest has no valid instance_id")
if resources.get("group") != "aabbcc" or resources.get("owner") != "W3_Lab":
    raise SystemExit("STOP: resource manifest group/owner does not match this deployment")
with contextlib.redirect_stdout(sys.stderr):
    context = lab.verify()
instances = lab.run_aws([
    "ec2", "describe-instances", "--instance-ids", instance_id,
    "--query", "Reservations[].Instances[].{Id:InstanceId,State:State.Name,Ip:PublicIpAddress,Tags:Tags}",
], context["region"])
if len(instances) != 1:
    raise SystemExit("STOP: instance lookup did not return exactly one host")
instance = instances[0]
tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
if instance.get("State") != "running" or not instance.get("Ip"):
    raise SystemExit("STOP: target instance is not running with a public IPv4")
if tags.get("course") != lab.COURSE or tags.get("group") != "aabbcc" or tags.get("owner") != "W3_Lab":
    raise SystemExit("STOP: target instance ownership tags do not match the manifest")
print(instance_id + " " + instance["Ip"])
PY
)
read -r instance_id public_ip <<< "$target"

printf 'Target host: %s (%s)\nCommit: %s\n' "$instance_id" "$public_ip" "$commit"
printf 'Type exactly DEPLOY %s to continue: ' "$instance_id"
IFS= read -r approval
[[ "$approval" == "DEPLOY $instance_id" ]] || { echo "Cancelled; no remote changes made."; exit 1; }

bundle=$(mktemp .local/w04-user-data.XXXXXX)
rm -f -- "$bundle"
trap 'rm -f -- "$bundle"' EXIT
bash deploy/make-user-data.sh "$commit" "$bundle"
ssh_options=(-i "$key_file" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
ssh "${ssh_options[@]}" "ec2-user@$public_ip" 'sudo bash -s' < "$bundle"
ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
    'sudo install -d -o root -g root -m 700 /etc/inspection && sudo install -o root -g root -m 600 /dev/stdin /etc/inspection/app.env' \
    < "$secret_file"
ssh "${ssh_options[@]}" "ec2-user@$public_ip" 'sudo systemctl restart inspection'

health=$(curl --fail --silent --show-error --max-time 10 "http://$public_ip/health")
printf '%s' "$health" | python3 -c 'import json,sys; expected=sys.argv[1]; data=json.load(sys.stdin); assert data.get("version")==expected, "deployed version mismatch"; assert data.get("auth_configured") is True, "service auth is not configured"; print(json.dumps(data, ensure_ascii=False, sort_keys=True))' "$commit"