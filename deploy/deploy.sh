#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

manifest=.local/resources.json
secret_file=.local/app.env
db_secret_file=.local/db.env
iot_dir=.local/iot

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
[[ -f "$db_secret_file" && ! -L "$db_secret_file" ]] || { echo "STOP: missing regular .local/db.env" >&2; exit 1; }
[[ "$(stat -c '%a' "$db_secret_file")" == 600 ]] || { echo "STOP: .local/db.env must have mode 600" >&2; exit 1; }
[[ -f "$key_file" && ! -L "$key_file" && "$(stat -c '%a' "$key_file")" == 600 ]] || {
    echo "STOP: SSH private key for $key_name is missing or does not have mode 600" >&2
    exit 1
}

code=$(python3 - "$manifest" <<'PY'
import json
import re
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    resources = json.load(stream)
code = resources.get("iot_code", "")
if code and (not re.fullmatch(r"[A-Za-z0-9-]{1,40}", code) or len(code + "-d10") > 32):
    raise SystemExit("STOP: invalid iot_code in resource manifest")
print(code)
PY
)
if [[ -n "$code" ]]; then
    [[ -d "$iot_dir" && ! -L "$iot_dir" ]] || { echo "STOP: .local/iot must be a regular directory" >&2; exit 1; }
    for name in endpoint AmazonRootCA1.pem consumer.cert.pem consumer.private.key; do
        file="$iot_dir/$name"
        [[ -f "$file" && ! -L "$file" && "$(stat -c '%a' "$file")" == 600 ]] || {
            echo "STOP: missing regular mode-600 W6 IoT file: $name" >&2
            exit 1
        }
    done
fi

bash scripts/verify-aws.sh
commit=$(git rev-parse --verify HEAD)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo "STOP: HEAD is not a commit" >&2; exit 1; }
git diff --quiet HEAD -- app/service.py deploy/nginx.conf deploy/make_user_data.py || {
    echo "STOP: commit app/service.py, deploy/nginx.conf and deploy/make_user_data.py before deployment" >&2
    exit 1
}
if [[ -n "$code" ]]; then
    git cat-file -e "$commit:app/consumer.py" 2>/dev/null || {
        echo "STOP: commit app/consumer.py before W6 deployment" >&2
        exit 1
    }
    git diff --quiet HEAD -- app/consumer.py || {
        echo "STOP: commit app/consumer.py before W6 deployment" >&2
        exit 1
    }
fi

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
trap 'rm -f -- "${bundle:-}" "${iot_env:-}"' EXIT
bash deploy/make-user-data.sh "$commit" "$bundle"
ssh_options=(-i "$key_file" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
ssh "${ssh_options[@]}" "ec2-user@$public_ip" 'sudo bash -s' < "$bundle"
ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
    'sudo install -d -o root -g root -m 755 /etc/inspection && sudo chmod 755 /etc/inspection && sudo install -o root -g root -m 600 /dev/stdin /etc/inspection/app.env' \
    < "$secret_file"
ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
    'sudo install -d -o root -g root -m 755 /etc/inspection && sudo chmod 755 /etc/inspection && sudo install -o root -g root -m 600 /dev/stdin /etc/inspection/db.env' \
    < "$db_secret_file"
if [[ -n "$code" ]]; then
    endpoint=$(<"$iot_dir/endpoint")
    [[ "$endpoint" =~ ^[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com$ ]] || {
        echo "STOP: invalid IoT endpoint file" >&2
        exit 1
    }
    ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
        'sudo chmod 755 /etc/inspection && sudo install -d -o inspection -g inspection -m 700 /etc/inspection/iot'
    for name in consumer.cert.pem consumer.private.key AmazonRootCA1.pem; do
        ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
            "sudo bash -c 'set -euo pipefail; umask 077; cat > /etc/inspection/iot/$name; chown inspection:inspection /etc/inspection/iot/$name; chmod 600 /etc/inspection/iot/$name'" \
            < "$iot_dir/$name"
    done
    iot_env=$(mktemp .local/w06-env.XXXXXX)
    chmod 600 "$iot_env"
    {
        printf 'IOT_ENDPOINT=%s\n' "$endpoint"
        printf 'IOT_TOPIC=cxe/%s/gw/events\n' "$code"
        printf 'IOT_CLIENT_ID=consumer-%s\n' "$code"
        printf 'IOT_DEVICE_IDS='
        for number in {1..10}; do
            [[ "$number" -eq 1 ]] || printf ','
            printf '%s-d%02d' "$code" "$number"
        done
        printf '\nIOT_CA=/etc/inspection/iot/AmazonRootCA1.pem\n'
        printf 'IOT_CERT=/etc/inspection/iot/consumer.cert.pem\n'
        printf 'IOT_KEY=/etc/inspection/iot/consumer.private.key\n'
    } > "$iot_env"
    ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
        "sudo bash -c 'set -euo pipefail; chmod 755 /etc/inspection; sed -i \"/^IOT_/d\" /etc/inspection/app.env; umask 077; cat >> /etc/inspection/app.env; chmod 600 /etc/inspection/app.env'" \
        < "$iot_env"
    ssh "${ssh_options[@]}" "ec2-user@$public_ip" \
        'sudo systemctl restart inspection && sudo systemctl restart inspection-consumer && systemctl is-active inspection inspection-consumer'
else
    ssh "${ssh_options[@]}" "ec2-user@$public_ip" 'sudo systemctl restart inspection'
fi

health=$(curl --fail --silent --show-error --max-time 10 "http://$public_ip/health")
printf '%s' "$health" | python3 -c 'import json,sys; expected=sys.argv[1]; data=json.load(sys.stdin); assert data.get("version")==expected, "deployed version mismatch"; assert data.get("auth_configured") is True, "service auth is not configured"; assert data.get("db_configured") is True, "service DB config is not configured"; print(json.dumps(data, ensure_ascii=False, sort_keys=True))' "$commit"