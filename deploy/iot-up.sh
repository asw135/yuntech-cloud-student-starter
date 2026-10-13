#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -ne 1 || ! "$1" =~ ^[A-Za-z0-9-]{1,40}$ ]]; then
    echo "Usage: deploy/iot-up.sh <code matching [A-Za-z0-9-]{1,40}>" >&2
    exit 2
fi

echo "AWS IoT plan for code: $1"
echo "Create at most two active certificates and two exact-topic policies; record IDs in .local/resources.json."
echo "No EC2, RDS, IAM, or public network rules will be created or changed."
echo "AWS IoT message/connectivity charges may apply; this script does not enforce a spending cap."
bash scripts/verify-aws.sh
exec python3 deploy/iot_up.py "$1"
