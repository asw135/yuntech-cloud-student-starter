#!/usr/bin/env python3
"""Run the public W4 rejection matrix against an explicitly supplied service URL."""
import argparse
from datetime import datetime, timezone
from getpass import getpass
import json
import re
import urllib.error
import urllib.request
import uuid


def request(base_url, path, method="GET", token=None, body=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    payload = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url + path, data=payload, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="Service origin, e.g. http://203.0.113.10")
    parser.add_argument("--group", required=True, help="Course group tag")
    parser.add_argument("--owner", required=True, help="Non-identifying group member tag")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        parser.error("base_url must use http:// or https://")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.group) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", args.owner):
        parser.error("group and owner must contain only letters, digits, '-' or '_'")
    event_id = f"{args.group}-{args.owner}-{uuid.uuid4().hex[:8]}"
    if len(event_id) > 64 or len(args.group) + 4 > 32:
        parser.error("group/owner values are too long for the event contract")

    status, health = request(base_url, "/health")
    if status != 200 or not isinstance(health.get("version"), str):
        raise SystemExit("STOP: /health did not return a deployed version")
    print("version: " + health["version"])
    reporter_token = getpass("Reporter token (hidden): ")
    operator_token = getpass("Operator token (hidden): ")
    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    valid_event = {
        "event_id": event_id,
        "device_id": args.group + "-d01",
        "observed_at": observed_at,
        "type": "status",
        "note": "W4 rejection matrix",
    }
    invalid_time = dict(valid_event, event_id=event_id + "-bad", observed_at="2026-09-29T10:00:00")
    rows = [
        ("1", lambda: request(base_url, "/events", "POST", reporter_token, valid_event)),
        ("2", lambda: request(base_url, "/events", "POST", None, dict(valid_event, event_id=event_id + "-unauth"))),
        ("3", lambda: request(base_url, "/events", "POST", operator_token, dict(valid_event, event_id=event_id + "-operator"))),
        ("4", lambda: request(base_url, "/events", "POST", reporter_token, invalid_time)),
        ("5", lambda: request(base_url, "/events", "POST", reporter_token, valid_event)),
        ("6", lambda: request(base_url, "/events", token=reporter_token)),
        ("7", lambda: request(base_url, "/events", token=operator_token)),
    ]
    for number, run in rows:
        try:
            code, body = run()
        except (urllib.error.URLError, TimeoutError, ValueError) as error:
            print(f"#{number} transport_error={type(error).__name__}")
            continue
        print(f"#{number} HTTP {code} {json.dumps(body, ensure_ascii=False, sort_keys=True)}")


if __name__ == "__main__":
    main()