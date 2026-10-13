#!/usr/bin/env python3
"""Publish the W6 32-message simulator batch to AWS IoT Core."""
import argparse
from datetime import datetime, timezone
import json
import re
import threading

from iot_support import (
    ROOT,
    configure_stdout,
    get_code,
    mqtt_reason_code,
    new_mqtt_client,
    validate_code,
)

PREFIX_RE = re.compile(r"[A-Za-z0-9-]{1,40}\Z")
RUN_RE = re.compile(r"r[1-9][0-9]*\Z")


def build_events(code, run):
    validate_code(code)
    if not RUN_RE.fullmatch(run):
        raise ValueError("run must be r1, r2, and so on")
    prefix = f"{code}-{run}"
    if not PREFIX_RE.fullmatch(prefix):
        raise ValueError("combined event prefix must match ^[A-Za-z0-9-]{1,40}$")

    observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    events = []
    for device_number in range(1, 11):
        device_id = f"{code}-d{device_number:02d}"
        for sequence in range(1, 4):
            events.append({
                "event_id": f"{prefix}-d{device_number:02d}-{sequence:02d}",
                "device_id": device_id,
                "observed_at": observed_at,
                "type": "status",
            })
    events.append(dict(events[0]))
    events.append({
        "event_id": f"{prefix}-d99-01",
        "device_id": f"{code}-d99",
        "observed_at": observed_at,
        "type": "status",
    })
    return prefix, events


def ensure_new_prefix(prefix, code, run):
    record_path = ROOT / ".local" / "w06-last-run.json"
    if record_path.is_symlink():
        raise RuntimeError("refusing symlink for .local/w06-last-run.json")
    if not record_path.exists():
        return
    with record_path.open(encoding="utf-8") as stream:
        previous = json.load(stream)
    old_prefix = previous.get("prefix", "")
    match = re.fullmatch(re.escape(code) + r"-r([1-9][0-9]*)", old_prefix)
    current_run = int(run[1:])
    if match and current_run != int(match.group(1)) + 1:
        raise ValueError("run number must increment from the last completed W6 run")
    if old_prefix and not match:
        raise RuntimeError("last-run record does not match this W6 code; inspect it before publishing")


def write_run_record(prefix, puback_ok):
    import sys
    sys.path.insert(0, str(ROOT))
    from scripts import lab

    data = {
        "prefix": prefix,
        "puback_ok": puback_ok,
        "total": 32,
    }
    lab.atomic_write(ROOT / ".local" / "w06-last-run.json", json.dumps(data) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True)
    parser.add_argument("--run", required=True)
    args = parser.parse_args()
    _, code = get_code()
    if args.code != code:
        parser.error("--code must match iot_code in .local/resources.json")
    prefix, events = build_events(code, args.run)
    ensure_new_prefix(prefix, code, args.run)
    mqtt, client, config = new_mqtt_client("gw")
    connected = threading.Event()
    result = {"connack": None}
    pending_lock = threading.Lock()
    acknowledgements = {}
    expected_mid = {"value": None}
    acknowledgement_ready = threading.Event()

    def on_connect(_current_client, _userdata, _flags, reason_code, _properties):
        result["connack"] = mqtt_reason_code(reason_code)
        connected.set()

    def on_publish(_current_client, _userdata, mid, reason_code, _properties):
        with pending_lock:
            acknowledgements[mid] = mqtt_reason_code(reason_code)
            if expected_mid["value"] == mid:
                acknowledgement_ready.set()

    client.on_connect = on_connect
    client.on_publish = on_publish
    client.connect(config["endpoint"], 8883, keepalive=60)
    client.loop_start()
    puback_ok = 0
    try:
        if not connected.wait(15):
            raise TimeoutError("timed out waiting for MQTT CONNACK")
        if result["connack"] != 0:
            raise RuntimeError(f"MQTT connection rejected with reason code {result['connack']}")
        for event in events:
            payload = json.dumps(event, separators=(",", ":"))
            info = client.publish(config["topic"], payload, qos=1)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError("MQTT publish request failed")
            with pending_lock:
                expected_mid["value"] = info.mid
                if info.mid in acknowledgements:
                    acknowledgement_ready.set()
            if not acknowledgement_ready.wait(15):
                raise TimeoutError("timed out waiting for MQTT PUBACK")
            with pending_lock:
                acknowledged_mid = expected_mid["value"]
                code_value = acknowledgements.pop(acknowledged_mid, None)
                expected_mid["value"] = None
                acknowledgement_ready.clear()
            if code_value is None:
                raise RuntimeError("received a PUBACK for an unexpected message identifier")
            if code_value < 128:
                puback_ok += 1
        write_run_record(prefix, puback_ok)
        print(f"puback_ok={puback_ok}/32")
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    configure_stdout()
    main()
