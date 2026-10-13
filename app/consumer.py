#!/usr/bin/env python3
"""Forward allowlisted MQTT events to the local inspection API."""
from http.client import HTTPException
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


EVENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
DEVICE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")


def _safe_event_id(value):
    return value if isinstance(value, str) and EVENT_ID_RE.fullmatch(value) else "invalid"


def _valid_event_id(value):
    return isinstance(value, str) and EVENT_ID_RE.fullmatch(value) is not None


def _post_event(event, reporter_token):
    request = Request(
        "http://127.0.0.1:8080/events",
        data=json.dumps(event, separators=(",", ":")).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + reporter_token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status
    except HTTPError as error:
        return error.code
    except (HTTPException, URLError, TimeoutError, OSError):
        return None


def process_payload(payload, allowed_device_ids, reporter_token, post_event=None):
    """Return one sanitized event ID and result without logging message contents."""
    try:
        event = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError):
        return "invalid", "rejected"
    if not isinstance(event, dict):
        return "invalid", "rejected"

    raw_event_id = event.get("event_id")
    event_id = _safe_event_id(raw_event_id)
    if not _valid_event_id(raw_event_id):
        return event_id, "rejected"
    device_id = event.get("device_id")
    if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
        return event_id, "rejected"
    if device_id not in allowed_device_ids:
        return event_id, "rejected"

    response_status = (post_event or _post_event)(event, reporter_token)
    if response_status == 201:
        return event_id, "created"
    if response_status == 200:
        return event_id, "duplicate"
    if response_status is not None and 400 <= response_status < 500:
        return event_id, "rejected"
    return event_id, "error"


def _required_environment():
    names = (
        "IOT_ENDPOINT",
        "IOT_TOPIC",
        "IOT_CLIENT_ID",
        "IOT_DEVICE_IDS",
        "IOT_CA",
        "IOT_CERT",
        "IOT_KEY",
        "REPORTER_TOKEN",
    )
    values = {name: os.environ.get(name, "") for name in names}
    if any(not value for value in values.values()):
        raise RuntimeError("consumer configuration is incomplete")
    allowed = {item for item in values["IOT_DEVICE_IDS"].split(",") if item}
    if not allowed:
        raise RuntimeError("consumer device allowlist is empty")
    return values, allowed


def main():
    try:
        import paho.mqtt.client as mqtt
    except ImportError as error:
        raise RuntimeError("paho-mqtt 2.1.0 is required") from error

    config, allowed_device_ids = _required_environment()
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=config["IOT_CLIENT_ID"],
        protocol=mqtt.MQTTv5,
    )
    client.tls_set(
        ca_certs=config["IOT_CA"],
        certfile=config["IOT_CERT"],
        keyfile=config["IOT_KEY"],
    )

    def on_connect(current_client, _userdata, _flags, reason_code, _properties):
        if int(reason_code) == 0:
            current_client.subscribe(config["IOT_TOPIC"], qos=1)

    def on_subscribe(_current_client, _userdata, _mid, reason_code_list, _properties):
        reason = reason_code_list[0] if reason_code_list else 128
        print(f"subscribed rc={int(reason)}", flush=True)

    def on_message(_current_client, _userdata, message):
        event_id, result = process_payload(
            message.payload,
            allowed_device_ids,
            config["REPORTER_TOKEN"],
        )
        print(f"event_id={event_id} result={result}", flush=True)

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_message = on_message
    client.connect(config["IOT_ENDPOINT"], 8883, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
