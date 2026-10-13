#!/usr/bin/env python3
"""Check the W6 gateway and consumer MQTT identities."""
import argparse
import json
import threading
import time

from iot_support import configure_stdout, mqtt_reason_code, new_mqtt_client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as", dest="identity", choices=("gw", "consumer"), required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--pub", help="topic to publish the fixed W6 check message to")
    action.add_argument("--sub", help="topic filter to subscribe to")
    parser.add_argument("--wait", type=float, default=60, help="subscription wait time in seconds")
    args = parser.parse_args()
    if args.wait <= 0 or args.wait > 300:
        parser.error("--wait must be greater than 0 and no more than 300 seconds")
    mqtt, client, config = new_mqtt_client(args.identity)
    connected = threading.Event()
    connection_result = {"code": None}
    subscription = threading.Event()
    subscription_result = {"code": None}
    published = threading.Event()
    published_result = {"mid": None, "code": None}
    pending_lock = threading.Lock()
    acknowledgements = {}

    def on_connect(_current_client, _userdata, _flags, reason_code, _properties):
        code = mqtt_reason_code(reason_code)
        connection_result["code"] = code
        print(f"connack={code}")
        connected.set()

    def on_subscribe(_current_client, _userdata, _mid, reason_codes, _properties):
        code = mqtt_reason_code(reason_codes[0]) if reason_codes else 128
        subscription_result["code"] = code
        print(f"suback={code}")
        subscription.set()

    def on_publish(_current_client, _userdata, mid, reason_code, _properties):
        with pending_lock:
            acknowledgements[mid] = mqtt_reason_code(reason_code)
            if mid == published_result["mid"]:
                published_result["code"] = acknowledgements[mid]
                published.set()

    def on_message(_current_client, _userdata, message):
        print(f"recv topic={message.topic} payload={message.payload.decode('utf-8', errors='replace')}")

    client.on_connect = on_connect
    client.on_subscribe = on_subscribe
    client.on_publish = on_publish
    client.on_message = on_message
    client.connect(config["endpoint"], 8883, keepalive=60)
    client.loop_start()
    try:
        if not connected.wait(15):
            raise TimeoutError("timed out waiting for MQTT CONNACK")
        if connection_result["code"] >= 128:
            raise SystemExit(1)
        if args.pub:
            payload = json.dumps(
                {"check": "t2", "code": config["code"]},
                separators=(",", ":"),
            )
            info = client.publish(args.pub, payload, qos=1)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError("MQTT publish request failed")
            with pending_lock:
                published_result["mid"] = info.mid
                if info.mid in acknowledgements:
                    published_result["code"] = acknowledgements.pop(info.mid)
                    published.set()
            if not published.wait(15):
                raise TimeoutError("timed out waiting for MQTT PUBACK")
            print(f"puback={published_result['code']}")
            with pending_lock:
                acknowledgements.pop(info.mid, None)
        else:
            result, mid = client.subscribe(args.sub, qos=1)
            if result != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError("MQTT subscribe request failed")
            if not subscription.wait(15):
                raise TimeoutError("timed out waiting for MQTT SUBACK")
            if subscription_result["code"] < 128:
                time.sleep(args.wait)
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    configure_stdout()
    main()
