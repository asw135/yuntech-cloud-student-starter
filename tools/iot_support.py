"""Shared local IoT configuration and MQTT helpers for W6 command-line tools."""
import json
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
IOT_DIR = ROOT / ".local" / "iot"
CODE_RE = re.compile(r"[A-Za-z0-9-]{1,40}\Z")


def validate_code(code):
    if not isinstance(code, str) or not CODE_RE.fullmatch(code):
        raise ValueError("code must match ^[A-Za-z0-9-]{1,40}$")
    if len(code + "-d10") > 32:
        raise ValueError("code is too long for the W4 device_id limit of 32 characters")
    return code


def read_manifest():
    manifest_path = ROOT / ".local" / "resources.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError("missing regular .local/resources.json")
    with manifest_path.open(encoding="utf-8") as stream:
        return json.load(stream)


def get_code():
    manifest = read_manifest()
    code = validate_code(manifest.get("iot_code", ""))
    return manifest, code


def _regular_private_file(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"missing regular IoT file: {path.name}")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise RuntimeError(f"IoT file must have mode 600: {path.name}")
    return path


def load_identity(identity):
    if identity not in ("gw", "consumer"):
        raise ValueError("identity must be gw or consumer")
    manifest, code = get_code()
    identity_label = "gw" if identity == "gw" else "consumer"
    endpoint_path = _regular_private_file(IOT_DIR / "endpoint")
    endpoint = endpoint_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", endpoint):
        raise RuntimeError("invalid AWS IoT data endpoint")
    cert = _regular_private_file(IOT_DIR / f"{identity_label}.cert.pem")
    key = _regular_private_file(IOT_DIR / f"{identity_label}.private.key")
    ca = _regular_private_file(IOT_DIR / "AmazonRootCA1.pem")
    client_id = f"{identity_label}-{code}"
    topic = f"cxe/{code}/gw/events"
    if identity == "consumer":
        client_id = f"consumer-{code}"
    else:
        client_id = f"gw-{code}"
    return {
        "endpoint": endpoint,
        "cert": str(cert),
        "key": str(key),
        "ca": str(ca),
        "client_id": client_id,
        "topic": topic,
        "manifest": manifest,
        "code": code,
    }


def new_mqtt_client(identity):
    try:
        import paho.mqtt.client as mqtt
    except ImportError as error:
        raise RuntimeError("install paho-mqtt==2.1.0 first") from error
    config = load_identity(identity)
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=config["client_id"],
        protocol=mqtt.MQTTv5,
    )
    client.tls_set(
        ca_certs=config["ca"],
        certfile=config["cert"],
        keyfile=config["key"],
    )
    return mqtt, client, config


def mqtt_reason_code(reason):
    return int(getattr(reason, "value", reason))


def configure_stdout():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
