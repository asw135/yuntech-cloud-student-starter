#!/usr/bin/env python3
"""Create W6 AWS IoT identities while keeping private keys off terminal output."""
import json
import re
from pathlib import Path
import sys
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import lab

CODE_RE = re.compile(r"[A-Za-z0-9-]{1,40}\Z")
IOT_DIR = ROOT / ".local" / "iot"
CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"


def _safe_local_file(path):
    if path.is_symlink():
        raise lab.LabError(f"Refusing symlink in IoT credential storage: {path.name}")
    if path.exists():
        if not path.is_file() or (path.stat().st_mode & 0o777) != 0o600:
            raise lab.LabError(f"IoT file must be a private regular file: {path.name}")
        return True
    return False


def _write_private(path, content):
    lab.atomic_write(path, content)
    path.chmod(0o600)


def _policy_documents(account, region, code):
    topic = f"cxe/{code}/gw/events"
    gateway_id = f"gw-{code}"
    consumer_id = f"consumer-{code}"
    base = f"arn:aws:iot:{region}:{account}:"
    gateway = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["iot:Connect"], "Resource": [base + "client/" + gateway_id]},
            {"Effect": "Allow", "Action": ["iot:Publish"], "Resource": [base + "topic/" + topic]},
        ],
    }
    consumer = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["iot:Connect"], "Resource": [base + "client/" + consumer_id]},
            {"Effect": "Allow", "Action": ["iot:Subscribe"], "Resource": [base + "topicfilter/" + topic]},
            {"Effect": "Allow", "Action": ["iot:Receive"], "Resource": [base + "topic/" + topic]},
        ],
    }
    return gateway, consumer


def _read_policy_document(policy_name, region):
    response = lab.run_aws(
        ["iot", "get-policy", "--policy-name", policy_name],
        region,
    )
    version_id = response.get("defaultVersionId")
    if not version_id:
        raise lab.LabError(f"IoT policy has no default version: {policy_name}")
    version = lab.run_aws(
        ["iot", "get-policy-version", "--policy-name", policy_name, "--policy-version-id", version_id],
        region,
    )
    document = version.get("policyDocument")
    if isinstance(document, str):
        from urllib.parse import unquote
        document = json.loads(unquote(document))
    return document


def _ensure_policy(policy_name, expected_document, manifest_key, resources, region):
    if resources.get(manifest_key):
        if resources[manifest_key] != policy_name:
            raise lab.LabError(f"Resource manifest conflicts for {manifest_key}")
        existing = _read_policy_document(policy_name, region)
        if existing != expected_document:
            raise lab.LabError(f"Existing IoT policy differs from required least-privilege policy: {policy_name}")
        return

    try:
        existing = _read_policy_document(policy_name, region)
    except lab.LabError as error:
        if "ResourceNotFoundException" not in str(error):
            raise
        document = json.dumps(expected_document, separators=(",", ":"))
        lab.run_aws(
            ["iot", "create-policy", "--policy-name", policy_name, "--policy-document", document],
            region,
        )
    else:
        if existing != expected_document:
            raise lab.LabError(f"Existing IoT policy differs; refusing to overwrite: {policy_name}")
    resources[manifest_key] = policy_name
    lab.atomic_write(ROOT / ".local" / "resources.json", json.dumps(resources, indent=2) + "\n")


def _ensure_certificate(identity, cert_manifest_key, cert_file, key_file, resources, region):
    cert_id = resources.get(cert_manifest_key)
    if cert_id:
        if not re.fullmatch(r"[0-9a-f]{64}", cert_id):
            raise lab.LabError(f"Invalid certificate ID in resource manifest: {cert_manifest_key}")
        if not _safe_local_file(cert_file) or not _safe_local_file(key_file):
            raise lab.LabError(f"Manifested {identity} certificate is missing locally; refusing to create a duplicate")
        return cert_id
    if _safe_local_file(cert_file) or _safe_local_file(key_file):
        raise lab.LabError(f"Untracked {identity} IoT certificate files exist; refusing to overwrite")

    response = lab.run_aws(["iot", "create-keys-and-certificate", "--set-as-active"], region)
    description = response.get("certificatePem")
    key_pair = response.get("keyPair") or {}
    private_key = key_pair.get("PrivateKey")
    cert_id = response.get("certificateId")
    if not cert_id or not description or not private_key:
        raise lab.LabError("AWS did not return the complete certificate material; inspect AWS IoT inventory before retrying")
    _write_private(cert_file, description)
    _write_private(key_file, private_key)
    resources[cert_manifest_key] = cert_id
    lab.atomic_write(ROOT / ".local" / "resources.json", json.dumps(resources, indent=2) + "\n")
    return cert_id


def _ensure_attached(policy_name, cert_id, account, region):
    target = f"arn:aws:iot:{region}:{account}:cert/{cert_id}"
    attached = lab.run_aws(["iot", "list-attached-policies", "--target", target], region)
    names = {item.get("policyName") for item in attached.get("policies", [])}
    if policy_name not in names:
        lab.run_aws(
            ["iot", "attach-policy", "--policy-name", policy_name, "--target", target],
            region,
        )


def _ensure_root_ca():
    path = IOT_DIR / "AmazonRootCA1.pem"
    if _safe_local_file(path):
        return
    try:
        with urlopen(CA_URL, timeout=20) as response:
            certificate = response.read(32_769)
    except (URLError, TimeoutError, OSError) as error:
        raise lab.LabError("Could not download Amazon Root CA 1 over HTTPS") from error
    if len(certificate) > 32_768 or b"-----BEGIN CERTIFICATE-----" not in certificate:
        raise lab.LabError("Downloaded Amazon Root CA 1 did not pass basic PEM validation")
    _write_private(path, certificate.decode("ascii"))


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("code")
    args = parser.parse_args()
    if not CODE_RE.fullmatch(args.code):
        parser.error("code must match ^[A-Za-z0-9-]{1,40}$")
    if len(args.code + "-d10") > 32:
        parser.error("code is too long for the W4 device_id limit of 32 characters")
    context = lab.verify()
    lab.approve(
        "AWS IoT changes: create/reuse two certificates and two exact-topic policies for "
        f"{args.code}; download one public Amazon Root CA file and record resource IDs locally. "
        "No EC2/RDS, IAM, or network rules will be changed. IoT message/connectivity charges may apply.",
        f"CREATE W6 IOT {args.code}",
    )
    IOT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if IOT_DIR.is_symlink():
        raise lab.LabError("Refusing symlink for .local/iot")
    IOT_DIR.chmod(0o700)
    manifest_path = ROOT / ".local" / "resources.json"
    if manifest_path.is_symlink():
        raise lab.LabError("Refusing symlink for .local/resources.json")
    with manifest_path.open(encoding="utf-8") as stream:
        resources = json.load(stream)
    if resources.get("iot_code") not in (None, args.code):
        raise lab.LabError("IoT code does not match the existing W6 resource manifest")
    if resources.get("iot_code") is None:
        resources["iot_code"] = args.code
        lab.atomic_write(manifest_path, json.dumps(resources, indent=2) + "\n")

    endpoint_path = IOT_DIR / "endpoint"
    if not _safe_local_file(endpoint_path):
        endpoint = lab.run_aws(
            ["iot", "describe-endpoint", "--endpoint-type", "iot:Data-ATS"],
            context["region"],
        ).get("endpointAddress")
        if not endpoint or not re.fullmatch(r"[a-z0-9-]+\.iot\.[a-z0-9-]+\.amazonaws\.com", endpoint):
            raise lab.LabError("AWS returned an invalid IoT data endpoint")
        _write_private(endpoint_path, endpoint + "\n")

    gateway_cert = _ensure_certificate(
        "gateway",
        "iot_gw_cert_id",
        IOT_DIR / "gw.cert.pem",
        IOT_DIR / "gw.private.key",
        resources,
        context["region"],
    )
    consumer_cert = _ensure_certificate(
        "consumer",
        "iot_consumer_cert_id",
        IOT_DIR / "consumer.cert.pem",
        IOT_DIR / "consumer.private.key",
        resources,
        context["region"],
    )
    gateway_policy, consumer_policy = _policy_documents(context["account"], context["region"], args.code)
    gateway_policy_name = f"cxe-{args.code}-gw"
    consumer_policy_name = f"cxe-{args.code}-consumer"
    _ensure_policy(gateway_policy_name, gateway_policy, "iot_gw_policy", resources, context["region"])
    _ensure_policy(consumer_policy_name, consumer_policy, "iot_consumer_policy", resources, context["region"])
    _ensure_attached(gateway_policy_name, gateway_cert, context["account"], context["region"])
    _ensure_attached(consumer_policy_name, consumer_cert, context["account"], context["region"])
    _ensure_root_ca()

    for label, cert_id in (("gateway", gateway_cert), ("consumer", consumer_cert)):
        status = lab.run_aws(
            ["iot", "describe-certificate", "--certificate-id", cert_id, "--query", "certificateDescription.status"],
            context["region"],
            raw=True,
        ).strip().strip('"')
        if status != "ACTIVE":
            raise lab.LabError(f"{label} certificate is not ACTIVE")
        print(f"{label} certificate: ACTIVE (ID ends {cert_id[-4:]})")


if __name__ == "__main__":
    try:
        main()
    except (lab.LabError, OSError, ValueError, json.JSONDecodeError) as error:
        print("STOP: " + str(error), file=sys.stderr)
        raise SystemExit(1)
