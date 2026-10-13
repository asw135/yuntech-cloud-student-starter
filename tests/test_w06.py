"""Offline tests for W6 consumer validation and simulator event shapes."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "deploy"))
sys.path.insert(0, str(ROOT / "tests"))
import consumer
import gateway_sim
import iot_up
import w06_reconcile


class ConsumerContract(unittest.TestCase):
    def setUp(self):
        self.allowed = {f"aabbcc-W3-Lab-d{number:02d}" for number in range(1, 11)}
        self.event = {
            "event_id": "aabbcc-W3-Lab-r1-d01-01",
            "device_id": "aabbcc-W3-Lab-d01",
            "observed_at": "2026-10-13T00:00:00Z",
            "type": "status",
        }

    def test_allowlisted_devices_are_forwarded_and_classified(self):
        for status, expected in ((201, "created"), (200, "duplicate"), (409, "rejected"), (503, "error"), (None, "error")):
            calls = []
            event_id, result = consumer.process_payload(
                __import__("json").dumps(self.event).encode(),
                self.allowed,
                "not-logged",
                lambda event, token, value=status: calls.append((event, token)) or value,
            )
            self.assertEqual((event_id, result), (self.event["event_id"], expected))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][1], "not-logged")

    def test_unlisted_device_is_rejected_before_api_call(self):
        calls = []
        event = dict(self.event, device_id="aabbcc-W3-Lab-d99")
        event_id, result = consumer.process_payload(
            __import__("json").dumps(event).encode(),
            self.allowed,
            "not-logged",
            lambda event, token: calls.append(event) or 201,
        )
        self.assertEqual((event_id, result), (event["event_id"], "rejected"))
        self.assertEqual(calls, [])

    def test_invalid_payloads_are_rejected_without_echoing_content(self):
        self.assertEqual(consumer.process_payload(b"not-json", self.allowed, "secret"), ("invalid", "rejected"))
        event_id, result = consumer.process_payload(
            b'{"event_id":"bad\\nline","device_id":"aabbcc-W3-Lab-d01"}',
            self.allowed,
            "secret",
        )
        self.assertEqual((event_id, result), ("invalid", "rejected"))


class GatewayContract(unittest.TestCase):
    def test_batch_has_thirty_unique_allowed_events_one_duplicate_and_one_unlisted(self):
        prefix, events = gateway_sim.build_events("aabbcc-W3-Lab", "r12")
        self.assertEqual(prefix, "aabbcc-W3-Lab-r12")
        self.assertEqual(len(events), 32)
        self.assertEqual(events[0], events[30])
        self.assertEqual(len({event["event_id"] for event in events[:30]}), 30)
        self.assertEqual(events[31]["device_id"], "aabbcc-W3-Lab-d99")
        self.assertTrue(all(event["type"] == "status" for event in events))
        self.assertTrue(all(event["observed_at"].endswith("Z") for event in events))

    def test_policy_resources_are_exact_and_use_topicfilter_for_subscribe(self):
        gateway, consumer_policy = iot_up._policy_documents("123456789012", "us-east-1", "aabbcc-W3-Lab")
        self.assertEqual(
            gateway["Statement"][1]["Resource"],
            ["arn:aws:iot:us-east-1:123456789012:topic/cxe/aabbcc-W3-Lab/gw/events"],
        )
        self.assertEqual(
            consumer_policy["Statement"][1]["Resource"],
            ["arn:aws:iot:us-east-1:123456789012:topicfilter/cxe/aabbcc-W3-Lab/gw/events"],
        )
        self.assertFalse(any("*" in resource for policy in (gateway, consumer_policy)
                             for statement in policy["Statement"] for resource in statement["Resource"]))

    def test_policy_attachment_uses_certificate_arn(self):
        with patch.object(iot_up.lab, "run_aws", side_effect=[{"policies": []}, {}]) as run_aws:
            iot_up._ensure_attached("cxe-aabbcc-W3-Lab-gw", "a" * 64, "123456789012", "us-east-1")
        target = f"arn:aws:iot:us-east-1:123456789012:cert/{'a' * 64}"
        self.assertEqual(run_aws.call_args_list[0].args[0], [
            "iot", "list-attached-policies", "--target", target,
        ])
        self.assertEqual(run_aws.call_args_list[1].args[0], [
            "iot", "attach-policy", "--policy-name", "cxe-aabbcc-W3-Lab-gw", "--target", target,
        ])

    def test_rejects_invalid_event_run_prefix(self):
        with self.assertRaises(ValueError):
            gateway_sim.build_events("valid-code", "r1;bad")
        with self.assertRaises(ValueError):
            gateway_sim.build_events("valid-code", "r0")
        with self.assertRaises(ValueError):
            gateway_sim.build_events("a" * 30, "r1")
        with self.assertRaises(ValueError):
            gateway_sim.build_events("a" * 28, "r" + "1" * 15)

    def test_run_number_must_increment_from_last_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local = root / ".local"
            local.mkdir()
            (local / "w06-last-run.json").write_text(
                '{"prefix":"aabbcc-W3-Lab-r3","puback_ok":32,"total":32}\n',
                encoding="utf-8",
            )
            with patch.object(gateway_sim, "ROOT", root):
                gateway_sim.ensure_new_prefix("aabbcc-W3-Lab-r4", "aabbcc-W3-Lab", "r4")
                with self.assertRaises(ValueError):
                    gateway_sim.ensure_new_prefix("aabbcc-W3-Lab-r3", "aabbcc-W3-Lab", "r3")


class ReconcileContract(unittest.TestCase):
    def test_filter_uses_operator_token_header_and_only_returns_current_prefix(self):
        response = type("Response", (), {
            "returncode": 0,
            "stdout": json.dumps({"events": [
                {"event_id": "aabbcc-W3-Lab-r1-d01-01"},
                {"event_id": "aabbcc-W3-Lab-r2-d01-01"},
            ]}),
        })()
        with patch.object(w06_reconcile.subprocess, "run", return_value=response) as run:
            event_ids = w06_reconcile._filtered_events(
                "192.0.2.1", "aabbcc-W3-Lab", "aabbcc-W3-Lab-r1",
            )
        self.assertEqual(event_ids, ["aabbcc-W3-Lab-r1-d01-01"])
        shell_script = run.call_args.args[0][2]
        self.assertIn("printf 'Authorization: %s\\n' \"$OPERATOR_TOKEN\"", shell_script)

    def test_reconcile_prefix_uses_w6_prefix_contract(self):
        self.assertTrue(w06_reconcile.PREFIX_RE.fullmatch("aabbcc-W3-Lab-r1"))
        self.assertFalse(w06_reconcile.PREFIX_RE.fullmatch("a" * 41))


if __name__ == "__main__":
    unittest.main()
