"""Offline public-contract checks; no AWS calls or classroom answers."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w03_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)
FIXTURES = ROOT / "tests/fixtures"


@contextmanager
def running_server():
    with tempfile.TemporaryDirectory() as td:
        version = Path(td) / "version"
        version.write_text("a" * 40)
        with patch.dict(os.environ, {"REPORTER_TOKEN": "reporter-secret", "OPERATOR_TOKEN": "operator-secret"}):
            server = service.make_server(version, port=0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield "http://127.0.0.1:" + str(server.server_port)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


def request(base, path, method="GET", token=None, body=None, content_type=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if content_type is not None:
        headers["Content-Type"] = content_type
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read()) if response.headers.get_content_type() == "application/json" else response.read().decode("utf-8")


class ServiceContract(unittest.TestCase):
    def test_health_version_and_unknown_route(self):
        with tempfile.TemporaryDirectory() as td:
            version = Path(td) / "version"
            version.write_text("a" * 40)
            server = service.make_server(version, port=0)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                self.assertEqual(server.server_address[0], "127.0.0.1")
                base = "http://127.0.0.1:" + str(server.server_port)
                with urllib.request.urlopen(base + "/health") as response:
                    result = json.load(response)
                    self.assertEqual(response.status, 200)
                    self.assertEqual(result["version"], "a" * 40)
                    self.assertEqual(result["service"], "inspection")
                    self.assertEqual(result["status"], "ok")
                    self.assertFalse(result["auth_configured"])
                    self.assertFalse(result["db_configured"])
                    self.assertTrue(result["started_at"].endswith("Z"))
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + "/unknown")
                self.assertEqual(caught.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)

    def test_invalid_deployment_version_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            version = Path(td) / "version"
            version.write_text("uncommitted")
            with self.assertRaises(ValueError):
                service.make_server(version, port=0)

    def test_fixture_events_create_reject_and_deduplicate(self):
        valid = json.loads((FIXTURES / "event-valid.json").read_text(encoding="utf-8"))
        invalid_fixtures = [
            ("event-invalid-timezone.json", "observed_at"),
            ("event-invalid-type.json", "type"),
        ]
        with running_server() as base:
            status, created = request(base, "/events", "POST", "reporter-secret", valid, "application/json")
            self.assertEqual(status, 201)
            self.assertEqual(created["event_id"], valid["event_id"])
            self.assertTrue(created["received_at"].endswith("Z"))
            status, duplicate = request(base, "/events", "POST", "reporter-secret", valid, "application/json")
            self.assertEqual(status, 409)
            self.assertEqual(duplicate["field"], "event_id")
            for filename, expected_field in invalid_fixtures:
                invalid = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
                status, rejected = request(base, "/events", "POST", "reporter-secret", invalid, "application/json")
                self.assertEqual(status, 400)
                self.assertEqual(rejected["field"], expected_field)
            invalid = dict(valid, event_id="aabbcc-W3_Lab-0004", type=[])
            status, rejected = request(base, "/events", "POST", "reporter-secret", invalid, "application/json")
            self.assertEqual(status, 400)
            self.assertEqual(rejected["field"], "type")

    def test_authentication_precedes_body_validation_and_roles_are_separated(self):
        with running_server() as base:
            status, rejected = request(base, "/events", "POST", body={"observed_at": "invalid"}, content_type="application/json")
            self.assertEqual(status, 401)
            self.assertEqual(set(rejected), {"error", "field"})
            status, rejected = request(base, "/events", "POST", "operator-secret", {}, "application/json")
            self.assertEqual(status, 403)
            status, rejected = request(base, "/events", token="reporter-secret")
            self.assertEqual(status, 403)
            status, rejected = request(
                base, "/events", "POST", "reporter-secret",
                {"event_id": "aabbcc-W3_Lab-leak", "device_id": "aabbcc-d01",
                 "observed_at": "2026-09-29T10:00:00Z", "type": "status",
                 "reporter-secret": "must-not-echo"},
                "application/json",
            )
            self.assertEqual(status, 400)
            self.assertNotIn("reporter-secret", json.dumps(rejected))

    def test_operator_can_list_and_get_events(self):
        event = json.loads((FIXTURES / "event-valid.json").read_text(encoding="utf-8"))
        with running_server() as base:
            status, created = request(base, "/events", "POST", "reporter-secret", event, "application/json")
            self.assertEqual(status, 201)
            status, listing = request(base, "/events", token="operator-secret")
            self.assertEqual(status, 200)
            self.assertEqual(listing["events"][0], created)
            status, detail = request(base, "/events/" + event["event_id"], token="operator-secret")
            self.assertEqual(status, 200)
            self.assertEqual(detail, created)
            status, missing = request(base, "/events/not-found", token="operator-secret")
            self.assertEqual(status, 404)
            self.assertEqual(missing["field"], "event_id")

    def test_payload_limits_and_display_page_safety(self):
        with running_server() as base:
            status, rejected = request(base, "/events", "POST", "reporter-secret", {}, "text/plain")
            self.assertEqual(status, 400)
            self.assertEqual(rejected["field"], "Content-Type")
            status, page = request(base, "/")
            self.assertEqual(status, 200)
            self.assertIn("textContent", page)
            self.assertNotIn("innerHTML", page)
            self.assertNotIn("localStorage", page)
