"""W5 persistence tests using a small PostgreSQL protocol double."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w05_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class FakePostgresError(Exception):
    pass


class FakeStore:
    def __init__(self):
        self.events = {}
        self.queries = []


class FakeCursor:
    def __init__(self, store):
        self.store = store
        self.one = None
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def execute(self, query, params=None):
        self.store.queries.append((query, params))
        normalized = " ".join(query.split())
        self.one = None
        self.rows = []
        if normalized.startswith("CREATE TABLE"):
            return None
        if normalized.startswith("INSERT INTO events"):
            event_id, device_id, observed_at, event_type, note, received_at = params
            if event_id not in self.store.events:
                self.store.events[event_id] = (
                    event_id,
                    device_id,
                    observed_at,
                    event_type,
                    note,
                    received_at,
                )
                self.one = (event_id,)
            return None
        if normalized.startswith("SELECT") and "WHERE event_id = %s" in normalized:
            self.one = self.store.events.get(params[0])
            return None
        if normalized.startswith("SELECT"):
            rows = sorted(
                self.store.events.values(),
                key=lambda row: (row[5], row[0]),
                reverse=True,
            )
            self.rows = rows[: params[0]]
            return None
        raise AssertionError("Unexpected SQL statement")

    def fetchone(self):
        row = self.one
        self.one = None
        return row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def cursor(self):
        return FakeCursor(self.store)

    def close(self):
        pass


def request(base, path, method="GET", token=None, body=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, timeout=3)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, json.loads(response.read())


class W05DatabaseContract(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.ca_file = Path(self.tempdir.name) / "rds-ca.pem"
        self.ca_file.write_text("test CA marker")
        self.store = FakeStore()
        self.connect_calls = []

        def connect(**kwargs):
            self.connect_calls.append(kwargs)
            return FakeConnection(self.store)

        self.driver = types.SimpleNamespace(Error=FakePostgresError, connect=connect)
        self.patches = [
            patch.dict(
                os.environ,
                {
                    "REPORTER_TOKEN": "reporter-secret",
                    "OPERATOR_TOKEN": "operator-secret",
                    "DB_HOST": "db.example.test",
                    "DB_NAME": "inspection",
                    "DB_USER": "inspection_admin",
                    "DB_PASSWORD": "db-secret",
                },
            ),
            patch.object(service, "DB_CA_FILE", str(self.ca_file)),
            patch.dict(sys.modules, {"psycopg2": self.driver}),
        ]
        for active_patch in self.patches:
            active_patch.start()

    def tearDown(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.tempdir.cleanup()

    def start_server(self):
        version = Path(self.tempdir.name) / "version"
        version.write_text("a" * 40)
        server = service.make_server(version, port=0)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        return server, worker, "http://127.0.0.1:" + str(server.server_port)

    @staticmethod
    def stop_server(server, worker):
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    def test_health_reports_database_configuration_and_ssl_is_verified(self):
        server, worker, base = self.start_server()
        try:
            status, health = request(base, "/health")
            self.assertEqual(status, 200)
            self.assertTrue(health["db_configured"])

            event = {
                "event_id": "aabbcc-W3_Lab-db-0001",
                "device_id": "aabbcc-d01",
                "observed_at": "2026-10-06T03:00:00Z",
                "type": "test",
                "note": "persistent event",
            }
            self.assertEqual(
                request(base, "/events", "POST", "reporter-secret", event)[0],
                201,
            )
            self.assertEqual(self.connect_calls[0]["sslmode"], "verify-full")
            self.assertEqual(self.connect_calls[0]["sslrootcert"], str(self.ca_file))
            self.assertEqual(self.connect_calls[0]["connect_timeout"], 5)
        finally:
            self.stop_server(server, worker)

    def test_idempotency_and_restart_persistence(self):
        event = {
            "event_id": "aabbcc-W3_Lab-db-0002",
            "device_id": "aabbcc-d01",
            "observed_at": "2026-10-06T03:01:00Z",
            "type": "test",
            "note": "original note",
        }
        server, worker, base = self.start_server()
        try:
            status, created = request(base, "/events", "POST", "reporter-secret", event)
            self.assertEqual(status, 201)
            status, replay = request(base, "/events", "POST", "reporter-secret", event)
            self.assertEqual(status, 200)
            self.assertEqual(replay, created)
            changed = dict(event, note="changed note")
            status, rejected = request(base, "/events", "POST", "reporter-secret", changed)
            self.assertEqual(status, 409)
            self.assertEqual(rejected, {"error": "duplicate_event", "field": "event_id"})
            self.assertEqual(len(self.store.events), 1)

            insert_queries = [
                (query, params)
                for query, params in self.store.queries
                if "INSERT INTO events" in query
            ]
            self.assertEqual(len(insert_queries), 3)
            self.assertTrue(all("%s" in query for query, _ in insert_queries))
            self.assertTrue(all(params[0] == event["event_id"] for _, params in insert_queries))
        finally:
            self.stop_server(server, worker)

        server, worker, base = self.start_server()
        try:
            status, listing = request(base, "/events", token="operator-secret")
            self.assertEqual(status, 200)
            self.assertEqual(listing["events"], [created])
            status, persisted = request(
                base,
                "/events/" + event["event_id"],
                token="operator-secret",
            )
            self.assertEqual(status, 200)
            self.assertEqual(persisted, created)
        finally:
            self.stop_server(server, worker)

    def test_database_errors_return_sanitized_503(self):
        def fail_to_connect(**kwargs):
            raise FakePostgresError("sensitive database connection details")

        self.driver.connect = fail_to_connect
        server, worker, base = self.start_server()
        try:
            status, result = request(base, "/events", token="operator-secret")
            self.assertEqual(status, 503)
            self.assertEqual(result, {"error": "database_unavailable", "field": "database"})
            self.assertNotIn("sensitive", json.dumps(result))
            self.assertNotIn("db-secret", json.dumps(result))
        finally:
            self.stop_server(server, worker)
