#!/usr/bin/env python3
"""W3 supplied inspection-service prototype; extend routes in later Sprints."""
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import import_module
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import unquote, urlsplit


DB_CA_FILE = "/etc/inspection/rds-ca.pem"
EVENT_COLUMNS = 'event_id, device_id, observed_at, "type", note, received_at'


class DatabaseUnavailable(Exception):
    pass


def database_configured():
    required = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
    return all(os.environ.get(name) for name in required) and Path(DB_CA_FILE).is_file()


def _event_from_row(row):
    event = {
        "event_id": row[0],
        "device_id": row[1],
        "observed_at": row[2],
        "type": row[3],
        "received_at": row[5].astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    if row[4] is not None:
        event["note"] = row[4]
    return event


def _database_operation(operation):
    try:
        psycopg2 = import_module("psycopg2")
    except ImportError:
        raise DatabaseUnavailable from None

    connection = None
    try:
        connection = psycopg2.connect(
            host=os.environ["DB_HOST"],
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            sslmode="verify-full",
            sslrootcert=DB_CA_FILE,
            connect_timeout=5,
        )
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        event_id VARCHAR(64) PRIMARY KEY,
                        device_id VARCHAR(32) NOT NULL,
                        observed_at TEXT NOT NULL,
                        "type" VARCHAR(16) NOT NULL,
                        note TEXT,
                        received_at TIMESTAMPTZ NOT NULL
                    )
                    """
                )
                return operation(cursor)
    except psycopg2.Error:
        raise DatabaseUnavailable from None
    finally:
        if connection is not None:
            connection.close()


def _database_list_events():
    def query(cursor):
        cursor.execute(
            f"SELECT {EVENT_COLUMNS} FROM events ORDER BY received_at DESC, event_id DESC LIMIT %s",
            (50,),
        )
        return [_event_from_row(row) for row in cursor.fetchall()]

    return _database_operation(query)


def _database_get_event(event_id):
    def query(cursor):
        cursor.execute(
            f"SELECT {EVENT_COLUMNS} FROM events WHERE event_id = %s",
            (event_id,),
        )
        row = cursor.fetchone()
        return _event_from_row(row) if row is not None else None

    return _database_operation(query)


def _database_store_event(event):
    def query(cursor):
        received_at = datetime.now(timezone.utc)
        values = (
            event["event_id"],
            event["device_id"],
            event["observed_at"],
            event["type"],
            event.get("note"),
            received_at,
        )
        cursor.execute(
            """
            INSERT INTO events (event_id, device_id, observed_at, "type", note, received_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING event_id
            """,
            values,
        )
        if cursor.fetchone() is not None:
            return 201, {**event, "received_at": received_at.isoformat(timespec="seconds").replace("+00:00", "Z")}

        cursor.execute(
            f"SELECT {EVENT_COLUMNS} FROM events WHERE event_id = %s",
            (event["event_id"],),
        )
        existing = cursor.fetchone()
        if existing is None:
            raise DatabaseUnavailable
        stored = _event_from_row(existing)
        same_content = all(
            stored.get(field) == event.get(field)
            for field in ("event_id", "device_id", "observed_at", "type", "note")
        )
        if same_content:
            return 200, stored
        return 409, {"error": "duplicate_event", "field": "event_id"}

    return _database_operation(query)


def make_server(version_file, port=8080):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    reporter_token = os.environ.get("REPORTER_TOKEN", "")
    operator_token = os.environ.get("OPERATOR_TOKEN", "")
    auth_configured = bool(reporter_token and operator_token and reporter_token != operator_token)
    db_configured = database_configured()
    events = {}
    events_lock = threading.Lock()
    event_id_pattern = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
    device_id_pattern = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
    allowed_fields = {"event_id", "device_id", "observed_at", "type", "note"}
    required_fields = ("event_id", "device_id", "observed_at", "type")
    event_types = {"status", "anomaly", "test"}

    def json_bytes(value):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")

    def validate_event(data):
        if not isinstance(data, dict):
            return None, "body"
        extra = sorted(set(data) - allowed_fields)
        if extra:
            return None, "body"
        for field in required_fields:
            if field not in data:
                return None, field
        if not isinstance(data["event_id"], str) or not event_id_pattern.fullmatch(data["event_id"]):
            return None, "event_id"
        if not isinstance(data["device_id"], str) or not device_id_pattern.fullmatch(data["device_id"]):
            return None, "device_id"
        if not isinstance(data["observed_at"], str):
            return None, "observed_at"
        try:
            observed_at = datetime.fromisoformat(data["observed_at"].replace("Z", "+00:00"))
        except ValueError:
            return None, "observed_at"
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            return None, "observed_at"
        if not isinstance(data["type"], str) or data["type"] not in event_types:
            return None, "type"
        if "note" in data and (not isinstance(data["note"], str) or len(data["note"]) > 200):
            return None, "note"
        return data, None

    display_page = """<!doctype html>
<html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Inspection events</title>
<main><h1>巡檢事件</h1><label>Operator 權杖 <input id="token" type="password" autocomplete="off"></label>
<button id="load" type="button">載入事件</button><p id="status" role="status"></p><ol id="events"></ol></main>
<script>
const tokenInput = document.querySelector('#token');
const statusOutput = document.querySelector('#status');
const eventList = document.querySelector('#events');
document.querySelector('#load').addEventListener('click', async () => {
  const token = tokenInput.value;
  tokenInput.value = '';
  eventList.replaceChildren();
  try {
    const response = await fetch('/events', {headers: {Authorization: `Bearer ${token}`}});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    statusOutput.textContent = `${result.events.length} 筆事件`;
    for (const event of result.events) {
      const item = document.createElement('li');
      item.textContent = `${event.event_id} | ${event.device_id} | ${event.type} | ${event.received_at} | ${event.note || ''}`;
      eventList.append(item);
    }
  } catch (error) {
    statusOutput.textContent = error.message;
  }
});
</script></html>""".encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/health":
                self.send_json(200, {"status": "ok", "service": "inspection", "version": version,
                                     "started_at": started, "auth_configured": auth_configured,
                                     "db_configured": db_configured})
                return
            if path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(display_page)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(display_page)
                return
            if path == "/events":
                role = self.authorized_role()
                if role is None:
                    return
                if role != "operator":
                    self.send_json(403, {"error": "forbidden", "field": "role"})
                    return
                if db_configured:
                    try:
                        latest = _database_list_events()
                    except DatabaseUnavailable:
                        self.send_json(503, {"error": "database_unavailable", "field": "database"})
                        return
                else:
                    with events_lock:
                        latest = list(events.values())[-50:][::-1]
                self.send_json(200, {"events": latest})
                return
            if path.startswith("/events/") and path.count("/") == 2:
                role = self.authorized_role()
                if role is None:
                    return
                if role != "operator":
                    self.send_json(403, {"error": "forbidden", "field": "role"})
                    return
                event_id = unquote(path.removeprefix("/events/"))
                if db_configured:
                    try:
                        event = _database_get_event(event_id)
                    except DatabaseUnavailable:
                        self.send_json(503, {"error": "database_unavailable", "field": "database"})
                        return
                else:
                    with events_lock:
                        event = events.get(event_id)
                if event is None:
                    self.send_json(404, {"error": "not_found", "field": "event_id"})
                    return
                self.send_json(200, event)
                return
            self.send_json(404, {"error": "not_found", "field": "path"})

        def do_POST(self):
            if urlsplit(self.path).path != "/events":
                self.send_json(404, {"error": "not_found", "field": "path"})
                return
            role = self.authorized_role()
            if role is None:
                return
            if role != "reporter":
                self.send_json(403, {"error": "forbidden", "field": "role"})
                return
            if self.headers.get_content_type() != "application/json":
                self.send_json(400, {"error": "invalid_content_type", "field": "Content-Type"})
                return
            try:
                content_length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                content_length = 0
            if content_length <= 0 or content_length > 4096:
                self.send_json(400, {"error": "invalid_body_size", "field": "body"})
                return
            try:
                payload = json.loads(self.rfile.read(content_length))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.send_json(400, {"error": "invalid_json", "field": "body"})
                return
            event, field = validate_event(payload)
            if field is not None:
                self.send_json(400, {"error": "invalid_event", "field": field})
                return
            if db_configured:
                try:
                    result_status, stored = _database_store_event(event)
                except DatabaseUnavailable:
                    self.send_json(503, {"error": "database_unavailable", "field": "database"})
                    return
            else:
                with events_lock:
                    if event["event_id"] in events:
                        self.send_json(409, {"error": "duplicate_event", "field": "event_id"})
                        return
                    stored = dict(event)
                    stored["received_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                    events[stored["event_id"]] = stored
                result_status = 201
            self.send_json(result_status, stored)

        def authorized_role(self):
            if not auth_configured:
                self.send_json(401, {"error": "unauthorized", "field": "Authorization"})
                return None
            authorization = self.headers.get("Authorization", "")
            if not authorization.startswith("Bearer "):
                self.send_json(401, {"error": "unauthorized", "field": "Authorization"})
                return None
            supplied = authorization[7:]
            reporter = hmac.compare_digest(supplied, reporter_token)
            operator = hmac.compare_digest(supplied, operator_token)
            if reporter:
                return "reporter"
            if operator:
                return "operator"
            self.send_json(401, {"error": "unauthorized", "field": "Authorization"})
            return None

        def send_json(self, status, body):
            data = json_bytes(body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):
            pass  # Never log request paths, bodies, headers or query strings.

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.events = events
    server.events_lock = events_lock
    return server


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
