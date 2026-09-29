#!/usr/bin/env python3
"""W3 supplied inspection-service prototype; extend routes in later Sprints."""
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import unquote, urlsplit


def make_server(version_file, port=8080):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    reporter_token = os.environ.get("REPORTER_TOKEN", "")
    operator_token = os.environ.get("OPERATOR_TOKEN", "")
    auth_configured = bool(reporter_token and operator_token and reporter_token != operator_token)
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
                                     "started_at": started, "auth_configured": auth_configured})
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
            with events_lock:
                if event["event_id"] in events:
                    self.send_json(409, {"error": "duplicate_event", "field": "event_id"})
                    return
                stored = dict(event)
                stored["received_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                events[stored["event_id"]] = stored
            self.send_json(201, stored)

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
