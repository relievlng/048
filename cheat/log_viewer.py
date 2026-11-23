#!/usr/bin/env python3
"""
Void Bypass - Cheat Log Viewer
Lightweight HTTP dashboard for the events table.

Deploy as a separate Railway service pointing at the same /data volume.
Auth: pass ?key=INTERNAL_API_KEY in the URL, or set it as a Bearer token.

Routes:
  GET  /             - HTML dashboard (paginated event log)
  GET  /events       - JSON event list  ?discord_id=&key=&event_type=&limit=&offset=
  GET  /user/:id     - JSON last-30 events for one Discord user
  GET  /health       - {"ok": true}
"""

import sqlite3
import json
import os
import html
import re
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

DB_PATH     = os.environ.get("DB_PATH", "/data/keylock.db")
API_KEY     = os.environ.get("INTERNAL_API_KEY", "")
PORT        = int(os.environ.get("PORT", 8090))
PAGE_SIZE   = 50


# ─── DB ───────────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def query_events(discord_id=None, key=None, event_type=None, limit=PAGE_SIZE, offset=0):
    conn = get_db()
    # Resolve key to discord_id if supplied
    if key and not discord_id:
        row = conn.execute(
            "SELECT discord_id FROM users WHERE key = ?", (key.upper(),)
        ).fetchone()
        if row:
            discord_id = row["discord_id"]

    wheres = []
    params = []
    if discord_id:
        wheres.append("discord_id = ?")
        params.append(str(discord_id))
    if event_type:
        wheres.append("event_type = ?")
        params.append(event_type)

    where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
    rows = conn.execute(
        f"""SELECT id, discord_id, hwid, ip, timestamp, event_type, product,
                   geo_country, geo_city, geo_vpn,
                   sys_os, sys_hostname, metadata
            FROM events {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?""",
        params + [int(limit), int(offset)],
    ).fetchall()
    total = conn.execute(
        f"SELECT COUNT(*) FROM events {where_sql}", params
    ).fetchone()[0]
    conn.close()
    return [dict(r) for r in rows], total


def get_user_summary(discord_id):
    conn = get_db()
    user = conn.execute(
        "SELECT key, product, status, hwid, expires_at FROM users WHERE discord_id = ?",
        (str(discord_id),)
    ).fetchone()
    events = conn.execute(
        """SELECT event_type, COUNT(*) as cnt, MAX(timestamp) as last_seen
           FROM events WHERE discord_id = ?
           GROUP BY event_type ORDER BY last_seen DESC""",
        (str(discord_id),)
    ).fetchall()
    conn.close()
    return dict(user) if user else {}, [dict(e) for e in events]


# ─── AUTH ─────────────────────────────────────────────────────────────────────

def _auth_ok(handler) -> bool:
    if not API_KEY:
        return True
    # Accept via query string or Authorization header
    parsed = urlparse(handler.path)
    qs = parse_qs(parsed.query)
    if qs.get("key", [None])[0] == API_KEY:
        return True
    auth_hdr = handler.headers.get("Authorization", "")
    if auth_hdr == f"Bearer {API_KEY}":
        return True
    return False


# ─── HTML DASHBOARD ───────────────────────────────────────────────────────────

_EVENT_COLORS = {
    "inject":           "#57F287",
    "menu_open":        "#5865F2",
    "menu_close":       "#7289DA",
    "destruct":         "#ED4245",
    "auth":             "#23272A",
    "auth_ok":          "#57F287",
    "auth_expired":     "#FEE75C",
    "auth_hwid_mismatch": "#ED4245",
    "fac_reset_request":"#FEE75C",
    "custom":           "#99AAB5",
}

def _badge(event_type):
    color = _EVENT_COLORS.get(event_type, "#99AAB5")
    return f'<span style="background:{color};color:#000;padding:2px 7px;border-radius:4px;font-size:12px;font-weight:600">{html.escape(event_type)}</span>'


def _render_dashboard(rows, total, offset, qs_raw):
    prev_off = max(0, offset - PAGE_SIZE)
    next_off = offset + PAGE_SIZE
    has_prev = offset > 0
    has_next = (offset + PAGE_SIZE) < total

    q_discord = html.escape(qs_raw.get("discord_id", [""])[0])
    q_key     = html.escape(qs_raw.get("key",        [""])[0])
    q_type    = html.escape(qs_raw.get("event_type", [""])[0])

    rows_html = ""
    for r in rows:
        ts_raw = r.get("timestamp", "")
        try:
            ts_fmt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts_fmt = ts_raw

        geo = ""
        if r.get("geo_country"):
            geo = html.escape(r["geo_country"])
            if r.get("geo_city"):
                geo = html.escape(r["geo_city"]) + ", " + geo
        if r.get("geo_vpn"):
            geo += " [VPN]"

        did = html.escape(r.get("discord_id") or "")
        did_link = (
            f'<a href="?discord_id={did}&key={API_KEY}" style="color:#5865F2">{did}</a>'
            if did else "-"
        )

        rows_html += f"""<tr>
          <td style="color:#666;font-size:11px">#{r['id']}</td>
          <td style="font-size:12px">{ts_fmt}</td>
          <td>{_badge(r.get('event_type',''))}</td>
          <td style="font-size:12px">{did_link}</td>
          <td style="font-size:12px;color:#aaa">{html.escape(r.get('product') or '-')}</td>
          <td style="font-size:12px;color:#aaa">{html.escape((r.get('sys_hostname') or r.get('ip') or '-'))}</td>
          <td style="font-size:12px;color:#aaa">{geo or '-'}</td>
          <td style="font-size:11px;color:#666;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{html.escape(r.get('sys_os') or '-')}</td>
        </tr>"""

    def nav_link(off, label, enabled):
        if not enabled:
            return f'<span style="color:#555;margin:0 4px">{label}</span>'
        return f'<a href="?discord_id={q_discord}&key={q_key}&event_type={q_type}&offset={off}&key={API_KEY}" style="color:#5865F2;margin:0 4px">{label}</a>'

    return f"""<!DOCTYPE html><html lang="en">
<head>
  <meta charset="utf-8">
  <title>Void Bypass - Cheat Logs</title>
  <style>
    body{{background:#1a1a2e;color:#e0e0e0;font-family:monospace;padding:24px;margin:0}}
    h1{{color:#5865F2;margin:0 0 16px}}
    .sub{{color:#888;font-size:13px;margin-bottom:20px}}
    form{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}}
    input{{background:#0f0f23;border:1px solid #444;color:#e0e0e0;padding:6px 10px;border-radius:4px;font-family:monospace}}
    button{{background:#5865F2;border:none;color:#fff;padding:6px 14px;border-radius:4px;cursor:pointer;font-family:monospace}}
    table{{width:100%;border-collapse:collapse;font-size:13px}}
    th{{background:#0f0f23;color:#888;text-align:left;padding:8px 10px;border-bottom:1px solid #333}}
    td{{padding:7px 10px;border-bottom:1px solid #1f1f3a;vertical-align:middle}}
    tr:hover{{background:#0f0f23}}
    .pager{{margin-top:16px;text-align:center;color:#aaa}}
    a{{color:#5865F2;text-decoration:none}}
    a:hover{{text-decoration:underline}}
  </style>
</head>
<body>
<h1>Void Bypass - Cheat Logs</h1>
<div class="sub">Showing {len(rows)} of {total:,} events (offset {offset})</div>
<form method="get">
  <input name="discord_id" placeholder="Discord ID" value="{q_discord}">
  <input name="event_type" placeholder="event_type" value="{q_type}">
  <input name="key" type="hidden" value="{API_KEY}">
  <button type="submit">Filter</button>
  {'<a href="?key=' + API_KEY + '" style="color:#888;font-size:12px;line-height:30px;margin-left:4px">clear</a>' if q_discord or q_type else ''}
</form>
<table>
  <tr>
    <th>#</th><th>Timestamp (UTC)</th><th>Event</th>
    <th>Discord ID</th><th>Product</th><th>Host</th><th>Geo</th><th>OS</th>
  </tr>
  {rows_html}
</table>
<div class="pager">
  {nav_link(prev_off, "Prev", has_prev)}
  page {offset // PAGE_SIZE + 1} / {max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)}
  {nav_link(next_off, "Next", has_next)}
</div>
</body></html>"""


# ─── HTTP HANDLER ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def _send(self, body: bytes, status=200, ct="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=200):
        self._send(json.dumps(data, default=str).encode(), status, "application/json")

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/") or "/"
        qs     = parse_qs(parsed.query)

        if path == "/health":
            self._json({"ok": True, "service": "void-cheat-logs"})
            return

        if not _auth_ok(self):
            self._json({"error": "forbidden"}, 403)
            return

        # JSON events API
        if path == "/events":
            did  = qs.get("discord_id", [None])[0]
            key  = qs.get("key",        [None])[0]
            etype= qs.get("event_type", [None])[0]
            lim  = min(int(qs.get("limit",  [PAGE_SIZE])[0]), 200)
            off  = int(qs.get("offset", [0])[0])
            rows, total = query_events(did, key, etype, lim, off)
            self._json({"total": total, "offset": off, "events": rows})
            return

        # User summary
        m = re.match(r"^/user/(\d+)$", path)
        if m:
            did = m.group(1)
            user, events = get_user_summary(did)
            rows, _ = query_events(discord_id=did, limit=30)
            self._json({"user": user, "event_summary": events, "recent_events": rows})
            return

        # HTML dashboard (root)
        off  = int(qs.get("offset", [0])[0])
        did  = qs.get("discord_id", [None])[0]
        key  = qs.get("key",        [None])[0]
        etype= qs.get("event_type", [None])[0]
        rows, total = query_events(did, key, etype, PAGE_SIZE, off)
        body = _render_dashboard(rows, total, off, qs).encode()
        self._send(body)

    def log_message(self, *args):
        pass


# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[log_viewer] listening on :{PORT} - DB: {DB_PATH}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
