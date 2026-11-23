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

_EVENT_META = {
    "inject":             {"color": "#00ff41", "glow": "#00ff41", "icon": ">>"},
    "menu_open":          {"color": "#7c3aed", "glow": "#a855f7", "icon": "[]"},
    "menu_close":         {"color": "#6d28d9", "glow": "#7c3aed", "icon": "[]"},
    "destruct":           {"color": "#ff2d55", "glow": "#ff2d55", "icon": "!!"},
    "auth":               {"color": "#64748b", "glow": "#94a3b8", "icon": ".."},
    "auth_ok":            {"color": "#00ff41", "glow": "#00ff41", "icon": "OK"},
    "auth_expired":       {"color": "#fbbf24", "glow": "#fbbf24", "icon": "EX"},
    "auth_hwid_mismatch": {"color": "#ff2d55", "glow": "#ff2d55", "icon": "HW"},
    "fac_reset_request":  {"color": "#f97316", "glow": "#f97316", "icon": "FC"},
    "custom":             {"color": "#64748b", "glow": "#94a3b8", "icon": ">>"},
}

def _badge(event_type):
    m = _EVENT_META.get(event_type, {"color": "#64748b", "glow": "#94a3b8", "icon": ">>"})
    c, g = m["color"], m["glow"]
    return (
        f'<span class="badge" style="'
        f'color:{c};border:1px solid {c};'
        f'box-shadow:0 0 6px {g}44,inset 0 0 6px {g}11;'
        f'text-shadow:0 0 8px {g};'
        f'">{html.escape(event_type)}</span>'
    )


def _get_stats():
    try:
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        today = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (today_str,)
        ).fetchone()[0]
        users = conn.execute("SELECT COUNT(DISTINCT discord_id) FROM events").fetchone()[0]
        injects = conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='inject'"
        ).fetchone()[0]
        destructs = conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_type='destruct'"
        ).fetchone()[0]
        conn.close()
        return total, today, users, injects, destructs
    except Exception:
        return 0, 0, 0, 0, 0


def _render_dashboard(rows, total, offset, qs_raw):
    prev_off = max(0, offset - PAGE_SIZE)
    next_off = offset + PAGE_SIZE
    has_prev = offset > 0
    has_next = (offset + PAGE_SIZE) < total

    q_discord = html.escape(qs_raw.get("discord_id", [""])[0])
    q_key     = html.escape(qs_raw.get("key",        [""])[0])
    q_type    = html.escape(qs_raw.get("event_type", [""])[0])

    stat_total, stat_today, stat_users, stat_injects, stat_destructs = _get_stats()

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
            geo += ' <span class="vpn-tag">VPN</span>'

        did = html.escape(r.get("discord_id") or "")
        did_link = (
            f'<a href="?discord_id={did}&key={API_KEY}" class="did-link">{did}</a>'
            if did else '<span class="dim">-</span>'
        )

        et = r.get("event_type", "")
        em = _EVENT_META.get(et, {"color": "#64748b"})
        row_glow = em["color"] + "08"

        rows_html += f"""<tr class="data-row" style="--row-accent:{em['color']}">
          <td class="id-cell">#{r['id']}</td>
          <td class="ts-cell">{ts_fmt}</td>
          <td>{_badge(et)}</td>
          <td class="did-cell">{did_link}</td>
          <td class="dim-cell">{html.escape(r.get('product') or '-')}</td>
          <td class="dim-cell">{html.escape((r.get('sys_hostname') or r.get('ip') or '-'))}</td>
          <td class="geo-cell">{geo or '<span class="dim">-</span>'}</td>
          <td class="os-cell">{html.escape(r.get('sys_os') or '-')}</td>
        </tr>"""

    def nav_link(off, label, enabled):
        if not enabled:
            return f'<span class="nav-disabled">{label}</span>'
        return (
            f'<a href="?discord_id={q_discord}&key={q_key}&event_type={q_type}'
            f'&offset={off}" class="nav-link">{label}</a>'
        )

    page_num = offset // PAGE_SIZE + 1
    page_tot = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    clear_link = (
        f'<a href="?key={API_KEY}" class="clear-link">clear filters</a>'
        if q_discord or q_type else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VOID BYPASS // LOGS</title>
  <style>
    :root {{
      --bg:        #060610;
      --bg2:       #0a0a1a;
      --bg3:       #0d0d20;
      --border:    #1a1a3a;
      --accent:    #00ff41;
      --accent2:   #7c3aed;
      --accent3:   #ff2d55;
      --dim:       #3a3a5c;
      --text:      #c8c8e8;
      --text-dim:  #5a5a8a;
      --font:      'Courier New', 'Lucida Console', monospace;
    }}
    *,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0 }}
    html {{ height:100%; background:var(--bg) }}
    body {{
      min-height:100vh;
      background:var(--bg);
      color:var(--text);
      font-family:var(--font);
      font-size:13px;
      overflow-x:hidden;
      position:relative;
    }}

    /* matrix canvas */
    #matrix {{
      position:fixed;
      top:0; left:0;
      width:100%; height:100%;
      opacity:0.045;
      pointer-events:none;
      z-index:0;
    }}

    /* scanline overlay */
    body::after {{
      content:'';
      position:fixed;
      inset:0;
      background:repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,0,0,0.08) 2px,
        rgba(0,0,0,0.08) 4px
      );
      pointer-events:none;
      z-index:999;
    }}

    .wrap {{
      position:relative;
      z-index:1;
      max-width:1400px;
      margin:0 auto;
      padding:28px 24px;
    }}

    /* header */
    .header {{
      display:flex;
      align-items:flex-end;
      gap:20px;
      margin-bottom:28px;
      padding-bottom:20px;
      border-bottom:1px solid var(--border);
    }}
    .logo {{
      font-size:28px;
      font-weight:900;
      letter-spacing:4px;
      color:var(--accent);
      text-shadow:0 0 20px var(--accent),0 0 40px var(--accent)66;
      line-height:1;
    }}
    .logo span {{ color:var(--accent2); text-shadow:0 0 20px var(--accent2); }}
    .logo-sub {{
      font-size:11px;
      color:var(--text-dim);
      letter-spacing:3px;
      text-transform:uppercase;
      margin-bottom:3px;
    }}
    .header-right {{
      margin-left:auto;
      text-align:right;
    }}
    .live-dot {{
      display:inline-block;
      width:7px; height:7px;
      border-radius:50%;
      background:var(--accent);
      box-shadow:0 0 8px var(--accent);
      animation:pulse 1.4s ease-in-out infinite;
      margin-right:6px;
      vertical-align:middle;
    }}
    .live-label {{
      font-size:11px;
      color:var(--accent);
      text-shadow:0 0 8px var(--accent);
      letter-spacing:2px;
    }}

    /* stat tiles */
    .stats {{
      display:grid;
      grid-template-columns:repeat(5,1fr);
      gap:12px;
      margin-bottom:24px;
    }}
    @media(max-width:900px){{ .stats{{grid-template-columns:repeat(3,1fr)}} }}
    .stat {{
      background:var(--bg2);
      border:1px solid var(--border);
      border-radius:6px;
      padding:14px 16px;
      position:relative;
      overflow:hidden;
      transition:border-color .2s;
    }}
    .stat::before {{
      content:'';
      position:absolute;
      inset:0;
      background:linear-gradient(135deg,var(--s-color)08,transparent 60%);
    }}
    .stat:hover {{ border-color:var(--s-color); }}
    .stat-val {{
      font-size:26px;
      font-weight:900;
      color:var(--s-color);
      text-shadow:0 0 16px var(--s-color)88;
      line-height:1;
      margin-bottom:4px;
    }}
    .stat-label {{ font-size:10px; color:var(--text-dim); letter-spacing:2px; text-transform:uppercase }}

    /* filter bar */
    .filterbar {{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
      margin-bottom:20px;
      align-items:center;
    }}
    .filterbar input {{
      background:var(--bg2);
      border:1px solid var(--border);
      color:var(--text);
      padding:7px 12px;
      border-radius:4px;
      font-family:var(--font);
      font-size:12px;
      outline:none;
      transition:border-color .2s, box-shadow .2s;
      min-width:180px;
    }}
    .filterbar input:focus {{
      border-color:var(--accent2);
      box-shadow:0 0 10px var(--accent2)33;
    }}
    .filterbar input::placeholder {{ color:var(--text-dim) }}
    .filterbar button {{
      background:transparent;
      border:1px solid var(--accent2);
      color:var(--accent2);
      padding:7px 18px;
      border-radius:4px;
      cursor:pointer;
      font-family:var(--font);
      font-size:12px;
      letter-spacing:1px;
      transition:all .2s;
      text-shadow:0 0 8px var(--accent2)88;
      box-shadow:0 0 8px var(--accent2)22;
    }}
    .filterbar button:hover {{
      background:var(--accent2);
      color:#fff;
      box-shadow:0 0 16px var(--accent2)88;
    }}
    .clear-link {{
      color:var(--text-dim);
      font-size:11px;
      text-decoration:none;
      border:1px solid var(--dim);
      padding:7px 12px;
      border-radius:4px;
      transition:all .2s;
    }}
    .clear-link:hover {{ color:var(--text); border-color:var(--text-dim) }}

    /* table */
    .table-wrap {{
      border:1px solid var(--border);
      border-radius:8px;
      overflow:hidden;
      background:var(--bg2);
    }}
    .tbl {{ width:100%; border-collapse:collapse }}
    .tbl th {{
      background:var(--bg3);
      color:var(--text-dim);
      text-align:left;
      padding:10px 12px;
      font-size:10px;
      letter-spacing:2px;
      text-transform:uppercase;
      border-bottom:1px solid var(--border);
      white-space:nowrap;
    }}
    .tbl td {{
      padding:9px 12px;
      border-bottom:1px solid var(--border);
      vertical-align:middle;
    }}
    .data-row {{ transition:background .15s }}
    .data-row:hover {{ background:color-mix(in srgb,var(--row-accent) 5%,var(--bg3)) }}
    .data-row:last-child td {{ border-bottom:none }}

    .id-cell   {{ color:var(--text-dim); font-size:11px; white-space:nowrap }}
    .ts-cell   {{ color:var(--text); font-size:11px; white-space:nowrap; font-variant-numeric:tabular-nums }}
    .did-cell  {{ font-size:11px }}
    .dim-cell  {{ color:var(--text-dim); font-size:11px }}
    .geo-cell  {{ font-size:11px; color:var(--text-dim); white-space:nowrap }}
    .os-cell   {{ font-size:10px; color:var(--dim); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }}
    .dim       {{ color:var(--dim) }}

    .badge {{
      display:inline-block;
      padding:2px 8px;
      border-radius:3px;
      font-size:11px;
      letter-spacing:1px;
      font-weight:700;
      white-space:nowrap;
      background:transparent;
    }}

    .did-link {{
      color:#a78bfa;
      text-decoration:none;
      font-family:var(--font);
    }}
    .did-link:hover {{ text-shadow:0 0 8px #a78bfa; }}

    .vpn-tag {{
      display:inline-block;
      font-size:9px;
      color:#fbbf24;
      border:1px solid #fbbf2466;
      padding:0 4px;
      border-radius:2px;
      margin-left:4px;
      vertical-align:middle;
    }}

    /* pagination */
    .pager {{
      display:flex;
      align-items:center;
      justify-content:center;
      gap:12px;
      margin-top:20px;
      color:var(--text-dim);
      font-size:12px;
    }}
    .nav-link {{
      color:var(--accent);
      text-decoration:none;
      border:1px solid var(--accent)44;
      padding:5px 14px;
      border-radius:4px;
      transition:all .2s;
      text-shadow:0 0 8px var(--accent)66;
    }}
    .nav-link:hover {{
      border-color:var(--accent);
      box-shadow:0 0 10px var(--accent)44;
    }}
    .nav-disabled {{ color:var(--dim); padding:5px 14px }}
    .page-info {{ color:var(--text-dim); letter-spacing:1px }}
    .page-info b {{ color:var(--text) }}

    @keyframes pulse {{
      0%,100% {{ opacity:1; box-shadow:0 0 8px var(--accent) }}
      50%      {{ opacity:.4; box-shadow:0 0 3px var(--accent) }}
    }}
  </style>
</head>
<body>
<canvas id="matrix"></canvas>
<div class="wrap">

  <div class="header">
    <div>
      <div class="logo-sub">[ internal dashboard ]</div>
      <div class="logo">VOID <span>BYPASS</span> // LOGS</div>
    </div>
    <div class="header-right">
      <div><span class="live-dot"></span><span class="live-label">LIVE</span></div>
    </div>
  </div>

  <div class="stats">
    <div class="stat" style="--s-color:#00ff41">
      <div class="stat-val">{stat_total:,}</div>
      <div class="stat-label">Total Events</div>
    </div>
    <div class="stat" style="--s-color:#7c3aed">
      <div class="stat-val">{stat_today:,}</div>
      <div class="stat-label">Today</div>
    </div>
    <div class="stat" style="--s-color:#a78bfa">
      <div class="stat-val">{stat_users:,}</div>
      <div class="stat-label">Unique Users</div>
    </div>
    <div class="stat" style="--s-color:#00ff41">
      <div class="stat-val">{stat_injects:,}</div>
      <div class="stat-label">Injects</div>
    </div>
    <div class="stat" style="--s-color:#ff2d55">
      <div class="stat-val">{stat_destructs:,}</div>
      <div class="stat-label">Destructs</div>
    </div>
  </div>

  <form class="filterbar" method="get">
    <input name="discord_id" placeholder="filter by discord id" value="{q_discord}">
    <input name="event_type" placeholder="filter by event type" value="{q_type}">
    <input name="key" type="hidden" value="{API_KEY}">
    <button type="submit">[ FILTER ]</button>
    {clear_link}
  </form>

  <div class="table-wrap">
    <table class="tbl">
      <thead>
        <tr>
          <th>#</th>
          <th>Timestamp (UTC)</th>
          <th>Event</th>
          <th>Discord ID</th>
          <th>Product</th>
          <th>Host</th>
          <th>Geo</th>
          <th>OS</th>
        </tr>
      </thead>
      <tbody>
        {rows_html if rows_html else '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--dim)">[ no events ]</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="pager">
    {nav_link(prev_off, "&larr; prev", has_prev)}
    <span class="page-info">page <b>{page_num}</b> / <b>{page_tot}</b> &nbsp;&middot;&nbsp; {total:,} events</span>
    {nav_link(next_off, "next &rarr;", has_next)}
  </div>

</div>

<script>
(function(){{
  var c = document.getElementById('matrix');
  var ctx = c.getContext('2d');
  function resize(){{ c.width=window.innerWidth; c.height=window.innerHeight; }}
  resize();
  window.addEventListener('resize', resize);
  var cols = Math.floor(window.innerWidth / 16);
  var drops = Array.from({{length:cols}},()=>Math.random()*-80|0);
  var chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノ';
  function draw(){{
    ctx.fillStyle='rgba(6,6,16,0.05)';
    ctx.fillRect(0,0,c.width,c.height);
    ctx.fillStyle='#00ff41';
    ctx.font='14px monospace';
    for(var i=0;i<drops.length;i++){{
      ctx.fillText(chars[Math.random()*chars.length|0], i*16, drops[i]*16);
      if(drops[i]*16>c.height&&Math.random()>0.975) drops[i]=0;
      drops[i]++;
    }}
  }}
  setInterval(draw, 50);
}})();
</script>
</body>
</html>"""


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
