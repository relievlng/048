#!/usr/bin/env python3
"""
Customer Bot - Customer-facing Discord bot
Handles: ticket system, rules embed, verification, key lookup, HWID resets
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
import sqlite3
import logging
import asyncio
import aiohttp
import json
import os
import re
import io
from datetime import datetime, timezone
from typing import Optional
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# ─── ENV / CONFIG ─────────────────────────────────────────────────────────────

def _load_webhooks_env(path: str = "/data/webhooks.env") -> int:
    """
    Read webhook URLs from the shared volume file written by the staff bot.
    Overwrites any env key that is missing or empty, so Railway env vars set
    to blank strings don't block the file values from loading.
    Returns the number of keys loaded.
    """
    if not os.path.isfile(path):
        return 0
    loaded = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            # Overwrite if the env var is missing OR set to an empty string
            if key and val and not os.environ.get(key, "").strip():
                os.environ[key] = val
                loaded += 1
    return loaded

_webhooks_loaded = _load_webhooks_env()

# Env key -> CONFIG key mapping, used to sync CONFIG from env after a live reload
_WEBHOOK_ENV_MAP: dict[str, str] = {
    "WEBHOOK_CUSTOMER_VERIFICATIONS":  "wh_verifications",
    "WEBHOOK_CUSTOMER_HWID_RESETS":    "wh_hwid_resets",
    "WEBHOOK_CUSTOMER_TICKETS_OPENED": "wh_tickets_opened",
    "WEBHOOK_CUSTOMER_TICKETS_CLOSED": "wh_tickets_closed",
    "WEBHOOK_CUSTOMER_TICKET_TRANSCRIPTS": "wh_ticket_transcripts",
    "WEBHOOK_CUSTOMER_KEY_GENERATED":  "wh_key_generated",
    "WEBHOOK_CUSTOMER_BANS":           "wh_bans",
    "LOG_WEBHOOK_URL":                 "log_webhook_url",
}

def _refresh_webhook_config() -> None:
    """
    Re-read /data/webhooks.env and push any new URLs into CONFIG.
    Safe to call repeatedly. Handles the case where the staff bot
    writes webhooks.env AFTER the customer bot started (CONFIG has
    empty strings from the initial env snapshot; this fixes that).
    """
    _load_webhooks_env()  # sets os.environ for any missing/empty keys
    for env_key, cfg_key in _WEBHOOK_ENV_MAP.items():
        val = os.environ.get(env_key, "").strip()
        if val:
            CONFIG[cfg_key] = val  # always overwrite - file is ground truth

def env(key: str, default=None):
    return os.environ.get(key, default)

def env_int(key: str, default: int = 0) -> int:
    val = os.environ.get(key, "").strip()
    try:
        return int(val) if val else default
    except ValueError:
        return default

CONFIG = {
    "token":                   env("DISCORD_TOKEN") or env("TOKEN"),
    "guild_id":                env_int("GUILD_ID"),
    "admin_role_id":           env_int("ADMIN_ROLE_ID"),
    "management_role_id":               env_int("MANAGEMENT_ROLE_ID"),
    "resetup_needed_role_id":           env_int("RESETUP_NEEDED_ROLE_ID"),
    "resetup_needed_payment_role_id":   env_int("RESETUP_NEEDED_PAYMENT_ROLE_ID"),
    "verified_role_id":                 env_int("VERIFIED_ROLE_ID"),
    "setup_pings_role_id":     env_int("SETUP_PINGS_ROLE_ID"),
    "setup_alerts_channel_id": env_int("SETUP_ALERTS_CHANNEL_ID"),
    "ticket_category_id":      env_int("TICKET_CATEGORY_ID"),
    # Per-ticket-type Discord category channel IDs (auto-created on startup if missing)
    "ticket_cat_support":      env_int("TICKET_CAT_SUPPORT"),
    "ticket_cat_setup":        env_int("TICKET_CAT_SETUP"),
    "ticket_cat_purchase":     env_int("TICKET_CAT_PURCHASE"),
    "ticket_cat_management":   env_int("TICKET_CAT_MANAGEMENT"),
    "ticket_cat_hwid_reset":   env_int("TICKET_CAT_HWID_RESET"),
    "rules_channel_id":        env_int("RULES_CHANNEL_ID"),
    "verify_channel_id":       env_int("VERIFY_CHANNEL_ID"),
    "hwid_channel_id":         env_int("HWID_CHANNEL_ID"),
    "ticket_channel_id":       env_int("TICKET_CHANNEL_ID"),
    # Per-channel webhook URLs (from staff bot's auto-setup output)
    "wh_verifications":        env("WEBHOOK_CUSTOMER_VERIFICATIONS"),
    "wh_hwid_resets":          env("WEBHOOK_CUSTOMER_HWID_RESETS"),
    "wh_tickets_opened":       env("WEBHOOK_CUSTOMER_TICKETS_OPENED"),
    "wh_tickets_closed":       env("WEBHOOK_CUSTOMER_TICKETS_CLOSED"),
    "wh_ticket_transcripts":   env("WEBHOOK_CUSTOMER_TICKET_TRANSCRIPTS"),
    "wh_key_generated":        env("WEBHOOK_CUSTOMER_KEY_GENERATED"),
    "wh_bans":                 env("WEBHOOK_CUSTOMER_BANS"),
    # Fallback: single webhook for any event type not explicitly wired
    "log_webhook_url":         env("LOG_WEBHOOK_URL"),
    "db_path":                 env("DB_PATH", "/data/keylock.db"),
    "key_prefix":              env("KEY_PREFIX", "KL"),
    "api_port":                env_int("PORT", 8080),
    "void_bot_url":            env("VOID_BOT_URL", ""),
    "internal_api_key":        env("INTERNAL_API_KEY", ""),
    "max_hwid_resets":         env_int("MAX_HWID_RESETS", 1),
    "logo_url":                env("LOGO_URL"),
}

# ─── CUSTOM EMOJIS ────────────────────────────────────────────────────────────
# Upload the SVGs from /emojis/ to your Discord server, then paste the
# <:name:id> strings here. Until then the fallback Unicode chars show fine.

EMOJIS = {
    # --- original keys ---
    "verify":      env("EMOJI_VERIFY",      "<:verify:EMOJI_ID>"),
    "key":         env("EMOJI_KEY",         "<:key:EMOJI_ID>"),
    "chip":        env("EMOJI_CHIP",        "<:chip:EMOJI_ID>"),
    "ticket":      env("EMOJI_TICKET",      "<:ticket:EMOJI_ID>"),
    "rules":       env("EMOJI_RULES",       "<:rules:EMOJI_ID>"),
    "cross":       env("EMOJI_CROSS",       "<:cross:EMOJI_ID>"),
    "shield":      env("EMOJI_SHIELD",      "<:shield:EMOJI_ID>"),
    "arrow":       env("EMOJI_ARROW",       "<:arrow:EMOJI_ID>"),
    "warn":        env("EMOJI_WARN",        "<:warn:EMOJI_ID>"),
    "dot":         env("EMOJI_DOT",         "<:dot:EMOJI_ID>"),
    "bell":        env("EMOJI_BELL",        "<:bell:EMOJI_ID>"),
    "lock":        env("EMOJI_LOCK",        "<:lock:EMOJI_ID>"),
    "gear":        env("EMOJI_GEAR",        "<:gear:EMOJI_ID>"),
    # --- blue icon pack ---
    "ac":          env("EMOJI_AC",          "<:ac:EMOJI_ID>"),
    "vpn":         env("EMOJI_VPN",         "<:vpn:EMOJI_ID>"),
    "angry":       env("EMOJI_ANGRY",       "<:angry:EMOJI_ID>"),
    "yes":         env("EMOJI_YES",         "<:yes:EMOJI_ID>"),
    "pin":         env("EMOJI_PIN",         "<:pin:EMOJI_ID>"),
    "ban":         env("EMOJI_BAN",         "<:ban:EMOJI_ID>"),
    "heath":       env("EMOJI_HEATH",       "<:heath:EMOJI_ID>"),
    "no":          env("EMOJI_NO",          "<:no:EMOJI_ID>"),
    "camera":      env("EMOJI_CAMERA",      "<:camera:EMOJI_ID>"),
    "wave":        env("EMOJI_WAVE",        "<:wave:EMOJI_ID>"),
    "handshake":   env("EMOJI_HANDSHAKE",   "<:handshake:EMOJI_ID>"),
    "clash":       env("EMOJI_CLASH",       "<:clash:EMOJI_ID>"),
    "crown":       env("EMOJI_CROWN",       "<:crown:EMOJI_ID>"),
    "clock":       env("EMOJI_CLOCK",       "<:clock:EMOJI_ID>"),
    "bug":         env("EMOJI_BUG",         "<:bug:EMOJI_ID>"),
    "calendar":    env("EMOJI_CALENDAR",    "<:calendar:EMOJI_ID>"),
    "support":     env("EMOJI_SUPPORT",     "<:support:EMOJI_ID>"),
    "triangle":    env("EMOJI_TRIANGLE",    "<:triangle:EMOJI_ID>"),
    "eye":         env("EMOJI_EYE",         "<:eye:EMOJI_ID>"),
    "description": env("EMOJI_DESCRIPTION", "<:description:EMOJI_ID>"),
}

def e(name: str) -> str:
    """Return the custom emoji string for a given name, empty string if not loaded."""
    val = EMOJIS.get(name, "")
    return "" if "EMOJI_ID" in val else val

# ─── LOGGING ──────────────────────────────────────────────────────────────────

os.makedirs(os.path.dirname(os.path.abspath(CONFIG["db_path"])), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("CustomerBot")

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    path = CONFIG["db_path"]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # Shared DB with staff bot - wait for locks instead of raising immediately.
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

def lookup_user(discord_id: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE discord_id = ? AND status != 'banned'",
            (str(discord_id),)
        ).fetchone()

def lookup_key(key: str) -> Optional[sqlite3.Row]:
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE key = ?",
            (key.upper(),)
        ).fetchone()

def register_key_to_discord(key: str, discord_id: str) -> bool:
    """Link a key to a discord ID for verification. Returns True on success."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE key = ?", (key.upper(),)).fetchone()
        if not row:
            return False
        if row["discord_id"] and row["discord_id"] != str(discord_id):
            return False
        conn.execute(
            "UPDATE users SET discord_id = ? WHERE key = ?",
            (str(discord_id), key.upper())
        )
        conn.commit()
    return True

def reset_hwid(discord_id: str) -> tuple[bool, str]:
    """Reset HWID for a user. Returns (success, message)."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE discord_id = ?",
            (str(discord_id),)
        ).fetchone()
        if not row:
            return False, "No key linked to your account."
        max_resets = CONFIG.get("max_hwid_resets", 1)
        if row["hwid_resets"] >= max_resets:
            return False, f"You have used all {max_resets} HWID reset(s). Open a ticket for further assistance."
        conn.execute(
            "UPDATE users SET hwid = NULL, hwid_resets = hwid_resets + 1 WHERE discord_id = ?",
            (str(discord_id),)
        )
        conn.commit()
        remaining = max_resets - row["hwid_resets"] - 1
        return True, f"HWID reset successfully. You have **{remaining}** reset(s) remaining."

# ─── WEBHOOK LOGGING ──────────────────────────────────────────────────────────

async def send_log(
    title: str,
    description: str,
    color: int = 0x5865F2,
    fields: list = None,
    webhook_key: str = "log_webhook_url",
    thumbnail_url: str = None,
    footer: str = None,
    attachment_bytes: bytes = None,
    attachment_filename: str = None,
):
    """
    Send a Components V2 log to the appropriate staff Discord channel via webhook.
    Pass attachment_bytes + attachment_filename to upload a file alongside the message.
    """
    _refresh_webhook_config()
    url = CONFIG.get(webhook_key) or CONFIG.get("log_webhook_url")
    if not url:
        log.warning("send_log: no webhook URL for key=%s - check webhooks.env or staff bot /setup", webhook_key)
        return

    now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    # Build Components V2 body
    comps: list = []

    # Header row: title + optional thumbnail as section accessory
    if thumbnail_url:
        comps.append({
            "type": 9,
            "components": [{"type": 10, "content": f"### {title}"}],
            "accessory": {"type": 11, "media": {"url": thumbnail_url}},
        })
    else:
        comps.append({"type": 10, "content": f"### {title}"})

    comps.append({"type": 14, "divider": True, "spacing": 1})

    # Description
    if description:
        comps.append({"type": 10, "content": description})

    # Fields - group inline fields on same line, block fields on own line
    if fields:
        comps.append({"type": 14, "divider": False, "spacing": 1})
        inline_buf: list = []
        for f in fields:
            chunk = f"`{f['name']}` {f['value']}"
            if f.get("inline"):
                inline_buf.append(chunk)
                if len(inline_buf) >= 3:
                    comps.append({"type": 10, "content": " • ".join(inline_buf)})
                    inline_buf = []
            else:
                if inline_buf:
                    comps.append({"type": 10, "content": " • ".join(inline_buf)})
                    inline_buf = []
                comps.append({"type": 10, "content": f"**{f['name']}**\n{f['value']}"})
        if inline_buf:
            comps.append({"type": 10, "content": " • ".join(inline_buf)})

    # Footer + timestamp
    footer_parts = []
    if footer:
        footer_parts.append(footer)
    footer_parts.append(now_str)
    comps.append({"type": 14, "divider": False, "spacing": 1})
    comps.append({"type": 10, "content": f"-# {' • '.join(footer_parts)}"})

    payload = {
        "flags": 1 << 15,
        "components": [{"type": 17, "accent_color": color, "components": comps}],
    }

    try:
        async with aiohttp.ClientSession() as session:
            if attachment_bytes and attachment_filename:
                form = aiohttp.FormData()
                form.add_field("payload_json", json.dumps(payload), content_type="application/json")
                ext = attachment_filename.rsplit(".", 1)[-1].lower()
                mime = "text/html" if ext == "html" else "text/plain"
                form.add_field("files[0]", attachment_bytes, filename=attachment_filename, content_type=mime)
                async with session.post(url, data=form) as resp:
                    if resp.status not in (200, 204):
                        raw = await resp.text()
                        log.warning("send_log(+file) webhook %s returned %d: %s", webhook_key, resp.status, raw[:200])
            else:
                async with session.post(url, json=payload) as resp:
                    if resp.status not in (200, 204):
                        raw = await resp.text()
                        log.warning("send_log webhook %s returned %d: %s", webhook_key, resp.status, raw[:200])
    except Exception as exc:
        log.warning("send_log failed for key=%s: %s", webhook_key, exc)

# ─── HEALTH SERVER ─────────────────────────────────────────────────────────────

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        # /deliver_key : staff bot asks this bot to DM a license key to a member.
        # This bot lives in the customer guild, so it can reach customers the
        # staff bot cannot. Auth via the shared INTERNAL_API_KEY.
        if self.path != "/deliver_key":
            self.send_response(404)
            self.end_headers()
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._json({"ok": False, "error": "bad json"}, 400)
            return
        expected = CONFIG.get("internal_api_key", "")
        if expected and body.get("api_key") != expected:
            self._json({"ok": False, "error": "forbidden"}, 403)
            return
        did = str(body.get("discord_id") or "").strip()
        key = str(body.get("key") or "").strip()
        product = body.get("product") or "private"
        expires_label = body.get("expires_label") or "Lifetime"
        if not did or not key:
            self._json({"ok": False, "error": "missing discord_id or key"}, 400)
            return
        loop = getattr(bot, "loop", None)
        if loop is None or not loop.is_running():
            self._json({"ok": False, "error": "bot not ready"}, 503)
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(
                _dm_key(did, key, product, expires_label), loop
            )
            result = fut.result(timeout=20)
        except Exception as ex:
            result = {"ok": False, "error": f"dispatch failed: {ex}"}
        self._json(result, 200 if result.get("ok") else 502)

    def _json(self, data: dict, status: int = 200):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass

def start_health_server(port: int):
    server = HTTPServer(("", port), HealthHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    log.info(f"Health server on :{port}")

# ─── EMBED HELPERS ────────────────────────────────────────────────────────────
# channel.send() does not accept components= in this discord.py build.
# Regular channel/interaction sends use discord.Embed; Components v2 JSON
# is used only for log webhooks (sent via raw aiohttp in send_log).

BRAND_COLOR = 0x60A5FA  # Customer brand blue (lighter)

async def _void_verify(invoice_id: str, discord_id: str) -> dict:
    """
    Call void_bot's /verify endpoint to validate an invoice ID.
    Returns the JSON response dict, or raises RuntimeError on failure.
    Response shape:
      {"valid": True,  "invoice_id": "...", "product": "..."}
      {"valid": False, "reason": "not_found" | "wrong_user"}
      {"error": "..."}
    """
    base_url = CONFIG.get("void_bot_url", "").rstrip("/")
    if not base_url:
        raise RuntimeError("VOID_BOT_URL not configured")
    api_key = CONFIG.get("internal_api_key", "")
    payload = {"api_key": api_key, "invoice_id": invoice_id, "discord_id": discord_id}
    async with aiohttp.ClientSession() as sess:
        async with sess.post(
            f"{base_url}/verify",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=8),
        ) as resp:
            return await resp.json()

def _make_embed(text: str, color: int = BRAND_COLOR) -> discord.Embed:
    """Convert markdown-formatted panel text into a discord.Embed.
    The first '## Heading' line becomes the embed title; the rest is description.
    If LOGO_URL is set, the logo appears as a thumbnail in the top-right corner."""
    lines = text.split('\n')
    title = ""
    desc_lines = []
    for line in lines:
        if line.startswith('## ') and not title:
            title = line[3:].strip()
        else:
            desc_lines.append(line)
    description = '\n'.join(desc_lines).strip()
    embed = discord.Embed(title=title, description=description, color=color)
    if CONFIG.get("logo_url"):
        embed.set_thumbnail(url=CONFIG["logo_url"])
    return embed

async def _send_v2(
    channel: discord.TextChannel,
    text: str,
    color: int = 0x2b2d31,
    view: discord.ui.View = None,
):
    """Send a panel embed to a channel."""
    kwargs: dict = {"embed": _make_embed(text, color)}
    if view:
        kwargs["view"] = view
    await channel.send(**kwargs)

async def _reply_v2(
    interaction: discord.Interaction,
    text: str,
    color: int = 0x2b2d31,
    ephemeral: bool = True,
):
    """Respond to an interaction with an embed."""
    await interaction.response.send_message(
        embed=_make_embed(text, color),
        ephemeral=ephemeral,
    )

# ─── COMPONENTS V2 PANEL HELPERS ──────────────────────────────────────────────
# Panel messages (verify, ticket, hwid, rules, info) are posted via Discord REST
# API directly with flags=IS_COMPONENTS_V2. Persistent discord.py views handle
# the button interactions (custom_ids match the payload buttons).

def _emoji_obj(name: str) -> dict | None:
    """Parse a custom emoji <:name:id> string into a Discord API emoji object."""
    raw = EMOJIS.get(name, "")
    if raw.startswith("<a:"):
        parts = raw.strip("<>").split(":")
        if len(parts) == 3:
            _, ename, eid = parts
            return {"id": eid, "name": ename, "animated": True}
    elif raw.startswith("<:"):
        parts = raw.strip("<>").split(":")
        if len(parts) == 3:
            _, ename, eid = parts
            return {"id": eid, "name": ename, "animated": False}
    return None


async def _post_channel_v2(channel: discord.TextChannel, payload: dict) -> None:
    """POST a Components v2 message to a channel via Discord REST API."""
    url = f"https://discord.com/api/v10/channels/{channel.id}/messages"
    headers = {
        "Authorization": f"Bot {CONFIG['token']}",
        "Content-Type": "application/json",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status not in (200, 201):
                body = await resp.text()
                log.error("_post_channel_v2 #%s failed %d: %s", channel.name, resp.status, body)
                raise RuntimeError(f"Discord API {resp.status}")


def _v2_banner() -> list:
    """Return a MediaGallery banner if LOGO_URL is configured, otherwise empty."""
    url = CONFIG.get("logo_url")
    if not url:
        return []
    return [{"type": 12, "items": [{"media": {"url": url}}]}]


def _v2_section(text: str, btn_label: str, btn_custom_id: str,
                btn_emoji_name: str = None, btn_style: int = 2) -> dict:
    """Section (type 9): TextDisplay left + Button accessory right, Pyrex style."""
    btn: dict = {
        "type": 2,
        "label": btn_label,
        "style": btn_style,
        "custom_id": btn_custom_id,
    }
    if btn_emoji_name:
        em = _emoji_obj(btn_emoji_name)
        if em:
            btn["emoji"] = em
    return {
        "type": 9,
        "components": [{"type": 10, "content": text}],
        "accessory": btn,
    }


def _v2_container(body: list, accent: int = 0x2b2d31) -> dict:
    """Wrap body in a Container with IS_COMPONENTS_V2 flag and accent color."""
    return {
        "flags": 1 << 15,
        "components": [{"type": 17, "accent_color": accent, "components": body}],
    }


def _emoji_in_text(key: str) -> str:
    """Return emoji string only if it's been configured (not a placeholder)."""
    val = EMOJIS.get(key, "")
    return val if val and "EMOJI_ID" not in val else ""


def _ticket_panel_payload() -> dict:
    em_ticket = _emoji_in_text("ticket")
    em_dot    = _emoji_in_text("dot")
    ticket_pfx = f"{em_ticket} " if em_ticket else "\U0001f3ab "
    bullet     = f"{em_dot} "    if em_dot    else "• "
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"# {ticket_pfx}Support\n"
        "Pick a category below and we'll open a **private channel** just for you and the team.\n\n"
        "-# Only you and our staff can see your ticket channel."
    )})
    body.append({"type": 14})
    for cat_id, cat in TICKET_CATEGORIES.items():
        body.append({"type": 14})
        em = _emoji_in_text(cat["emoji_key"])
        prefix = f"{em} " if em else ""
        body.append(_v2_section(
            f"{prefix}**{cat['label']}** - {cat['desc']}",
            cat["label"],
            f"ticket_open_{cat_id}",
            btn_emoji_name=cat["emoji_key"],
            btn_style=2,
        ))
        # Re-Setup sits right after Setup in the panel
        if cat_id == "setup":
            body.append({"type": 14})
            em_rs = _emoji_in_text("arrow")
            rs_prefix = f"{em_rs} " if em_rs else ""
            body.append(_v2_section(
                f"{rs_prefix}**Re-Setup** - Already set up? Open a re-setup request",
                "Re-Setup",
                "ticket_open_resetup",
                btn_emoji_name="arrow",
                btn_style=2,
            ))
    return _v2_container(body, accent=BRAND_COLOR)


def _verify_panel_payload() -> dict:
    em_lock   = _emoji_in_text("lock")
    em_ticket = _emoji_in_text("ticket")
    em_verify = _emoji_in_text("verify")
    em_dot    = _emoji_in_text("dot")
    lock_pfx   = f"{em_lock} "   if em_lock   else "\U0001f512 "
    ticket_pfx = f"{em_ticket} " if em_ticket else "\U0001f39f "
    verify_pfx = f"{em_verify} " if em_verify else ""
    bullet     = f"{em_dot} "    if em_dot    else "• "
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"# {lock_pfx}Verification\n"
        "Enter your **Invoice ID** below to verify your purchase and unlock your access.\n\n"
        "-# Your Invoice ID was provided by staff after your order was confirmed."
    )})
    body.append({"type": 14})
    body.append({"type": 10, "content": (
        f"{ticket_pfx}**HOW IT WORKS**\n"
        f"{bullet}After purchase, staff will give you an Invoice ID.\n"
        f"{bullet}Click Verify below and enter that ID to get your role.\n"
        f"{bullet}Lost access? Use the same Invoice ID to re-verify anytime."
    )})
    body.append({"type": 14})
    body.append(_v2_section(
        f"{verify_pfx}**HAVE AN INVOICE ID?**\n"
        f"{bullet}Click below and enter it when prompted.",
        "Verify",
        "verify_button",
        btn_emoji_name="verify",
        btn_style=2,
    ))
    return _v2_container(body, accent=BRAND_COLOR)


def _hwid_panel_payload() -> dict:
    em_gear = _emoji_in_text("gear")
    em_chip = _emoji_in_text("chip")
    em_warn = _emoji_in_text("warn")
    em_dot  = _emoji_in_text("dot")
    gear_pfx = f"{em_gear} " if em_gear else "⚙️ "
    chip_pfx = f"{em_chip} " if em_chip else ""
    warn_pfx = f"{em_warn} " if em_warn else "⚠️ "
    bullet   = f"{em_dot} "  if em_dot  else "• "
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"## {gear_pfx}HWID Reset\n"
        "Changed hardware or reinstalled Windows? Reset your hardware ID here."
    )})
    body.append({"type": 14})
    body.append({"type": 10, "content": (
        f"{warn_pfx}**BEFORE YOU RESET**\n"
        f"{bullet}You have a limited number of resets - use them wisely.\n"
        f"{bullet}HWID resets are logged and monitored by staff.\n"
        f"{bullet}Used all your resets? Open a support ticket instead."
    )})
    body.append({"type": 14})
    body.append(_v2_section(
        f"{chip_pfx}**RESET YOUR HARDWARE ID**\n"
        f"{bullet}Click the button to consume one of your available resets.",
        "Reset HWID",
        "hwid_reset_button",
        btn_emoji_name="chip",
    ))
    return _v2_container(body, accent=BRAND_COLOR)


def _rules_panel_payload() -> dict:
    em_rules  = _emoji_in_text("rules")
    em_dot    = _emoji_in_text("dot")
    em_cross  = _emoji_in_text("cross")
    em_warn   = _emoji_in_text("warn")
    em_shield = _emoji_in_text("shield")
    em_lock   = _emoji_in_text("lock")
    rules_pfx  = f"{em_rules} "  if em_rules  else "\U0001f4cb "
    bullet     = f"{em_dot} "    if em_dot    else "- "
    cross_pfx  = f"{em_cross} "  if em_cross  else "❌ "
    warn_pfx   = f"{em_warn} "   if em_warn   else "⚠️ "
    shield_pfx = f"{em_shield} " if em_shield else "\U0001f6e1️ "
    lock_pfx   = f"{em_lock} "   if em_lock   else "\U0001f512 "

    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"# {rules_pfx}Server Rules\n"
        "-# By using this server and our software you agree to all rules below. "
        "Violations may result in key termination or permanent blacklisting."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{shield_pfx}**RULES & TERMS**\n"
        "All rules from our main terms of service apply here. "
        "Using our software means you agree to everything listed.\n\n"
        f"{shield_pfx}**SHARING INFORMATION**\n"
        "Do not share our software, procedures, or any member information:\n"
        f"{bullet}Loader photos / videos\n"
        f"{bullet}Injection methods or instructions\n"
        f"{bullet}Backdooring users, or helping staff/devs detect features\n"
        f"{bullet}Recording setups, screenshotting or screensharing this server"
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{lock_pfx}**ACCOUNT & SERVER ACCESS**\n"
        "Lost account access may mean no re-invite. Keep your account secure. "
        "Token-logged spam accounts are banned instantly and may need a new key.\n\n"
        f"{lock_pfx}**PAUSING KEYS**\n"
        "To pause your key, open a ticket and speak to staff. "
        "Pauses last up to 2 weeks, then resume automatically. "
        "Respect staff - they are not 24/7. Disrespect may result in a timeout or ban. "
        "Serious issues: report to management."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{cross_pfx}**MULTI SOFTWARE POLICY**\n"
        "Using or affiliating with any other cheat / bypass while using our software is prohibited. "
        "Caught using or promoting another product - key terminated, no refund.\n"
        f"{bullet}Includes other Discord tags, vanities in your profile, etc.\n\n"
        f"{cross_pfx}**PC CHECKING**\n"
        "No PC checking of any kind:\n"
        f"{bullet}Self scanning - scanning friends - general server PC checks\n\n"
        f"{cross_pfx}**REPORTING**\n"
        "Knowing about a TOS / rule breach and not reporting it can get you punished too. "
        "Friends breaking rules, leaks, suspicious DMs/solicits, anything that harms the community.\n\n"
        f"{cross_pfx}**DISRESPECT TO OTHER PRODUCTS**\n"
        f"Insults or attacks toward other software providers are banned. "
        "**Immediate key termination. ZERO TOLERANCE.**"
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{shield_pfx}**RESETUPS**\n"
        "Resetups are free UNLESS you:\n"
        f"{bullet}Destruct without PC check proof\n"
        f"{bullet}Break or disable something yourself\n"
        f"{bullet}Factory reset without approval or valid proof\n\n"
        "**Factory resets require** a ticket, valid proof, and staff approval.\n\n"
        "**PC Check proof must include:**\n"
        f"{bullet}Screenshot/VOD of scan or ban\n"
        f"{bullet}Visible PC checker roles\n"
        f"{bullet}Date and time\n\n"
        "Violations incur a **$10 setup fee**. Repeated offences may result in blacklisting."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{warn_pfx}**DISCLOSURE**\n"
        "Failure to follow these rules or failure to report a rule break will result in:\n"
        f"{bullet}Permanent blacklisting from our services without refund\n"
        f"{bullet}Further punishment to the user/s who vouched or invited you"
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": "-# Last updated by staff"})
    return _v2_container(body, accent=BRAND_COLOR)


def _setup_info_payload(ticket_ref: str, alerts_ref: str) -> dict:
    em_warn   = _emoji_in_text("warn")
    em_lock   = _emoji_in_text("lock")
    em_ticket = _emoji_in_text("ticket")
    em_arrow  = _emoji_in_text("arrow")
    em_dot    = _emoji_in_text("dot")

    gear_pfx   = f"{em_warn} "   if em_warn   else "⚠️ "
    bell_pfx   = f"{em_lock} "   if em_lock   else "\U0001f512 "
    ticket_pfx = f"{em_ticket} " if em_ticket else "\U0001f3ab "
    arrow_pfx  = f"{em_arrow} "  if em_arrow  else "➡️ "
    warn_pfx   = f"{em_warn} "   if em_warn   else "⚠️ "
    bullet     = f"{em_dot} "    if em_dot    else "• "

    body: list = []
    body.extend(_v2_banner())

    pings_role_id = CONFIG.get("setup_pings_role_id")
    role_ref = f"<@&{pings_role_id}>" if pings_role_id else "@Setup Pings"

    body.append({"type": 10, "content": (
        f"# {gear_pfx}Awaiting Setup?\n"
        "Complete every step below, then wait for the Setup Team."
    )})
    body.append({"type": 14})

    body.append(_v2_section(
        f"{bell_pfx}**GET SETUP PINGS ROLE**\n"
        f"{bullet}Click the button to get the {role_ref} role. Click again to remove it.",
        "Setup Pings",
        "setup_pings_toggle",
        btn_emoji_name="arrow",
    ))
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{ticket_pfx}**OPEN A SETUP TICKET**\n"
        f"{bullet}Open a setup ticket here: {ticket_ref}\n"
        "-# Your Invoice ID is in your DMs."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{arrow_pfx}**WAIT FOR SETUP TEAM**\n"
        f"{bullet}Check {alerts_ref} regularly.\n"
        f"{bullet}When a setup team member is available, ping them in your ticket **once** "
        "with your **AnyDesk code & invoice ID**."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{warn_pfx}**IMPORTANT**\n"
        f"{bullet}Do **NOT** ping staff unless they have announced they are available for setups."
    )})

    return _v2_container(body, accent=BRAND_COLOR)


# ─── TICKET CATEGORY LIFECYCLE ───────────────────────────────────────────────
# Categories are created on demand when the first ticket of that type is opened,
# and deleted automatically when the last ticket in them is closed.

async def _get_or_create_ticket_category(guild: discord.Guild, cat_id: str) -> discord.CategoryChannel | None:
    """
    Return the Discord category for the given ticket type.
    Creates it on the fly if it does not exist yet.
    Caches the ID in CONFIG so subsequent lookups are free.

    Uses a three-stage lookup:
      1. Cached category ID in CONFIG (free)
      2. guild.categories cache - case-insensitive name match
      3. guild.fetch_channels() REST call - catches categories the bot
         can't see in its local cache (missing VIEW_CHANNEL overwrite)
    """
    cat        = TICKET_CATEGORIES[cat_id]
    config_key = cat["config_key"]
    cat_name   = cat["cat_name"]  # Discord-safe name (no slashes)

    # 1. Fast path: cached and still valid
    cached_id = CONFIG.get(config_key)
    if cached_id:
        ch = guild.get_channel(cached_id)
        if ch:
            return ch
        log.warning("Cached category ID %d for %s is stale, re-resolving", cached_id, cat_name)

    # 2. Search the in-memory cache (case-insensitive match)
    cached_cats = [(c.name, c.id) for c in guild.categories]
    log.info("Category lookup for %s - cache has %d categories: %s", cat_name, len(cached_cats), cached_cats)
    existing = next(
        (c for c in guild.categories if c.name.lower() == cat_name.lower()),
        None,
    )
    if existing:
        CONFIG[config_key] = existing.id
        log.info("Reused cached category %s (%d) for ticket type %s", existing.name, existing.id, cat_id)
        return existing

    # 3. Cache miss - fetch fresh from Discord REST API.
    #    Needed when bot lacks VIEW_CHANNEL on the category and it's absent from cache.
    log.info("Category %s not in cache for %s - fetching from API", cat_name, cat_id)
    try:
        all_channels = await guild.fetch_channels()
        api_cats = [(c.name, c.id) for c in all_channels if isinstance(c, discord.CategoryChannel)]
        log.info("API fetch returned %d categories: %s", len(api_cats), api_cats)
        existing = next(
            (c for c in all_channels
             if isinstance(c, discord.CategoryChannel) and c.name.lower() == cat_name.lower()),
            None,
        )
        if existing:
            CONFIG[config_key] = existing.id
            log.info("Reused API-fetched category %s (%d) for ticket type %s", existing.name, existing.id, cat_id)
            return existing
    except Exception as exc:
        log.warning("fetch_channels failed: %s", exc)

    # None found anywhere - create the category now
    log.info("Creating new Discord category %s for ticket type %s", cat_name, cat_id)
    admin_role = guild.get_role(CONFIG["admin_role_id"])
    mgmt_role  = guild.get_role(CONFIG["management_role_id"])
    overwrites: dict = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
    }
    # FAC resetting category: management only; all others: admin role
    if cat_id == "hwid_reset":
        if mgmt_role:
            overwrites[mgmt_role] = discord.PermissionOverwrite(
                view_channel=True, manage_channels=True,
                send_messages=True, read_message_history=True,
            )
    else:
        if admin_role:
            overwrites[admin_role] = discord.PermissionOverwrite(
                view_channel=True, manage_channels=True,
                send_messages=True, read_message_history=True,
            )

    # Place new ticket category at the bottom of the server
    position = max((c.position for c in guild.categories), default=0) + 1

    try:
        new_cat = await guild.create_category(
            name=cat_name,
            overwrites=overwrites,
            position=position,
            reason=f"Ticket category for {cat['label']}",
        )
        CONFIG[config_key] = new_cat.id
        log.info("Created Discord category %s (%d) for ticket type %s", cat_name, new_cat.id, cat_id)
        return new_cat
    except discord.Forbidden:
        log.error("Missing Manage Channels - cannot create category %s", cat_name)
        return None
    except discord.HTTPException as exc:
        log.error("Failed to create category %s: %s", cat_name, exc)
        return None


def _cat_id_for_channel(channel: discord.TextChannel) -> str | None:
    """Find which TICKET_CATEGORIES key a ticket channel belongs to, via topic or name prefix."""
    if channel.topic and " | " in channel.topic:
        label = channel.topic.split(" | ")[0].strip()
        for cid, cat in TICKET_CATEGORIES.items():
            if cat["label"] == label:
                return cid
    # Fallback: match the channel name prefix
    for cid, cat in TICKET_CATEGORIES.items():
        if channel.name.startswith(cat["channel_prefix"] + "-"):
            return cid
    return None


async def _cleanup_empty_category(guild: discord.Guild, cat_id: str) -> None:
    """Delete the ticket category for cat_id if it has no channels left."""
    config_key = TICKET_CATEGORIES[cat_id]["config_key"]
    cat_ch = guild.get_channel(CONFIG.get(config_key) or 0)
    if not cat_ch:
        return
    remaining = [ch for ch in cat_ch.channels if isinstance(ch, discord.TextChannel)]
    if not remaining:
        try:
            await cat_ch.delete(reason="All tickets closed - removing empty category")
            CONFIG[config_key] = 0
            log.info("Deleted empty ticket category %s", cat_ch.name)
        except discord.HTTPException as exc:
            log.warning("Could not delete empty category %s: %s", cat_ch.name, exc)


# ─── EMOJI AUTO-SETUP ─────────────────────────────────────────────────────────

EMOJI_SVG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "emojis")

# Maps emoji key -> SVG filename stem (all match by convention except warn)
_EMOJI_FILE_MAP = {
    # original (PNG overrides SVG where available)
    "verify":      "verify",
    "key":         "key",
    "chip":        "chip",
    "ticket":      "support",
    "rules":       "rules",
    "cross":       "no",
    "shield":      "shield",
    "arrow":       "arrow",
    "warn":        "triangle",
    "dot":         "dot",
    "bell":        "bell",
    "lock":        "lock",
    "gear":        "gear",
    # blue icon pack
    "ac":          "ac",
    "vpn":         "vpn",
    "angry":       "angry",
    "yes":         "yes",
    "pin":         "pin",
    "ban":         "ban",
    "heath":       "heath",
    "no":          "no",
    "camera":      "camera",
    "wave":        "wave",
    "handshake":   "handshake",
    "clash":       "clash",
    "crown":       "crown",
    "clock":       "clock",
    "bug":         "bug",
    "calendar":    "calendar",
    "support":     "support",
    "triangle":    "triangle",
    "eye":         "eye",
    "description": "description",
}

async def _fetch_app_emojis_cb(app_id: int, token: str) -> dict:
    """Return {name: emoji_obj} for all application emojis (customer bot)."""
    url     = f"https://discord.com/api/v10/applications/{app_id}/emojis"
    headers = {"Authorization": f"Bot {token}"}
    async with aiohttp.ClientSession() as sess:
        async with sess.get(url, headers=headers) as resp:
            if resp.status != 200:
                log.warning("[emojis] fetch returned %s", resp.status)
                return {}
            data  = await resp.json()
            items = data.get("items", data) if isinstance(data, dict) else data
            return {em["name"]: em for em in items}

async def _create_app_emoji_cb(app_id: int, token: str, name: str, png_bytes: bytes) -> Optional[dict]:
    """Upload one application emoji; returns emoji object or None."""
    import base64
    image_data = "data:image/png;base64," + base64.b64encode(png_bytes).decode()
    url     = f"https://discord.com/api/v10/applications/{app_id}/emojis"
    headers = {"Authorization": f"Bot {token}", "Content-Type": "application/json"}
    async with aiohttp.ClientSession() as sess:
        async with sess.post(url, headers=headers, json={"name": name, "image": image_data}) as resp:
            if resp.status in (200, 201):
                return await resp.json()
            body = await resp.text()
            log.warning("[emojis] create %s -> %s %s", name, resp.status, body[:200])
            return None

async def _setup_emojis(guild: discord.Guild) -> None:
    """
    Sync application emojis (bot-owned, no guild slot limit) on startup.
    1. Load from DB cache.
    2. Diff against Discord API list.
    3. Create missing ones from PNG (preferred) or SVG fallback.
    """
    app_id = bot.application_id
    token  = CONFIG["token"]

    if not app_id:
        log.warning("[emojis] application_id not available yet - skipping")
        return

    emoji_dir = EMOJI_SVG_DIR

    # 1. Load cached DB entries
    with get_db() as conn:
        try:
            rows = conn.execute("SELECT name, emoji_str FROM app_emojis").fetchall()
            for row in rows:
                for key, filename in _EMOJI_FILE_MAP.items():
                    if filename == row["name"] and "EMOJI_ID" in EMOJIS.get(key, "EMOJI_ID"):
                        EMOJIS[key] = row["emoji_str"]
        except Exception:
            pass  # table may not exist on first boot

    # 2. Find still-missing keys
    still_missing = {
        key: fn for key, fn in _EMOJI_FILE_MAP.items()
        if "EMOJI_ID" in EMOJIS.get(key, "EMOJI_ID")
    }
    if not still_missing:
        log.info("[emojis] all loaded from DB cache")
        return

    # 3. Fetch existing application emojis from Discord
    try:
        existing = await _fetch_app_emojis_cb(app_id, token)
    except Exception as exc:
        log.warning("[emojis] could not fetch: %s", exc)
        existing = {}

    with get_db() as conn:
        for key, filename in list(still_missing.items()):
            if filename in existing:
                em  = existing[filename]
                fmt = f"<:{em['name']}:{em['id']}>"
                EMOJIS[key] = fmt
                try:
                    conn.execute(
                        "INSERT OR REPLACE INTO app_emojis(name, emoji_id, emoji_str, animated, synced_at)"
                        " VALUES(?,?,?,?,?)",
                        (filename, str(em["id"]), fmt, int(em.get("animated", False)), "")
                    )
                except Exception:
                    pass
                del still_missing[key]
        conn.commit()

    if not still_missing:
        log.info("[emojis] all synced from API")
        return

    # 4. Create missing - try PNG first, then SVG
    if not os.path.isdir(emoji_dir):
        log.warning("[emojis] emojis/ directory not found - skipping creation")
        return

    with get_db() as conn:
        for key, filename in still_missing.items():
            png_bytes: Optional[bytes] = None

            png_path = os.path.join(emoji_dir, f"{filename}.png")
            if os.path.isfile(png_path):
                with open(png_path, "rb") as fh:
                    png_bytes = fh.read()

            if not png_bytes:
                svg_path = os.path.join(emoji_dir, f"{filename}.svg")
                if os.path.isfile(svg_path):
                    try:
                        import cairosvg
                        png_bytes = cairosvg.svg2png(url=svg_path, output_width=128, output_height=128)
                    except ImportError:
                        log.warning("[emojis] cairosvg not installed, cannot convert SVG for %s", key)
                        continue
                    except Exception as exc:
                        log.warning("[emojis] SVG conversion failed for %s: %s", key, exc)
                        continue
                else:
                    log.warning("[emojis] no PNG or SVG for key=%s file=%s", key, filename)
                    continue

            try:
                em = await _create_app_emoji_cb(app_id, token, filename, png_bytes)
                if em:
                    fmt = f"<:{em['name']}:{em['id']}>"
                    EMOJIS[key] = fmt
                    log.info("[emojis] created :%s: (id=%s)", em["name"], em["id"])
                    try:
                        conn.execute(
                            "INSERT OR REPLACE INTO app_emojis(name, emoji_id, emoji_str, animated, synced_at)"
                            " VALUES(?,?,?,?,?)",
                            (filename, str(em["id"]), fmt, int(em.get("animated", False)), "")
                        )
                    except Exception:
                        pass
            except Exception as exc:
                log.warning("[emojis] creation failed for %s: %s", key, exc)
        conn.commit()


# ─── TICKET SYSTEM ────────────────────────────────────────────────────────────

TICKET_CATEGORIES = {
    "purchase":   {"label": "Purchase / Renewal", "cat_name": "Purchase-Renewal", "channel_prefix": "purchase",    "emoji_key": "crown",   "desc": "Purchase or renew a product",          "config_key": "ticket_cat_purchase"},
    "setup":      {"label": "Setup",              "cat_name": "Setup",            "channel_prefix": "setup",       "emoji_key": "description", "desc": "First time setup assistance",      "config_key": "ticket_cat_setup"},
    "hwid_reset": {"label": "FAC Resetting",      "cat_name": "FAC-Resetting",    "channel_prefix": "fac-reset",   "emoji_key": "key",     "desc": "Open a ticket to get authorised to FAC", "config_key": "ticket_cat_hwid_reset"},
    "support":    {"label": "Support",            "cat_name": "Support",          "channel_prefix": "support",     "emoji_key": "support", "desc": "Product support or general enquiries", "config_key": "ticket_cat_support"},
    "management": {"label": "Management",         "cat_name": "Management",       "channel_prefix": "management",  "emoji_key": "shield",  "desc": "Account or management requests",       "config_key": "ticket_cat_management"},
}

# ─── TICKET COUNTER ───────────────────────────────────────────────────────────

def _ensure_tables():
    """Ensure all required tables exist (safe to call multiple times)."""
    with get_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ticket_counter "
            "(id INTEGER PRIMARY KEY, next_num INTEGER NOT NULL DEFAULT 1)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO ticket_counter (id, next_num) VALUES (1, 1)"
        )
        # Unified tickets table (void_bot owns schema; this is a safety net for first-deploy)
        conn.execute("""CREATE TABLE IF NOT EXISTS app_emojis (
            name        TEXT PRIMARY KEY,
            emoji_id    TEXT NOT NULL,
            emoji_str   TEXT NOT NULL,
            animated    INTEGER NOT NULL DEFAULT 0,
            synced_at   TEXT NOT NULL DEFAULT ''
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS tickets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_num      TEXT NOT NULL DEFAULT '0000',
            channel_id      TEXT UNIQUE NOT NULL,
            guild_id        TEXT NOT NULL DEFAULT '',
            bot_source      TEXT NOT NULL DEFAULT 'customer',
            discord_id      TEXT NOT NULL,
            type            TEXT,
            category        TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'open',
            claimed_by      TEXT,
            opened_at       TEXT NOT NULL,
            closed_at       TEXT,
            closed_by       TEXT,
            assigned_to     TEXT,
            payment_status  TEXT NOT NULL DEFAULT 'none',
            invoice_id      TEXT,
            paid_at         TEXT,
            product         TEXT,
            expires_at      TEXT,
            resolution      TEXT,
            transcript      TEXT,
            notes           TEXT
        )""")
        # Migration: add columns that may be missing on existing DBs
        for _col_sql in [
            "ALTER TABLE tickets ADD COLUMN product           TEXT",
            "ALTER TABLE tickets ADD COLUMN expires_at        TEXT",
            "ALTER TABLE tickets ADD COLUMN fac_authorised    INTEGER DEFAULT 0",
            "ALTER TABLE tickets ADD COLUMN fac_authorised_at TEXT",
        ]:
            try:
                conn.execute(_col_sql)
            except Exception:
                pass  # column already exists
        # payments table is owned by staff_bot; create here as safety net for shared DB
        conn.execute("""CREATE TABLE IF NOT EXISTS payments (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id   TEXT UNIQUE NOT NULL,
            discord_id   TEXT NOT NULL,
            key          TEXT NOT NULL,
            product      TEXT NOT NULL,
            amount       TEXT,
            method       TEXT,
            expires_at   TEXT,
            paid_at      TEXT NOT NULL,
            confirmed_by TEXT NOT NULL,
            notes        TEXT
        )""")
        # key_deliveries: staff_bot queues keys here, this bot DMs them to members
        conn.execute("""CREATE TABLE IF NOT EXISTS key_deliveries (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id    TEXT NOT NULL,
            key           TEXT NOT NULL,
            product       TEXT,
            expires_label TEXT,
            invoice_id    TEXT,
            status        TEXT NOT NULL DEFAULT 'pending',
            attempts      INTEGER NOT NULL DEFAULT 0,
            last_error    TEXT,
            created_by    TEXT,
            created_at    TEXT NOT NULL DEFAULT '',
            delivered_at  TEXT
        )""")
        conn.commit()

def _init_ticket_counter():
    """Ensure the ticket_counter table exists."""
    _ensure_tables()

def get_next_ticket_number() -> int:
    """Atomically increment and return the next ticket number."""
    _init_ticket_counter()
    with get_db() as conn:
        row = conn.execute("SELECT next_num FROM ticket_counter WHERE id = 1").fetchone()
        num = row["next_num"] if row else 1
        conn.execute("UPDATE ticket_counter SET next_num = next_num + 1 WHERE id = 1")
        conn.commit()
        return num

# ─── HTML TRANSCRIPT BUILDER ──────────────────────────────────────────────────

def _html_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )

def _fmt_discord_md(text: str) -> str:
    """Very lightweight Discord markdown -> HTML converter."""
    import html as html_mod
    s = html_mod.escape(text)
    # Code blocks (must come before inline code)
    s = re.sub(r'```(?:\w+\n)?(.*?)```', lambda m: f'<pre><code>{m.group(1).strip()}</code></pre>', s, flags=re.DOTALL)
    s = re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
    # Bold / italic / underline / strikethrough
    s = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', s)
    s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)
    s = re.sub(r'\*(.+?)\*', r'<em>\1</em>', s)
    s = re.sub(r'__(.+?)__', r'<u>\1</u>', s)
    s = re.sub(r'~~(.+?)~~', r'<s>\1</s>', s)
    # Spoilers
    s = re.sub(r'\|\|(.+?)\|\|', r'<span class="spoiler">\1</span>', s)
    # Newlines
    s = s.replace('\n', '<br>')
    return s

def _build_html_transcript(
    messages: list,
    channel_name: str,
    opener_name: str,
    closed_by_name: str,
    cat_label: str,
    ticket_num_str: str,
    duration_str: str,
    opened_at: str,
) -> str:
    """Generate a Discord-dark-theme HTML transcript like TicketTool produces."""

    # Group consecutive messages from the same author within 7 minutes
    groups = []
    for msg in messages:
        if (
            groups
            and groups[-1][0].author.id == msg.author.id
            and not msg.author.bot
            and (msg.created_at - groups[-1][-1].created_at).total_seconds() < 420
        ):
            groups[-1].append(msg)
        else:
            groups.append([msg])

    # Render messages
    rows_html = []
    last_date = None
    for group in groups:
        first = group[0]
        date_label = first.created_at.strftime("%B %d, %Y")
        if date_label != last_date:
            rows_html.append(f'<div class="date-divider">{_html_escape(date_label)}</div>')
            last_date = date_label

        is_bot = first.author.bot
        avatar_url = str(first.author.display_avatar.url) if first.author.display_avatar else ""
        display_name = _html_escape(first.author.display_name)
        username_class = "username bot" if is_bot else "username"
        bot_badge = '<span class="bot-badge">APP</span>' if is_bot else ""
        ts_full = first.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        ts_short = first.created_at.strftime("%H:%M")

        # Build all messages in the group
        msgs_in_group = []
        for i, msg in enumerate(group):
            msg_ts = msg.created_at.strftime("%H:%M")
            msg_parts = []

            # Content
            if msg.content:
                msg_parts.append(f'<div class="message-text">{_fmt_discord_md(msg.content)}</div>')

            # Embeds
            for emb in msg.embeds:
                emb_html = '<div class="embed">'
                if emb.title:
                    emb_html += f'<div class="embed-title">{_html_escape(emb.title)}</div>'
                if emb.description:
                    emb_html += f'<div class="embed-description">{_fmt_discord_md(emb.description)}</div>'
                if emb.fields:
                    emb_html += '<div class="embed-fields">'
                    for field in emb.fields:
                        emb_html += (
                            f'<div class="embed-field">'
                            f'<div class="embed-field-name">{_html_escape(field.name)}</div>'
                            f'<div class="embed-field-value">{_fmt_discord_md(field.value)}</div>'
                            f'</div>'
                        )
                    emb_html += '</div>'
                emb_html += '</div>'
                msg_parts.append(emb_html)

            # Attachments
            for att in msg.attachments:
                att_name = _html_escape(att.filename)
                att_url = att.url
                if att.content_type and att.content_type.startswith("image/"):
                    msg_parts.append(
                        f'<div class="attachment-img"><a href="{att_url}" target="_blank">'
                        f'<img src="{att_url}" alt="{att_name}" class="img-attachment"></a></div>'
                    )
                else:
                    msg_parts.append(
                        f'<a class="attachment" href="{att_url}" target="_blank">'
                        f'<span>&#128206;</span> {att_name}</a>'
                    )

            if not msg_parts:
                msg_parts.append('<div class="message-text" style="color:#6b7280">[No content]</div>')

            msg_body = "".join(msg_parts)
            if i == 0:
                msgs_in_group.append(
                    f'<div class="message-group first-in-sequence">'
                    f'  <div class="avatar-col"><img class="avatar" src="{avatar_url}" alt="{display_name}" onerror="this.style.display=\'none\'"></div>'
                    f'  <div class="message-content">'
                    f'    <div class="message-header">'
                    f'      <span class="{username_class}">{display_name}</span>'
                    f'      {bot_badge}'
                    f'      <span class="timestamp" title="{ts_full}">{ts_short}</span>'
                    f'    </div>'
                    f'    {msg_body}'
                    f'  </div>'
                    f'</div>'
                )
            else:
                msg_full_ts = msg.created_at.strftime("%H:%M:%S UTC")
                msgs_in_group.append(
                    f'<div class="message-group">'
                    f'  <div class="avatar-col"><span class="ts-side" title="{msg_full_ts}">{msg_ts}</span></div>'
                    f'  <div class="message-content">{msg_body}</div>'
                    f'</div>'
                )

        rows_html.append("".join(msgs_in_group))

    messages_html = "\n".join(rows_html)
    total_count = len(messages)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Transcript - #{_html_escape(channel_name)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#313338;color:#dbdee1;font-family:"gg sans","Noto Sans",Whitney,"Helvetica Neue",Helvetica,Roboto,Arial,sans-serif;font-size:16px;line-height:1.375}}
.header{{background:#1e1f22;border-bottom:1px solid #232428;padding:20px 24px;display:flex;align-items:center;gap:16px}}
.header-icon{{width:52px;height:52px;border-radius:50%;background:#5865f2;display:flex;align-items:center;justify-content:center;font-size:26px;flex-shrink:0}}
.header-info h1{{font-size:20px;font-weight:700;color:#fff}}
.header-info p{{font-size:14px;color:#949ba4;margin-top:3px}}
.stats-bar{{background:#2b2d31;border-bottom:1px solid #232428;padding:14px 24px;display:flex;gap:32px;flex-wrap:wrap}}
.stat{{display:flex;flex-direction:column}}
.stat-label{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:#949ba4}}
.stat-value{{font-size:14px;color:#dbdee1;margin-top:3px}}
.messages{{padding:16px 24px 32px}}
.date-divider{{display:flex;align-items:center;gap:8px;padding:20px 0 8px;color:#949ba4;font-size:12px;font-weight:500}}
.date-divider::before,.date-divider::after{{content:"";flex:1;height:1px;background:#3f4147}}
.message-group{{display:flex;padding:2px 8px;border-radius:4px;min-height:22px}}
.message-group:hover{{background:rgba(4,4,5,.07)}}
.message-group.first-in-sequence{{margin-top:17px;padding-top:4px}}
.avatar-col{{width:40px;flex-shrink:0;margin-right:12px;padding-top:2px}}
.avatar{{width:40px;height:40px;border-radius:50%;object-fit:cover;cursor:pointer}}
.ts-side{{font-size:11px;color:transparent;line-height:22px;display:block;text-align:right;white-space:nowrap;user-select:none}}
.message-group:hover .ts-side{{color:#949ba4}}
.message-content{{flex:1;min-width:0}}
.message-header{{display:flex;align-items:baseline;gap:8px;margin-bottom:2px}}
.username{{font-size:16px;font-weight:500;color:#fff;cursor:pointer}}
.username:hover{{text-decoration:underline}}
.username.bot{{color:#949ba4}}
.bot-badge{{background:#5865f2;color:#fff;font-size:10px;font-weight:700;padding:1px 5px;border-radius:3px;text-transform:uppercase;letter-spacing:.04em;vertical-align:middle}}
.timestamp{{font-size:11px;color:#949ba4;white-space:nowrap}}
.message-text{{font-size:15px;color:#dbdee1;word-break:break-word;white-space:pre-wrap}}
.message-text code{{background:#1e1f22;border-radius:3px;padding:0 4px;font-family:Consolas,"Andale Mono WT",monospace;font-size:85%;color:#e06c75}}
.message-text pre{{background:#1e1f22;border-radius:4px;padding:8px 12px;margin-top:4px;overflow-x:auto;border:1px solid #111214}}
.message-text pre code{{color:#abb2bf;background:none;padding:0;font-size:13px}}
.spoiler{{background:#202225;color:#202225;border-radius:2px;cursor:pointer}}
.spoiler:hover{{background:transparent;color:#dbdee1}}
.embed{{max-width:520px;border-radius:4px;border-left:4px solid #5865f2;background:#2b2d31;padding:8px 12px 10px;margin-top:4px}}
.embed-title{{font-weight:600;font-size:15px;color:#fff;margin-bottom:4px}}
.embed-description{{font-size:14px;color:#dbdee1;white-space:pre-wrap}}
.embed-fields{{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}}
.embed-field{{min-width:120px}}
.embed-field-name{{font-size:12px;font-weight:700;color:#dbdee1;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px}}
.embed-field-value{{font-size:13px;color:#dbdee1}}
.attachment{{display:inline-flex;align-items:center;gap:8px;background:#2b2d31;border:1px solid #1e1f22;border-radius:4px;padding:8px 12px;margin-top:4px;font-size:14px;color:#00aff4;text-decoration:none;max-width:400px}}
.attachment:hover{{text-decoration:underline}}
.img-attachment img.img-attachment{{max-width:400px;max-height:300px;border-radius:4px;margin-top:4px;display:block}}
.footer{{background:#1e1f22;border-top:1px solid #232428;padding:16px 24px;text-align:center;font-size:13px;color:#949ba4}}
.footer strong{{color:#dbdee1}}
</style>
</head>
<body>
<div class="header">
  <div class="header-icon">&#127903;</div>
  <div class="header-info">
    <h1>#{_html_escape(channel_name)}</h1>
    <p>{_html_escape(cat_label)} Ticket &bull; Ticket #{_html_escape(ticket_num_str)}</p>
  </div>
</div>
<div class="stats-bar">
  <div class="stat"><span class="stat-label">Ticket</span><span class="stat-value">#{_html_escape(ticket_num_str)}</span></div>
  <div class="stat"><span class="stat-label">Category</span><span class="stat-value">{_html_escape(cat_label)}</span></div>
  <div class="stat"><span class="stat-label">Opened by</span><span class="stat-value">{_html_escape(opener_name)}</span></div>
  <div class="stat"><span class="stat-label">Closed by</span><span class="stat-value">{_html_escape(closed_by_name)}</span></div>
  <div class="stat"><span class="stat-label">Duration</span><span class="stat-value">{_html_escape(duration_str)}</span></div>
  <div class="stat"><span class="stat-label">Opened</span><span class="stat-value">{_html_escape(opened_at)}</span></div>
  <div class="stat"><span class="stat-label">Messages</span><span class="stat-value">{total_count}</span></div>
</div>
<div class="messages">
{messages_html}
</div>
<div class="footer">
  Transcript generated <strong>{generated_at}</strong> &bull; {total_count} messages &bull; <strong>#{_html_escape(channel_name)}</strong>
</div>
</body>
</html>"""


class CloseConfirmModal(discord.ui.Modal, title="Close Ticket"):
    reason = discord.ui.TextInput(
        label="Reason for closing",
        placeholder="e.g. Issue resolved, No response, etc.",
        required=False,
        max_length=200,
        style=discord.TextStyle.short,
    )

    async def on_submit(self, interaction: discord.Interaction):
        close_reason = self.reason.value.strip() or "No reason provided"
        await close_ticket(interaction, reason=close_reason)


class AddUserModal(discord.ui.Modal, title="Add User to Ticket"):
    user_id_input = discord.ui.TextInput(
        label="User ID",
        placeholder="Right-click a user > Copy ID and paste it here",
        min_length=15,
        max_length=20,
        style=discord.TextStyle.short,
    )

    async def on_submit(self, interaction: discord.Interaction):
        channel = interaction.channel
        raw = self.user_id_input.value.strip().lstrip("<@!>").rstrip(">")
        try:
            uid = int(raw)
        except ValueError:
            await interaction.response.send_message(
                embed=_make_embed(f"Invalid user ID: `{raw}`\nRight-click the user, then Copy ID.", 0xED4245),
                ephemeral=True,
            )
            return

        member = interaction.guild.get_member(uid)
        if not member:
            try:
                member = await interaction.guild.fetch_member(uid)
            except discord.NotFound:
                await interaction.response.send_message(
                    embed=_make_embed(f"No member found with ID `{uid}`.", 0xED4245),
                    ephemeral=True,
                )
                return

        await channel.set_permissions(
            member,
            view_channel=True,
            send_messages=True,
            read_message_history=True,
        )
        await interaction.response.send_message(
            embed=_make_embed(
                f"**{member.mention}** (`{member.name}`) has been added to this ticket.",
                0x57F287,
            ),
            ephemeral=False,
        )
        log.info("Added %s (%d) to ticket %s by %s", member, uid, channel.name, interaction.user)


class TicketPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        for cat_id, cat in TICKET_CATEGORIES.items():
            btn = discord.ui.Button(
                label=cat["label"],
                emoji=None,  # buttons handled by persistent view, emoji shown in Components v2 panel
                style=discord.ButtonStyle.secondary,
                custom_id=f"ticket_open_{cat_id}",
            )
            btn.callback = self._make_callback(cat_id)
            self.add_item(btn)

        # Re-Setup button: for existing customers needing setup help again
        resetup_btn = discord.ui.Button(
            label="Re-Setup",
            style=discord.ButtonStyle.secondary,
            custom_id="ticket_open_resetup",
        )
        resetup_btn.callback = self._resetup_callback
        self.add_item(resetup_btn)

    def _make_callback(self, cat_id: str):
        async def callback(interaction: discord.Interaction):
            if cat_id == "setup":
                # Show invoice modal first - validates purchase and pulls build info
                await interaction.response.send_modal(SetupInvoiceModal())
            else:
                await open_ticket(interaction, cat_id)
        return callback

    async def _resetup_callback(self, interaction: discord.Interaction):
        """Re-Setup ticket - validates invoice like setup, creates a setup ticket."""
        await interaction.response.send_modal(SetupInvoiceModal())


class TicketControlView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Close Ticket", style=discord.ButtonStyle.danger, custom_id="ticket_close")
    async def close_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(CloseConfirmModal())

    @discord.ui.button(label="Claim", style=discord.ButtonStyle.secondary, custom_id="ticket_claim")
    async def claim_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        admin_role = interaction.guild.get_role(CONFIG["admin_role_id"])
        if not (admin_role and admin_role in interaction.user.roles):
            await interaction.response.send_message(
                embed=_make_embed("Only staff can claim tickets.", 0xED4245),
                ephemeral=True,
            )
            return

        channel = interaction.channel
        # Update topic to include claimed-by
        current_topic = channel.topic or ""
        # Remove any existing Claimed: segment first
        new_topic = re.sub(r'\s*\|\s*Claimed:[^\|]*', '', current_topic).strip()
        new_topic = f"{new_topic} | Claimed:{interaction.user.id}"
        try:
            await channel.edit(topic=new_topic[:1024])
        except Exception:
            pass

        await interaction.response.send_message(
            embed=_make_embed(
                f"**{interaction.user.mention}** has claimed this ticket.",
                0x5865F2,
            ),
            ephemeral=False,
        )
        log.info("Ticket %s claimed by %s (%d)", channel.name, interaction.user, interaction.user.id)

    @discord.ui.button(label="Add User", style=discord.ButtonStyle.primary, custom_id="ticket_add_user")
    async def add_user_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        admin_role = interaction.guild.get_role(CONFIG["admin_role_id"])
        if not (admin_role and admin_role in interaction.user.roles):
            await interaction.response.send_message(
                embed=_make_embed("Only staff can add users to tickets.", 0xED4245),
                ephemeral=True,
            )
            return
        await interaction.response.send_modal(AddUserModal())


class FACAuthoriseView(discord.ui.View):
    """Management-only action panel posted inside FAC Resetting tickets."""
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Authorise FAC", style=discord.ButtonStyle.success, custom_id="fac_authorise")
    async def authorise_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        mgmt_role = interaction.guild.get_role(CONFIG["management_role_id"])
        if not (mgmt_role and mgmt_role in interaction.user.roles):
            await interaction.response.send_message(
                embed=_make_embed("Only management can authorise FAC.", 0xED4245),
                ephemeral=True,
            )
            return

        # Pull the ticket opener from the channel topic
        channel = interaction.channel
        opener_id = None
        if channel.topic:
            m = re.search(r'\((\d+)\)', channel.topic)
            if m:
                opener_id = int(m.group(1))

        opener = channel.guild.get_member(opener_id) if opener_id else None
        opener_mention = opener.mention if opener else f"<@{opener_id}>" if opener_id else "the user"

        # Fetch invoice_id for this ticket from DB
        ticket_invoice_id = None
        with get_db() as _db:
            _row = _db.execute(
                "SELECT invoice_id FROM tickets WHERE channel_id = ?",
                (str(channel.id),),
            ).fetchone()
            if _row:
                ticket_invoice_id = _row["invoice_id"]

        # Store FAC authorisation in the ticket row
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db() as _db:
            _db.execute(
                "UPDATE tickets SET fac_authorised = 1, fac_authorised_at = ? WHERE channel_id = ?",
                (now_iso, str(channel.id)),
            )
            _db.commit()

        # Assign Re-Setup Needed role to the opener
        if opener:
            resetup_role = interaction.guild.get_role(CONFIG["resetup_needed_role_id"])
            if resetup_role:
                try:
                    await opener.add_roles(resetup_role, reason="FAC authorised via ticket")
                except Exception as _ex:
                    log.warning("Could not assign Re-Setup Needed role to %s: %s", opener_id, _ex)

        # Disable this button so it can only fire once
        button.disabled = True
        button.label = "FAC Authorised"
        await interaction.message.edit(view=self)

        inv_line = f"**Invoice** `{ticket_invoice_id}`\n" if ticket_invoice_id else ""
        await interaction.response.send_message(
            embed=_make_embed(
                f"{e('verify')} **FAC Authorised**\n\n"
                f"{opener_mention} has been authorised to use FAC.\n\n"
                f"{inv_line}"
                f"**Authorised by** {interaction.user.mention} (`{interaction.user.name}`)\n\n"
                "-# Close this ticket once you have communicated this to the user.",
                0x57F287,
            ),
        )

        await send_log(
            title="FAC Authorised",
            description=(
                f"{opener_mention}\n"
                f"`{opener.name if opener else opener_id}` - `{opener_id}`"
            ),
            color=0x57F287,
            webhook_key="wh_tickets_opened",
            fields=[
                {"name": "Authorised by", "value": f"{interaction.user.mention} (`{interaction.user.name}`)", "inline": True},
                {"name": "Invoice",       "value": f"`{ticket_invoice_id}`" if ticket_invoice_id else "N/A",  "inline": True},
                {"name": "Channel",       "value": f"[#{channel.name}]({channel.jump_url})",                  "inline": True},
            ],
            footer=f"Opener ID: {opener_id}",
        )
        log.info("FAC authorised for %s (invoice=%s) by %s in %s", opener_id, ticket_invoice_id, interaction.user, channel.name)


class SetupInvoiceModal(discord.ui.Modal, title="Enter Your Invoice ID"):
    """Shown when a user opens a setup ticket - validates invoice and pulls build info."""
    invoice_input = discord.ui.TextInput(
        label="Invoice ID",
        placeholder="e.g. INV-XXXX-XXXX-XXXX-XXXX",
        min_length=5,
        max_length=40,
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        invoice_id = self.invoice_input.value.strip().upper()
        member     = interaction.user

        # Call void_bot's /verify API - no discord_id check for setup (just validate invoice exists)
        try:
            result = await _void_verify(invoice_id, str(member.id))
        except Exception as ex:
            log.error("Setup invoice API failed user=%s invoice=%s: %s", member.id, invoice_id, ex)
            await interaction.followup.send(
                "Could not reach auth server. Contact staff.", ephemeral=True
            )
            return

        if result.get("error") or not result.get("valid"):
            reason = result.get("reason", "unknown")
            if reason == "wrong_user":
                await interaction.followup.send(
                    "That Invoice ID belongs to a different Discord account. Contact staff if this is wrong.",
                    ephemeral=True,
                )
            else:
                await interaction.followup.send(
                    "Invoice ID not found. Make sure your purchase has been confirmed by staff.",
                    ephemeral=True,
                )
            return

        product    = result.get("product")
        expires_at = None  # /verify endpoint doesn't return expires_at; shown as N/A

        await open_ticket(
            interaction, "setup",
            invoice_id=invoice_id,
            product=product,
            expires_at=expires_at,
        )


async def open_ticket(
    interaction: discord.Interaction,
    cat_id: str,
    *,
    invoice_id: Optional[str] = None,
    product:    Optional[str] = None,
    expires_at: Optional[str] = None,
):
    guild  = interaction.guild
    member = interaction.user
    cat_info = TICKET_CATEGORIES[cat_id]

    # Check if the user already has any open ticket (search by user ID in topic)
    user_id_tag = f"({member.id})"
    existing = next(
        (ch for ch in guild.text_channels if ch.topic and user_id_tag in ch.topic),
        None,
    )
    if existing:
        await _reply_v2(
            interaction,
            f"You already have an open ticket: [{existing.name}]({existing.jump_url})\n\n"
            "-# Close your existing ticket before opening a new one.",
            color=0xFEE75C,
        )
        return

    # Assign ticket number before creating the channel
    ticket_num = get_next_ticket_number()
    ticket_num_str = str(ticket_num).zfill(4)

    # Setup tickets: name includes username + build so staff can see at a glance
    if cat_id == "setup" and product:
        # Clean product to slug: lowercase, spaces -> hyphens, max 16 chars
        prod_slug = re.sub(r"[^a-z0-9-]", "", product.lower().replace(" ", "-"))[:16]
        # Clean username: lowercase, strip special chars, max 12 chars
        uname_slug = re.sub(r"[^a-z0-9]", "", member.name.lower())[:12]
        channel_name = f"setup-{uname_slug}-{prod_slug}" if prod_slug else f"setup-{uname_slug}-{ticket_num_str}"
    else:
        # Build a clean channel name: {prefix}-{ticket_num}
        channel_name = f"{cat_info['channel_prefix']}-{ticket_num_str}"

    admin_role = guild.get_role(CONFIG["admin_role_id"])
    mgmt_role  = guild.get_role(CONFIG["management_role_id"])

    # FAC resetting tickets: visible to management only, not regular staff
    is_fac = cat_id == "hwid_reset"

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True,
        ),
    }
    if is_fac:
        # Only management (and owner via Discord perms) can see FAC tickets
        if mgmt_role:
            overwrites[mgmt_role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True,
                read_message_history=True, manage_channels=True,
            )
    else:
        if admin_role:
            overwrites[admin_role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True,
                read_message_history=True, manage_channels=True,
            )

    # Get or create the per-type Discord category on demand
    ticket_category = await _get_or_create_ticket_category(guild, cat_id)
    log.info(
        "open_ticket: resolved category for %s = %s",
        cat_id,
        f"{ticket_category.name}({ticket_category.id})" if ticket_category else "None - channel will land at top level",
    )

    # Topic stores all parseable metadata: category | user (id) | #num
    topic = f"{cat_info['label']} | {member.name} ({member.id}) | #{ticket_num_str}"
    channel = await guild.create_text_channel(
        name=channel_name,
        category=ticket_category,
        overwrites=overwrites,
        topic=topic,
    )

    # Persist the ticket to DB so FAC authorisation can be linked later
    _opened_at_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as _db:
        _db.execute(
            """INSERT OR IGNORE INTO tickets
               (ticket_num, channel_id, guild_id, discord_id, type, category, status, opened_at, invoice_id, product, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)""",
            (
                ticket_num_str,
                str(channel.id),
                str(guild.id),
                str(member.id),
                cat_id,
                cat_info["label"],
                _opened_at_iso,
                invoice_id,
                product,
                expires_at,
            ),
        )
        _db.commit()

    # Check if this user has been FAC-authorised (shown in setup/re-setup tickets)
    fac_authorised = False
    if cat_id == "setup":
        with get_db() as _db:
            _fa = _db.execute(
                "SELECT 1 FROM tickets WHERE discord_id = ? AND fac_authorised = 1 LIMIT 1",
                (str(member.id),),
            ).fetchone()
            fac_authorised = bool(_fa)

    # --- Rich ticket open embed (Components V2) ---
    now_ts = int(discord.utils.utcnow().timestamp())
    if cat_id == "setup" and invoice_id:
        # Setup ticket: show build, invoice and user identity so staff see everything
        exp_str = ""
        if expires_at:
            try:
                from datetime import datetime as _dt
                exp_ts = int(_dt.fromisoformat(expires_at).timestamp())
                exp_str = f"\n**Expires** <t:{exp_ts}:D>"
            except Exception:
                exp_str = f"\n**Expires** {expires_at}"
        fac_line = "**FAC Authorised** Yes\n" if fac_authorised else ""
        text = (
            f"## {e('description')} Setup Ticket\n\n"
            f"Welcome, {member.mention} - a setup team member will be with you shortly.\n\n"
            f"**User** {member.mention} (`{member.name}`) - `{member.id}`\n"
            f"**Build** {product or 'Unknown'}{exp_str}\n"
            f"**Invoice** `{invoice_id}`\n"
            f"{fac_line}"
            f"**Ticket** #{ticket_num_str} - **Opened** <t:{now_ts}:R>\n\n"
            "Please wait for a setup team member. "
            "Do not ping staff - you will be pinged when someone is available.\n\n"
            "-# Use the buttons below to manage this ticket."
        )
    elif is_fac:
        text = (
            f"## {e('chip')} FAC Resetting Ticket\n\n"
            f"Welcome, {member.mention} (`{member.name}`) - a management member will be with you shortly.\n\n"
            f"**User** {member.mention} (`{member.name}`) - `{member.id}`\n"
            f"**Ticket** #{ticket_num_str} - **Opened** <t:{now_ts}:R>\n\n"
            "Please wait for a management team member to review your request.\n\n"
            "-# Use the buttons below to manage this ticket."
        )
    else:
        text = (
            f"## {e('ticket')} {cat_info['label']} Ticket\n\n"
            f"Welcome, {member.mention} (`{member.name}`) - a staff member will be with you shortly.\n\n"
            f"**User** `{member.name}` - `{member.id}`\n"
            f"**Category** {cat_info['desc']}\n"
            f"**Ticket** #{ticket_num_str} - **Opened** <t:{now_ts}:R>\n\n"
            "Please describe your issue in detail. "
            "Include any relevant screenshots, order IDs, or error messages.\n\n"
            "-# Use the buttons below to manage this ticket."
        )

    # FAC tickets ping management; all others ping admin
    if is_fac:
        mention_str = mgmt_role.mention if mgmt_role else ""
    else:
        mention_str = admin_role.mention if admin_role else ""

    # Build Components V2 ticket open message
    _ticket_payload = dict(_v2_container([
        {"type": 10, "content": text},
        {"type": 14},
        {
            "type": 1,
            "components": [
                {"type": 2, "label": "Close Ticket", "style": 4, "custom_id": "ticket_close"},
                {"type": 2, "label": "Claim",        "style": 2, "custom_id": "ticket_claim"},
                {"type": 2, "label": "Add User",     "style": 1, "custom_id": "ticket_add_user"},
            ],
        },
    ], accent=0x5865F2))
    # Components V2 forbids the legacy 'content' field. Put the ping in a
    # top-level TextDisplay above the container; allowed_mentions makes it notify.
    ping_line = f"{member.mention} {mention_str}".strip()
    if ping_line:
        _ticket_payload["components"].insert(0, {"type": 10, "content": ping_line})
    _ticket_payload["allowed_mentions"] = {"parse": ["users", "roles"]}
    await _post_channel_v2(channel, _ticket_payload)

    # FAC tickets get a second management-action message with the Authorise button
    if is_fac:
        await _post_channel_v2(channel, _v2_container([
            {"type": 10, "content": (
                f"## {e('shield')} Management Action\n\n"
                "Only management can authorise FAC. Click the button below once authorised."
            )},
            {"type": 14},
            {
                "type": 1,
                "components": [
                    {"type": 2, "label": "Authorise FAC", "style": 3, "custom_id": "fac_authorise"},
                ],
            },
        ], accent=0xFEE75C))

    await _reply_v2(
        interaction,
        f"**Ticket #{ticket_num_str} opened.**\nHead to your private channel: [{channel.name}]({channel.jump_url})",
        color=0x57F287,
    )

    account_age = (datetime.now(timezone.utc) - member.created_at).days
    await send_log(
        title="Ticket Opened",
        description=(
            f"{member.mention}\n"
            f"`{member.name}` - `{member.id}`"
        ),
        color=0x57F287,
        webhook_key="wh_tickets_opened",
        thumbnail_url=str(member.display_avatar.url),
        fields=[
            {"name": "Ticket",        "value": f"#{ticket_num_str}",                                "inline": True},
            {"name": "Category",      "value": cat_info["label"],                                   "inline": True},
            {"name": "Channel",       "value": f"[#{channel.name}]({channel.jump_url})",            "inline": True},
            {"name": "Account Age",   "value": f"{account_age:,} days",                             "inline": True},
            {"name": "Joined Server", "value": f"<t:{int(member.joined_at.timestamp())}:R>" if member.joined_at else "Unknown", "inline": True},
        ],
        footer=f"User ID: {member.id}",
    )


async def _dm_ticket_closed(
    channel: discord.TextChannel,
    closed_by: discord.Member,
    html_transcript: str,
    ticket_num_str: str,
    cat_label: str,
    duration_str: str,
    close_reason: str,
) -> None:
    """DM the ticket opener when their ticket is closed, with an HTML transcript."""
    if not channel.topic:
        return
    match = re.search(r'\((\d+)\)', channel.topic)
    if not match:
        return

    try:
        opener_id = int(match.group(1))
        opener = channel.guild.get_member(opener_id)
        if not opener:
            return

        summary = (
            f"## Ticket Closed - #{ticket_num_str}\n\n"
            f"**Category** {cat_label}\n"
            f"**Channel** #{channel.name}\n"
            f"**Closed by** {closed_by.name}\n"
            f"**Duration** {duration_str}\n"
            f"**Reason** {close_reason}\n\n"
            "Your full conversation transcript is attached as an HTML file. "
            "Open it in your browser to view it."
        )

        file = discord.File(
            io.BytesIO(html_transcript.encode("utf-8")),
            filename=f"transcript-{channel.name}.html",
        )
        await opener.send(embed=_make_embed(summary, 0x5865F2), file=file)
        log.info("DMed HTML transcript to %s (%d) for %s", opener, opener_id, channel.name)

    except discord.Forbidden:
        log.info("Cannot DM ticket opener %s - DMs are disabled", match.group(1))
    except Exception as exc:
        log.warning("Failed to DM ticket opener: %s", exc)


async def close_ticket(interaction: discord.Interaction, reason: str = "No reason provided"):
    channel = interaction.channel
    admin_role = interaction.guild.get_role(CONFIG["admin_role_id"])
    is_admin = admin_role and admin_role in interaction.user.roles

    # Check the channel looks like a ticket channel (has a topic with user ID)
    is_ticket_channel = channel.topic and re.search(r'\((\d+)\)', channel.topic)
    if not is_admin and not is_ticket_channel:
        await _reply_v2(interaction, "You cannot close this ticket.", color=0xED4245)
        return

    # Acknowledge immediately with a closing embed inside the channel
    close_embed = _make_embed(
        f"## Ticket Closing\n\n"
        f"**Closed by** {interaction.user.mention}\n"
        f"**Reason** {reason}\n\n"
        "-# Collecting transcript and deleting channel...",
        0xED4245,
    )
    await interaction.response.send_message(embed=close_embed)

    # --- Parse topic metadata ---
    # Topic format: "{cat_label} | {username} ({user_id}) | #{ticket_num} | Claimed:{staff_id}"
    cat_label      = "Unknown"
    opener_mention = "Unknown"
    opener_name    = "Unknown"
    opener_avatar  = None
    ticket_num_str = "????"

    if channel.topic and " | " in channel.topic:
        parts = channel.topic.split(" | ")
        cat_label = parts[0].strip()

    uid_match = re.search(r'\((\d+)\)', channel.topic or "")
    if uid_match:
        opener_id  = int(uid_match.group(1))
        opener_obj = channel.guild.get_member(opener_id)
        if opener_obj:
            opener_mention = f"{opener_obj.mention} `{opener_obj.name}` (`{opener_id}`)"
            opener_name    = opener_obj.name
            opener_avatar  = str(opener_obj.display_avatar.url)
        else:
            opener_mention = f"<@{opener_id}> (`{opener_id}`)"
            opener_name    = str(opener_id)

    num_match = re.search(r'#(\d{4,})', channel.topic or "")
    if num_match:
        ticket_num_str = num_match.group(1)

    # --- Collect ALL messages for the HTML transcript ---
    all_messages   = []
    user_msgs_txt  = []
    first_msg_ts   = None
    async for msg in channel.history(limit=1000, oldest_first=True):
        all_messages.append(msg)
        if first_msg_ts is None:
            first_msg_ts = msg.created_at
        if not msg.author.bot and msg.content:
            ts = msg.created_at.strftime("%Y-%m-%d %H:%M")
            user_msgs_txt.append(f"[{ts}] {msg.author.display_name}: {msg.content}")

    total_count = len(all_messages)
    user_count  = len(user_msgs_txt)

    # --- Duration ---
    duration_str = "Unknown"
    opened_at_str = "Unknown"
    if first_msg_ts:
        delta = datetime.now(timezone.utc) - first_msg_ts
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m = rem // 60
        duration_str  = f"{h}h {m}m" if h else f"{m}m"
        opened_at_str = first_msg_ts.strftime("%Y-%m-%d %H:%M UTC")

    # --- Build HTML transcript ---
    html_transcript = _build_html_transcript(
        messages     = all_messages,
        channel_name = channel.name,
        opener_name  = opener_name,
        closed_by_name = interaction.user.name,
        cat_label    = cat_label,
        ticket_num_str = ticket_num_str,
        duration_str = duration_str,
        opened_at    = opened_at_str,
    )

    # --- Ticket Closed log ---
    await send_log(
        title="Ticket Closed",
        description=(
            f"**Opened by** {opener_mention}\n"
            f"**Closed by** {interaction.user.mention} `{interaction.user.name}`\n"
            f"**Reason** {reason}"
        ),
        color=0xED4245,
        webhook_key="wh_tickets_closed",
        thumbnail_url=opener_avatar,
        fields=[
            {"name": "Ticket",    "value": f"#{ticket_num_str}",                                 "inline": True},
            {"name": "Category",  "value": cat_label,                                            "inline": True},
            {"name": "Channel",   "value": f"#{channel.name}",                                   "inline": True},
            {"name": "Duration",  "value": duration_str,                                         "inline": True},
            {"name": "Messages",  "value": f"{user_count} user / {total_count} total",           "inline": True},
        ],
        footer=f"User ID: {uid_match.group(1) if uid_match else 'Unknown'}",
    )

    # --- Transcript log - preview in embed + full HTML attached to same message ---
    preview_lines = user_msgs_txt[-15:] if user_msgs_txt else ["No user messages in this ticket."]
    preview       = "\n".join(preview_lines)
    html_bytes    = html_transcript.encode("utf-8")
    await send_log(
        title=f"Transcript - {channel.name}",
        description=f"```\n{preview[:1800]}\n```",
        color=BRAND_COLOR,
        webhook_key="wh_ticket_transcripts",
        fields=[
            {"name": "Ticket",         "value": f"#{ticket_num_str}",  "inline": True},
            {"name": "Category",       "value": cat_label,              "inline": True},
            {"name": "Duration",       "value": duration_str,           "inline": True},
            {"name": "Total Messages", "value": str(total_count),       "inline": True},
            {"name": "User Messages",  "value": str(user_count),        "inline": True},
        ],
        footer=f"Full transcript attached above",
        attachment_bytes=html_bytes,
        attachment_filename=f"transcript-{channel.name}.html",
    )

    # --- DM opener with HTML transcript file ---
    await _dm_ticket_closed(
        channel        = channel,
        closed_by      = interaction.user,
        html_transcript = html_transcript,
        ticket_num_str = ticket_num_str,
        cat_label      = cat_label,
        duration_str   = duration_str,
        close_reason   = reason,
    )

    # Stash cat_id before the channel is deleted
    closing_cat_id = _cat_id_for_channel(channel)

    await asyncio.sleep(3)
    await channel.delete(reason=f"Ticket #{ticket_num_str} closed by {interaction.user}: {reason}")

    # Delete the category if it is now empty
    if closing_cat_id:
        await _cleanup_empty_category(interaction.guild, closing_cat_id)

# ─── VERIFICATION VIEW ────────────────────────────────────────────────────────

class VerifyModal(discord.ui.Modal, title="Purchase Verification"):
    invoice_input = discord.ui.TextInput(
        label="Invoice ID",
        placeholder="e.g. INV-XXXX-XXXX-XXXX-XXXX",
        min_length=5,
        max_length=32,
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        invoice_id = self.invoice_input.value.strip().upper()
        member     = interaction.user
        guild      = interaction.guild

        # Call void_bot's /verify API (avoids shared-volume requirement)
        try:
            result = await _void_verify(invoice_id, str(member.id))
        except Exception as ex:
            log.error("Verify API call failed user=%s invoice=%s: %s", member.id, invoice_id, ex)
            await interaction.followup.send(
                "Verification failed - could not reach auth server. Contact staff.", ephemeral=True
            )
            return

        if result.get("error"):
            log.error("Verify API error user=%s invoice=%s: %s", member.id, invoice_id, result["error"])
            await interaction.followup.send(
                "Verification failed - auth server error. Contact staff.", ephemeral=True
            )
            return

        if not result.get("valid"):
            reason = result.get("reason", "unknown")
            if reason == "wrong_user":
                await interaction.followup.send(
                    "That Invoice ID does not match your Discord account. Contact staff if you think this is wrong.",
                    ephemeral=True,
                )
            else:
                await interaction.followup.send(
                    "Invoice ID not found. Double-check the ID from your DM and try again.",
                    ephemeral=True,
                )
            return

        log.info("Verify API hit user=%s invoice=%s", member.id, invoice_id)

        # Assign verified role
        verified_role = guild.get_role(CONFIG["verified_role_id"]) if guild else None
        role_assigned = False
        if verified_role:
            if verified_role not in member.roles:
                try:
                    await member.add_roles(verified_role, reason=f"Invoice {invoice_id}")
                    role_assigned = True
                except Exception as ex:
                    log.warning("Could not assign verified role user=%s: %s", member.id, ex)
            else:
                role_assigned = True  # already had it

        status = "You now have access to the server." if role_assigned else "Role could not be assigned - contact staff."
        await interaction.followup.send(f"Verified. {status}", ephemeral=True)

        log.info("Verified user=%s invoice=%s role_assigned=%s", member.id, invoice_id, role_assigned)
        try:
            await send_log(
                title="User Verified",
                description=f"{member.mention} (`{member.name}` - `{member.id}`)",
                color=0x57F287,
                webhook_key="wh_verifications",
                fields=[{"name": "Invoice ID", "value": f"`{invoice_id}`", "inline": True}],
                footer=f"User ID: {member.id}",
            )
        except Exception as ex:
            log.warning("Verify log failed: %s", ex)


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify", style=discord.ButtonStyle.success, custom_id="verify_button")
    async def verify_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_modal(VerifyModal())

# ─── HWID RESET VIEW ──────────────────────────────────────────────────────────

class HWIDView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Reset HWID", style=discord.ButtonStyle.secondary, custom_id="hwid_reset_button")
    async def hwid_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        success, message = reset_hwid(str(interaction.user.id))
        if success:
            await _reply_v2(
                interaction,
                f"{e('chip')} **HWID Reset Successful**\n\n{message}",
                color=0x57F287,
            )
            u = interaction.user
            await send_log(
                title="HWID Reset",
                description=f"{u.mention}\n`{u.name}` - `{u.id}`",
                color=0xFEE75C,
                webhook_key="wh_hwid_resets",
                thumbnail_url=str(u.display_avatar.url),
                fields=[
                    {"name": "User",   "value": f"`{u.name}`",  "inline": True},
                    {"name": "ID",     "value": f"`{u.id}`",    "inline": True},
                    {"name": "Result", "value": "Success",      "inline": True},
                ],
                footer=f"User ID: {u.id}",
            )
        else:
            await _reply_v2(
                interaction,
                f"{e('cross')} **HWID Reset Failed**\n\n{message}",
                color=0xED4245,
            )

# ─── SETUP PINGS VIEW ─────────────────────────────────────────────────────────

class SetupPingsView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Setup Pings",
        style=discord.ButtonStyle.secondary,
        custom_id="setup_pings_toggle",
    )
    async def toggle_setup_pings(self, interaction: discord.Interaction, button: discord.ui.Button):
        role_id = CONFIG["setup_pings_role_id"]
        if not role_id:
            await _reply_v2(interaction, f"{e('cross')} Setup pings role is not configured.", color=0xED4245)
            return
        role = interaction.guild.get_role(role_id)
        if not role:
            await _reply_v2(interaction, f"{e('cross')} Setup pings role not found.", color=0xED4245)
            return
        member = interaction.user
        if role in member.roles:
            await member.remove_roles(role, reason="Setup pings toggle")
            await _reply_v2(
                interaction,
                f"{e('cross')} Removed **{role.name}** - you will no longer receive setup pings.",
                color=0xFEE75C,
            )
        else:
            await member.add_roles(role, reason="Setup pings toggle")
            await _reply_v2(
                interaction,
                f"{e('verify')} Added **{role.name}** - you will be pinged when setup team is available.",
                color=0x57F287,
            )

# ─── BOT ──────────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.members = False
intents.message_content = False

bot = commands.Bot(command_prefix="!", intents=intents)


# ─── KEY DELIVERY QUEUE ───────────────────────────────────────────────────────
# Staff /keygen writes rows to key_deliveries. The staff bot usually does not
# share a server with customers, so it cannot DM them. This bot lives in the
# customer guild, so it polls the queue and delivers the key by DM.

KEY_DELIVERY_MAX_ATTEMPTS = 5


def _key_dm_embed(key: str, product: str, expires_label: str) -> discord.Embed:
    prod_icon = "\U0001f310" if (product or "").lower() == "public" else "\U0001f512"
    em = discord.Embed(
        title="Your License Key",
        description="Your key is ready. Open the loader and enter it to activate your license.",
        color=BRAND_COLOR,
    )
    em.add_field(name="Key", value=f"```{key}```", inline=False)
    em.add_field(name="Product", value=f"{prod_icon} {product or 'private'}", inline=True)
    em.add_field(name="Valid For", value=expires_label or "Lifetime", inline=True)
    em.set_footer(text="Keep this key private - do not share it with anyone.")
    return em


async def _dm_key(discord_id: str, key: str, product: str, expires_label: str) -> dict:
    """DM a license key to a user from this bot. Returns {ok, error}. Never raises."""
    try:
        user = bot.get_user(int(discord_id)) or await bot.fetch_user(int(discord_id))
        await user.send(embed=_key_dm_embed(key, product, expires_label))
        log.info("[deliver_key] DM sent user=%s key=%s", discord_id, key[:12])
        try:
            await send_log(
                title="Key Delivered",
                description=f"<@{discord_id}> (`{discord_id}`) received their license key via DM.",
                color=0x57F287,
                webhook_key="wh_key_generated",
                fields=[
                    {"name": "Product", "value": f"`{product or 'private'}`", "inline": True},
                    {"name": "Valid For", "value": f"`{expires_label or 'Lifetime'}`", "inline": True},
                ],
                footer=f"User ID: {discord_id}",
            )
        except Exception:
            pass
        return {"ok": True}
    except discord.Forbidden:
        log.warning("[deliver_key] Forbidden user=%s (DMs closed or not in server)", discord_id)
        return {"ok": False, "error": "User has DMs closed or is not in the customer server"}
    except discord.NotFound:
        log.warning("[deliver_key] user not found id=%s", discord_id)
        return {"ok": False, "error": "User not found by ID"}
    except Exception as ex:
        log.warning("[deliver_key] failed user=%s: %s", discord_id, ex)
        return {"ok": False, "error": str(ex)}


def _fetch_pending_deliveries() -> list:
    """Read pending delivery rows. Returns [] on any error (never raises)."""
    conn = None
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM key_deliveries WHERE status='pending' AND attempts < ? "
            "ORDER BY id ASC LIMIT 10",
            (KEY_DELIVERY_MAX_ATTEMPTS,),
        ).fetchall()
        return list(rows)
    except Exception as ex:
        log.warning("[delivery] queue read failed: %s", ex)
        return []
    finally:
        if conn is not None:
            conn.close()


def _mark_delivery(row_id: int, delivered: bool, attempt_no: int, err: Optional[str]):
    """Update a delivery row's status. Never raises."""
    conn = None
    try:
        conn = get_db()
        if delivered:
            conn.execute(
                "UPDATE key_deliveries SET status='delivered', delivered_at=?, "
                "attempts=?, last_error=NULL WHERE id=?",
                (datetime.now(timezone.utc).isoformat(), attempt_no, row_id),
            )
        else:
            new_status = "failed" if attempt_no >= KEY_DELIVERY_MAX_ATTEMPTS else "pending"
            conn.execute(
                "UPDATE key_deliveries SET status=?, attempts=?, last_error=? WHERE id=?",
                (new_status, attempt_no, err, row_id),
            )
        conn.commit()
    except Exception as ex:
        log.warning("[delivery] status update failed id=%s: %s", row_id, ex)
    finally:
        if conn is not None:
            conn.close()


@tasks.loop(seconds=10)
async def deliver_pending_keys():
    """Poll the shared key_deliveries queue and DM each pending key from this bot.

    Wrapped so no single failure can kill the loop - a dead loop would stop all
    future deliveries silently.
    """
    try:
        rows = _fetch_pending_deliveries()
        if not rows:
            return
        log.info("[delivery] %d pending key delivery(ies) to process", len(rows))

        for row in rows:
            did = str(row["discord_id"])
            key = row["key"]
            product = row["product"]
            expires_label = row["expires_label"]
            attempt_no = row["attempts"] + 1
            delivered = False
            err = None
            try:
                user = bot.get_user(int(did)) or await bot.fetch_user(int(did))
                await user.send(embed=_key_dm_embed(key, product, expires_label))
                delivered = True
            except discord.Forbidden:
                err = "User has DMs closed or does not share this server"
            except discord.NotFound:
                err = "User not found by ID"
            except Exception as ex:
                err = str(ex)

            _mark_delivery(row["id"], delivered, attempt_no, err)

            if delivered:
                log.info("[delivery] key delivered user=%s key=%s", did, key[:12])
                try:
                    await send_log(
                        title="Key Delivered",
                        description=f"<@{did}> (`{did}`) received their license key via DM.",
                        color=0x57F287,
                        webhook_key="wh_key_generated",
                        fields=[
                            {"name": "Product", "value": f"`{product or 'private'}`", "inline": True},
                            {"name": "Valid For", "value": f"`{expires_label or 'Lifetime'}`", "inline": True},
                        ],
                        footer=f"User ID: {did}",
                    )
                except Exception:
                    pass
            else:
                log.warning("[delivery] DM failed user=%s attempt=%d/%d err=%s",
                            did, attempt_no, KEY_DELIVERY_MAX_ATTEMPTS, err)
                if attempt_no >= KEY_DELIVERY_MAX_ATTEMPTS:
                    try:
                        await send_log(
                            title="Key Delivery Failed",
                            description=(
                                f"Could not DM a license key to <@{did}> (`{did}`) after "
                                f"{KEY_DELIVERY_MAX_ATTEMPTS} attempts."
                            ),
                            color=0xED4245,
                            webhook_key="wh_key_generated",
                            fields=[
                                {"name": "Reason", "value": err or "Unknown", "inline": False},
                                {"name": "Key", "value": f"`{key}`", "inline": False},
                            ],
                            footer=f"User ID: {did}",
                        )
                    except Exception:
                        pass
    except Exception as ex:
        # Last-resort guard: keep the loop alive no matter what.
        log.exception("[delivery] poller tick crashed (loop stays alive): %s", ex)


@deliver_pending_keys.before_loop
async def _before_delivery_loop():
    await bot.wait_until_ready()


@deliver_pending_keys.error
async def _delivery_loop_error(exc: Exception):
    """If the loop ever errors out, log it and restart it so delivery resumes."""
    log.exception("[delivery] poller stopped on error, restarting: %s", exc)
    try:
        deliver_pending_keys.restart()
    except Exception:
        pass


@bot.event
async def on_ready():
    _ensure_tables()
    log.info(f"Customer Bot ready as {bot.user} ({bot.user.id})")
    if _webhooks_loaded:
        log.info("Loaded %d webhook URL(s) from /data/webhooks.env", _webhooks_loaded)
    else:
        log.warning("No /data/webhooks.env found - logs will not reach staff Discord until staff bot runs /setup")

    # Log webhook URL status so it's visible in Railway logs on every boot
    _WEBHOOK_STATUS = {
        "wh_verifications":      "WEBHOOK_CUSTOMER_VERIFICATIONS",
        "wh_hwid_resets":        "WEBHOOK_CUSTOMER_HWID_RESETS",
        "wh_tickets_opened":     "WEBHOOK_CUSTOMER_TICKETS_OPENED",
        "wh_tickets_closed":     "WEBHOOK_CUSTOMER_TICKETS_CLOSED",
        "wh_ticket_transcripts": "WEBHOOK_CUSTOMER_TICKET_TRANSCRIPTS",
        "wh_key_generated":      "WEBHOOK_CUSTOMER_KEY_GENERATED",
        "wh_bans":               "WEBHOOK_CUSTOMER_BANS",
        "log_webhook_url":       "LOG_WEBHOOK_URL (fallback)",
    }
    any_missing = False
    for cfg_key, label in _WEBHOOK_STATUS.items():
        val = CONFIG.get(cfg_key)
        if val:
            log.info("[webhooks] OK      %s", label)
        else:
            log.warning("[webhooks] MISSING %s", label)
            any_missing = True
    if any_missing:
        log.warning("[webhooks] Some webhooks are not set. Ensure staff bot has run its startup setup and both services share the same Railway volume.")
    bot.add_view(TicketPanelView())
    bot.add_view(TicketControlView())
    bot.add_view(FACAuthoriseView())
    bot.add_view(VerifyView())
    bot.add_view(HWIDView())
    bot.add_view(SetupPingsView())

    if not deliver_pending_keys.is_running():
        deliver_pending_keys.start()
        # Boot diagnostic: confirm the poller is live and can see the shared queue.
        try:
            _dconn = get_db()
            _pending = _dconn.execute(
                "SELECT COUNT(*) FROM key_deliveries WHERE status='pending'"
            ).fetchone()[0]
            _dconn.close()
            log.info("Key delivery poller started (db=%s, %d pending in queue)",
                     CONFIG["db_path"], _pending)
        except Exception as ex:
            log.warning("Key delivery poller started, but queue read failed: %s", ex)

    guild = bot.get_guild(CONFIG["guild_id"])
    if not guild:
        log.warning("Guild %s not found on ready", CONFIG["guild_id"])
    # Emoji setup uses application emoji API (no guild slot limits)
    await _setup_emojis(guild)

    try:
        synced = await bot.tree.sync()
        log.info(f"Synced {len(synced)} slash commands")
    except Exception as e:
        log.error(f"Slash sync failed: {e}")

    log.info("Customer Bot fully started.")

# ─── SLASH COMMANDS ───────────────────────────────────────────────────────────

@bot.tree.command(name="setup-tickets", description="[Admin] Post the ticket panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_tickets(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _ticket_panel_payload())
    await interaction.followup.send(f"{e('verify')} Ticket panel posted.", ephemeral=True)


@bot.tree.command(name="setup-verify", description="[Admin] Post the verification panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_verify(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _verify_panel_payload())
    await interaction.followup.send(f"{e('verify')} Verification panel posted.", ephemeral=True)


@bot.tree.command(name="setup-hwid", description="[Admin] Post the HWID reset panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_hwid(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _hwid_panel_payload())
    await interaction.followup.send(f"{e('verify')} HWID panel posted.", ephemeral=True)


@bot.tree.command(name="setup-rules", description="[Admin] Post the rules in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_rules(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _rules_panel_payload())
    await interaction.followup.send(f"{e('verify')} Rules posted.", ephemeral=True)


@bot.tree.command(name="setup-info", description="[Admin] Post the setup instructions in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_info_cmd(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    ticket_ch = guild.get_channel(CONFIG["ticket_channel_id"])
    ticket_ref = ticket_ch.mention if ticket_ch else "#open-a-ticket"
    alerts_ch = guild.get_channel(CONFIG["setup_alerts_channel_id"]) if CONFIG["setup_alerts_channel_id"] else None
    alerts_ref = alerts_ch.mention if alerts_ch else "#setup-alerts"
    await _post_channel_v2(interaction.channel, _setup_info_payload(ticket_ref, alerts_ref))
    await interaction.followup.send(f"{e('verify')} Setup info posted.", ephemeral=True)


@bot.tree.command(name="key", description="Check your license key status.")
async def key_cmd(interaction: discord.Interaction):
    row = lookup_user(str(interaction.user.id))
    if not row:
        await _reply_v2(
            interaction,
            (
                f"{e('cross')} **No key linked.**\n\n"
                "Use `/verify` or the verification panel to link your license key."
            ),
            color=0xED4245,
        )
        return

    expires = row["expires_at"] or "Never"
    hwid_used = row["hwid"] is not None
    max_resets = CONFIG.get("max_hwid_resets", 1)
    resets_left = max(0, int(max_resets) - int(row["hwid_resets"]))

    text = (
        f"## {e('key')} Your License\n\n"
        f"**Key** `{row['key']}`\n"
        f"**Product** {row['product'] or 'default'}\n"
        f"**Status** {row['status'].capitalize()}\n"
        f"**Expires** {expires}\n\n"
        f"{e('chip')} **HWID Bound** {'Yes' if hwid_used else 'No'}\n"
        f"{e('dot')} **Resets Remaining** {resets_left}"
    )
    await _reply_v2(interaction, text, color=BRAND_COLOR)


@bot.tree.command(name="hwid-reset", description="Reset your HWID (limited uses).")
async def hwid_reset_cmd(interaction: discord.Interaction):
    success, message = reset_hwid(str(interaction.user.id))
    if success:
        await _reply_v2(
            interaction,
            f"{e('chip')} **HWID Reset Successful**\n\n{message}",
            color=0x57F287,
        )
        u = interaction.user
        await send_log(
            title="HWID Reset",
            description=f"{u.mention}\n`{u.name}` - `{u.id}`",
            color=0xFEE75C,
            webhook_key="wh_hwid_resets",
            thumbnail_url=str(u.display_avatar.url),
            fields=[
                {"name": "User",   "value": f"`{u.name}`", "inline": True},
                {"name": "ID",     "value": f"`{u.id}`",   "inline": True},
                {"name": "Result", "value": "Success",     "inline": True},
            ],
            footer=f"User ID: {u.id}",
        )
    else:
        await _reply_v2(
            interaction,
            f"{e('cross')} **HWID Reset Failed**\n\n{message}",
            color=0xED4245,
        )


@bot.tree.command(name="verify", description="Link your license key to your Discord account.")
async def verify_cmd(interaction: discord.Interaction):
    verified_role = interaction.guild.get_role(CONFIG["verified_role_id"])
    if verified_role and verified_role in interaction.user.roles:
        await _reply_v2(
            interaction,
            f"{e('verify')} You are already verified.",
            color=0x57F287,
        )
        return
    await interaction.response.send_modal(VerifyModal())


@bot.tree.command(name="lookup", description="[Admin] Look up a user's key by Discord ID.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def lookup_cmd(interaction: discord.Interaction, user: discord.Member):
    row = lookup_user(str(user.id))
    if not row:
        await _reply_v2(
            interaction,
            f"{e('cross')} No key linked to {user.mention}.",
            color=0xED4245,
        )
        return

    expires = row["expires_at"] or "Never"
    hwid_val = f"`{row['hwid']}`" if row["hwid"] else "Not bound"

    text = (
        f"## {e('shield')} Key Lookup: {user}\n\n"
        f"**Key** `{row['key']}`\n"
        f"**Product** {row['product'] or 'default'}\n"
        f"**Status** {row['status'].capitalize()}\n"
        f"**Expires** {expires}\n\n"
        f"{e('chip')} **HWID** {hwid_val}\n"
        f"{e('dot')} **HWID Resets Used** {row['hwid_resets']}"
    )
    await _reply_v2(interaction, text, color=BRAND_COLOR)


@bot.tree.command(name="test-logs", description="[Admin] Send a test message to every configured webhook.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def test_logs_cmd(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    _refresh_webhook_config()  # pull latest URLs from webhooks.env before testing
    results = []
    test_keys = {
        "wh_verifications":      "Verifications",
        "wh_hwid_resets":        "HWID Resets",
        "wh_tickets_opened":     "Tickets Opened",
        "wh_tickets_closed":     "Tickets Closed",
        "wh_ticket_transcripts": "Ticket Transcripts",
        "wh_key_generated":      "Key Generated",
        "wh_bans":               "Bans",
        "log_webhook_url":       "Fallback Log",
    }
    for key, label in test_keys.items():
        url = CONFIG.get(key)
        if not url:
            results.append(f"{e('cross')} **{label}** - not configured")
            continue
        try:
            async with aiohttp.ClientSession() as session:
                payload = {"embeds": [{"title": f"Test - {label}", "description": f"Webhook test from `/test-logs` by {interaction.user}", "color": 0x5865F2}]}
                async with session.post(url, json=payload) as resp:
                    if resp.status in (200, 204):
                        results.append(f"{e('verify')} **{label}** - OK")
                    else:
                        body = await resp.text()
                        results.append(f"{e('cross')} **{label}** - HTTP {resp.status}: {body[:80]}")
        except Exception as exc:
            results.append(f"{e('warn')} **{label}** - error: {exc}")

    text = "## Webhook Test Results\n\n" + "\n".join(results)
    await interaction.followup.send(embed=_make_embed(text, 0x2b2d31), ephemeral=True)


@bot.tree.command(name="close", description="[Admin] Force-close a ticket channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def close_cmd(interaction: discord.Interaction):
    if not interaction.channel.name.startswith("ticket-"):
        await _reply_v2(
            interaction,
            f"{e('cross')} This is not a ticket channel.",
            color=0xED4245,
        )
        return
    await close_ticket(interaction)

@bot.tree.command(name="debug-verify", description="[Admin] Test invoice lookup via void_bot API.")
@app_commands.describe(invoice_id="Invoice ID to test", discord_id="Discord user ID to check against")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def debug_verify(interaction: discord.Interaction, invoice_id: str, discord_id: str = "0"):
    await interaction.response.defer(ephemeral=True)
    inv = invoice_id.strip().upper()
    void_url = CONFIG.get("void_bot_url", "(not set)")
    lines = [f"**void_bot_url:** `{void_url}`", f"**Lookup:** `{inv}` for discord_id=`{discord_id}`"]
    try:
        result = await _void_verify(inv, discord_id)
        lines.append(f"**Response:** `{result}`")
    except Exception as ex:
        lines.append(f"**Error:** `{ex}`")
    await interaction.followup.send("\n".join(lines), ephemeral=True)


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    start_health_server(CONFIG["api_port"])
    bot.run(CONFIG["token"])
