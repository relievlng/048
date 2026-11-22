#!/usr/bin/env python3
"""
Customer Bot - Customer-facing Discord bot
Handles: ticket system, rules embed, verification, key lookup, HWID resets
"""

import discord
from discord.ext import commands
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
    "verified_role_id":        env_int("VERIFIED_ROLE_ID"),
    "setup_pings_role_id":     env_int("SETUP_PINGS_ROLE_ID"),
    "setup_alerts_channel_id": env_int("SETUP_ALERTS_CHANNEL_ID"),
    "ticket_category_id":      env_int("TICKET_CATEGORY_ID"),
    # Per-ticket-type Discord category channel IDs (auto-created on startup if missing)
    "ticket_cat_support":      env_int("TICKET_CAT_SUPPORT"),
    "ticket_cat_setup":        env_int("TICKET_CAT_SETUP"),
    "ticket_cat_purchase":     env_int("TICKET_CAT_PURCHASE"),
    "ticket_cat_management":   env_int("TICKET_CAT_MANAGEMENT"),
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
    "max_hwid_resets":         env_int("MAX_HWID_RESETS", 1),
    "logo_url":                env("LOGO_URL"),
}

# ─── CUSTOM EMOJIS ────────────────────────────────────────────────────────────
# Upload the SVGs from /emojis/ to your Discord server, then paste the
# <:name:id> strings here. Until then the fallback Unicode chars show fine.

EMOJIS = {
    "verify":  env("EMOJI_VERIFY",  "<:verify:EMOJI_ID>"),
    "key":     env("EMOJI_KEY",     "<:key:EMOJI_ID>"),
    "chip":    env("EMOJI_CHIP",    "<:chip:EMOJI_ID>"),
    "ticket":  env("EMOJI_TICKET",  "<:ticket:EMOJI_ID>"),
    "rules":   env("EMOJI_RULES",   "<:rules:EMOJI_ID>"),
    "cross":   env("EMOJI_CROSS",   "<:cross:EMOJI_ID>"),
    "shield":  env("EMOJI_SHIELD",  "<:shield:EMOJI_ID>"),
    "arrow":   env("EMOJI_ARROW",   "<:arrow:EMOJI_ID>"),
    "warn":    env("EMOJI_WARN",    "<:warn:EMOJI_ID>"),
    "dot":     env("EMOJI_DOT",     "<:dot:EMOJI_ID>"),
    "bell":    env("EMOJI_BELL",    "<:bell:EMOJI_ID>"),
    "lock":    env("EMOJI_LOCK",    "<:lock:EMOJI_ID>"),
    "gear":    env("EMOJI_GEAR",    "<:gear:EMOJI_ID>"),
}

def e(name: str) -> str:
    """Return the custom emoji string for a given name."""
    return EMOJIS.get(name, "")

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
    Send an embed log to the appropriate staff Discord channel via webhook.
    Uses standard Discord embed format (webhooks don't support Components v2).
    Pass attachment_bytes + attachment_filename to upload a file alongside the embed.
    """
    _refresh_webhook_config()
    url = CONFIG.get(webhook_key) or CONFIG.get("log_webhook_url")
    if not url:
        log.warning("send_log: no webhook URL for key=%s - check webhooks.env or staff bot /setup", webhook_key)
        return

    embed: dict = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if fields:
        embed["fields"] = [
            {"name": f["name"], "value": f["value"], "inline": f.get("inline", False)}
            for f in fields
        ]
    if thumbnail_url:
        embed["thumbnail"] = {"url": thumbnail_url}
    if footer:
        embed["footer"] = {"text": footer}

    payload = {"embeds": [embed]}

    try:
        async with aiohttp.ClientSession() as session:
            if attachment_bytes and attachment_filename:
                # Multipart: embed JSON + file attachment in one request
                form = aiohttp.FormData()
                form.add_field(
                    "payload_json",
                    json.dumps(payload),
                    content_type="application/json",
                )
                ext = attachment_filename.rsplit(".", 1)[-1].lower()
                mime = "text/html" if ext == "html" else "text/plain"
                form.add_field(
                    "files[0]",
                    attachment_bytes,
                    filename=attachment_filename,
                    content_type=mime,
                )
                async with session.post(url, data=form) as resp:
                    if resp.status not in (200, 204):
                        body = await resp.text()
                        log.warning("send_log(+file) webhook %s returned %d: %s", webhook_key, resp.status, body[:200])
            else:
                async with session.post(url, json=payload) as resp:
                    if resp.status not in (200, 204):
                        body = await resp.text()
                        log.warning("send_log webhook %s returned %d: %s", webhook_key, resp.status, body[:200])
    except Exception as exc:
        log.warning("send_log failed for key=%s: %s", webhook_key, exc)

# ─── HEALTH SERVER ─────────────────────────────────────────────────────────────

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
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

def _make_embed(text: str, color: int = 0x2b2d31) -> discord.Embed:
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
        f"## {ticket_pfx}Support Tickets\n"
        "Select a category below to open a private support channel with staff."
    )})
    body.append({"type": 14})
    first = True
    for cat_id, cat in TICKET_CATEGORIES.items():
        if not first:
            body.append({"type": 14})
        first = False
        em = _emoji_in_text(cat["emoji_key"])
        prefix = f"{em} " if em else ""
        body.append(_v2_section(
            f"{prefix}**{cat['label'].upper()}**\n{bullet}{cat['desc']}",
            cat["label"],
            f"ticket_open_{cat_id}",
            btn_emoji_name=cat["emoji_key"],
        ))
    return _v2_container(body, accent=0x5865F2)


def _verify_panel_payload() -> dict:
    em_lock   = _emoji_in_text("lock")
    em_key    = _emoji_in_text("key")
    em_verify = _emoji_in_text("verify")
    em_dot    = _emoji_in_text("dot")
    lock_pfx   = f"{em_lock} "   if em_lock   else "\U0001f512 "
    key_pfx    = f"{em_key} "    if em_key    else "\U0001f511 "
    verify_pfx = f"{em_verify} " if em_verify else ""
    bullet     = f"{em_dot} "    if em_dot    else "• "
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"## {lock_pfx}Verification\n"
        "Link your license key to unlock full access to this server."
    )})
    body.append({"type": 14})
    body.append({"type": 10, "content": (
        f"{key_pfx}**HOW IT WORKS**\n"
        f"{bullet}Your license key is linked permanently to your Discord account.\n"
        f"{bullet}One key per account - keys are non-transferable.\n"
        f"{bullet}Click the button below to begin verification."
    )})
    body.append({"type": 14})
    body.append(_v2_section(
        f"{verify_pfx}**VERIFY YOUR LICENSE**\n"
        f"{bullet}Have your license key ready before clicking.",
        "Verify",
        "verify_button",
        btn_emoji_name="verify",
        btn_style=3,
    ))
    return _v2_container(body, accent=0x57F287)


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
    return _v2_container(body, accent=0xFEE75C)


def _rules_panel_payload() -> dict:
    em_rules = _emoji_in_text("rules")
    em_dot   = _emoji_in_text("dot")
    em_cross = _emoji_in_text("cross")
    em_warn  = _emoji_in_text("warn")
    rules_pfx = f"{em_rules} " if em_rules else "\U0001f4cb "
    bullet    = f"{em_dot} "   if em_dot   else "• "
    cross_pfx = f"{em_cross} " if em_cross else "❌ "
    warn_pfx  = f"{em_warn} "  if em_warn  else "⚠️ "

    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"## {rules_pfx}Server Rules\n"
        "By being in this server and using our software, you agree to the following rules. "
        "Violations may result in key termination or permanent blacklisting."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        "**RULES & TERMS:**\n"
        "All rules from our main terms of service apply here to all customers. "
        "Using our software means you agree to all terms.\n\n"
        "**SHARING INFORMATION:**\n"
        "Do not share our software, procedures, or member information, including:\n"
        f"{bullet}Loader photos / videos\n"
        f"{bullet}Injection methods or instructions\n"
        f"{bullet}Backdooring users, or helping staff/devs detect features\n"
        f"{bullet}Recording setups, or screenshotting / screensharing this server"
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        "**INVITES & VOUCHES:**\n"
        "Group owners — you are responsible for your group's TOS violations (may deactivate access).\n"
        "You are responsible for anyone you vouch for or invite to this server.\n\n"
        "**ACCOUNT & SERVER ACCESS:**\n"
        "Lost account access may mean no re-invite. Keep your account secure. "
        "Token-logged spam accounts are banned instantly and may need a new key.\n\n"
        "**PAUSING KEYS:**\n"
        "To pause your key, open a ticket and speak to staff. Pauses last up to 2 weeks, "
        "then resume automatically. Respect staff - they are not 24/7. Disrespect may "
        "result in a timeout or ban. Serious issues: report to management."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        "**MULTI SOFTWARE POLICY:**\n"
        "Using or affiliating with any other cheat / bypass while using our software is prohibited. "
        "Caught using or promoting another product → key terminated, no refund.\n"
        f"{bullet}Includes other Discord tags, vanities in your profile, etc.\n\n"
        "**PC CHECKING:**\n"
        "No PC checking of any kind:\n"
        f"{bullet}Self scanning · scanning friends · general server PC checks\n\n"
        "**REPORTING:**\n"
        "Knowing about a TOS / rule breach and not reporting it can get you punished too - "
        "friends breaking rules, leaks, suspicious DMs/solicits, or anything that harms the community.\n\n"
        "**DISRESPECT TO OTHER PRODUCTS:**\n"
        f"Insults or attacks toward other software providers are banned. "
        f"{cross_pfx}**Immediate key termination. ZERO TOLERANCE.**"
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        "**RESETUPS:**\n"
        "Resetups are free UNLESS you:\n"
        f"{bullet}Destruct without PC check proof\n"
        f"{bullet}Break or disable something yourself\n"
        f"{bullet}Factory reset without approval or valid proof\n\n"
        "**Factory resets require** a ticket, valid proof, and staff approval.\n\n"
        "**PC Checks** - ensure you have clear proof of your PC check:\n"
        f"{bullet}Screenshot/VOD of scan or ban\n"
        f"{bullet}Visible PC checker roles\n"
        f"{bullet}Date and time included\n\n"
        "Violations incur a **$10 setup fee**. Repeated offences may result in blacklisting."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": (
        f"{warn_pfx}**DISCLOSURE:**\n"
        "Failure to comply with these rules or failure to report a rule break to management will lead to:\n"
        f"{bullet}Permanent blacklisting from our services without refund.\n"
        f"{bullet}Further punishment to the user/s who vouched / invited you."
    )})
    body.append({"type": 14})

    body.append({"type": 10, "content": "-# Last updated by staff"})
    return _v2_container(body, accent=0xED4245)


def _setup_info_payload(ticket_ref: str, alerts_ref: str) -> dict:
    em_gear   = _emoji_in_text("gear")
    em_bell   = _emoji_in_text("bell")
    em_ticket = _emoji_in_text("ticket")
    em_arrow  = _emoji_in_text("arrow")
    em_warn   = _emoji_in_text("warn")
    em_dot    = _emoji_in_text("dot")

    gear_pfx   = f"{em_gear} "   if em_gear   else "⚙️ "
    bell_pfx   = f"{em_bell} "   if em_bell   else "\U0001f514 "
    ticket_pfx = f"{em_ticket} " if em_ticket else "\U0001f3ab "
    arrow_pfx  = f"{em_arrow} "  if em_arrow  else "➡️ "
    warn_pfx   = f"{em_warn} "   if em_warn   else "⚠️ "
    bullet     = f"{em_dot} "    if em_dot    else "• "

    body: list = []
    body.extend(_v2_banner())

    body.append({"type": 10, "content": (
        f"## {gear_pfx}Awaiting Setup?\n"
        "Complete every step below, then wait for the Setup Team."
    )})
    body.append({"type": 14})

    body.append(_v2_section(
        f"{bell_pfx}**GET SETUP PINGS ROLE**\n"
        f"{bullet}Click the button to get the **@Setup Pings** role. Click again to remove it.",
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

    return _v2_container(body, accent=0x5865F2)


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
    overwrites: dict = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
    }
    if admin_role:
        overwrites[admin_role] = discord.PermissionOverwrite(
            view_channel=True, manage_channels=True,
            send_messages=True, read_message_history=True,
        )

    base_cat = guild.get_channel(CONFIG.get("ticket_category_id") or 0)
    position = (base_cat.position + 1) if base_cat else 0

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
    "verify":  "verify",
    "key":     "key",
    "chip":    "chip",
    "ticket":  "ticket",
    "rules":   "rules",
    "cross":   "cross",
    "shield":  "shield",
    "arrow":   "arrow",
    "warn":    "warning",
    "dot":     "dot",
    "bell":    "bell",
    "lock":    "lock",
    "gear":    "gear",
}

async def _setup_emojis(guild: discord.Guild) -> None:
    """
    Auto-create custom emojis from /emojis/*.svg on startup.
    - Reuses existing guild emojis by name (skips re-upload).
    - Converts SVG -> PNG via cairosvg, uploads via guild.create_custom_emoji().
    - Patches EMOJIS dict in-place with real <:name:id> strings.
    - Logs the EMOJI_* env var values so the user can persist them.
    """
    try:
        import cairosvg  # type: ignore
    except ImportError:
        log.warning("cairosvg not installed - skipping emoji auto-setup. Add cairosvg>=2.7.0 to requirements.txt")
        return

    if not os.path.isdir(EMOJI_SVG_DIR):
        log.warning("No /emojis/ directory found - skipping emoji auto-setup")
        return

    # Build a map of name -> existing emoji for fast lookup
    existing: dict[str, discord.Emoji] = {em.name: em for em in guild.emojis}
    created_any = False

    for key, file_stem in _EMOJI_FILE_MAP.items():
        emoji_name = file_stem  # Discord emoji name = file stem
        env_var    = f"EMOJI_{key.upper()}"

        # If env var is already set to a real emoji string, skip
        current = EMOJIS.get(key, "")
        if current and "EMOJI_ID" not in current:
            log.info("Emoji %s already configured via env (%s)", key, env_var)
            continue

        # Reuse existing guild emoji if present
        if emoji_name in existing:
            em = existing[emoji_name]
            fmt = f"<:{em.name}:{em.id}>"
            EMOJIS[key] = fmt
            log.info("Reused existing emoji %-10s -> %s  (set %s=%s)", emoji_name, fmt, env_var, fmt)
            continue

        # Try to upload from SVG
        svg_path = os.path.join(EMOJI_SVG_DIR, f"{file_stem}.svg")
        if not os.path.isfile(svg_path):
            log.warning("SVG not found for emoji key=%s (%s) - skipping", key, svg_path)
            continue

        try:
            png_bytes: bytes = cairosvg.svg2png(
                url=svg_path,
                output_width=128,
                output_height=128,
            )
            em = await guild.create_custom_emoji(name=emoji_name, image=png_bytes)
            fmt = f"<:{em.name}:{em.id}>"
            EMOJIS[key] = fmt
            created_any = True
            log.info("Created emoji %-10s -> %s  (set %s=%s)", emoji_name, fmt, env_var, fmt)
        except discord.Forbidden:
            log.error("Missing Manage Emojis permission - cannot upload emoji %s", emoji_name)
            break
        except discord.HTTPException as exc:
            log.error("Failed to upload emoji %s: %s", emoji_name, exc)
        except Exception as exc:
            log.error("Unexpected error uploading emoji %s: %s", emoji_name, exc)

    if created_any:
        log.info("=" * 60)
        log.info("EMOJI SETUP COMPLETE - add these env vars to Railway to persist:")
        for key in _EMOJI_FILE_MAP:
            val = EMOJIS.get(key, "")
            if val and "EMOJI_ID" not in val:
                log.info("  EMOJI_%s=%s", key.upper(), val)
        log.info("=" * 60)


# ─── TICKET SYSTEM ────────────────────────────────────────────────────────────

TICKET_CATEGORIES = {
    "support":    {"label": "Support",            "cat_name": "Support",          "channel_prefix": "support",    "emoji_key": "ticket",  "desc": "Product support or general enquiries", "config_key": "ticket_cat_support"},
    "setup":      {"label": "Setup",              "cat_name": "Setup",            "channel_prefix": "setup",      "emoji_key": "arrow",   "desc": "First time setup",                    "config_key": "ticket_cat_setup"},
    "purchase":   {"label": "Purchase / Renewal", "cat_name": "Purchase-Renewal", "channel_prefix": "purchase",   "emoji_key": "shield",  "desc": "Purchase or renew",                   "config_key": "ticket_cat_purchase"},
    "management": {"label": "Management",         "cat_name": "Management",       "channel_prefix": "management", "emoji_key": "key",     "desc": "Management help",                     "config_key": "ticket_cat_management"},
}

# ─── TICKET COUNTER ───────────────────────────────────────────────────────────

def _init_ticket_counter():
    """Ensure the ticket_counter table exists."""
    with get_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ticket_counter "
            "(id INTEGER PRIMARY KEY, next_num INTEGER NOT NULL DEFAULT 1)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO ticket_counter (id, next_num) VALUES (1, 1)"
        )
        conn.commit()

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

    def _make_callback(self, cat_id: str):
        async def callback(interaction: discord.Interaction):
            await open_ticket(interaction, cat_id)
        return callback


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


async def open_ticket(interaction: discord.Interaction, cat_id: str):
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

    # Build a clean channel name: {prefix}-{ticket_num}
    channel_name = f"{cat_info['channel_prefix']}-{ticket_num_str}"

    admin_role = guild.get_role(CONFIG["admin_role_id"])

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True,
        ),
    }
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

    # --- Rich ticket open embed ---
    now_ts = int(discord.utils.utcnow().timestamp())
    text = (
        f"## {e('ticket')} {cat_info['label']} Ticket\n\n"
        f"Welcome, {member.mention}. A staff member will be with you shortly.\n\n"
        f"**Category** {cat_info['desc']}\n"
        f"**Ticket** #{ticket_num_str}\n"
        f"**Opened** <t:{now_ts}:R>\n\n"
        "Please describe your issue in as much detail as possible. "
        "Include any relevant screenshots, order IDs, or error messages.\n\n"
        "-# Use the buttons below to manage this ticket."
    )
    mention_str = admin_role.mention if admin_role else ""
    await channel.send(
        content=f"{member.mention} {mention_str}",
        embed=_make_embed(text, 0x5865F2),
        view=TicketControlView(),
    )

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
        color=0x5865F2,
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

class VerifyModal(discord.ui.Modal, title="Verify Your License Key"):
    key_input = discord.ui.TextInput(
        label="License Key",
        placeholder="e.g. KL-XXXX-XXXX-XXXX",
        min_length=5,
        max_length=50,
    )

    async def on_submit(self, interaction: discord.Interaction):
        key = self.key_input.value.strip().upper()
        member = interaction.user
        guild = interaction.guild

        row = lookup_key(key)
        if not row:
            await _reply_v2(
                interaction,
                f"{e('cross')} **Invalid key.**\nPlease check your key and try again.",
                color=0xED4245,
            )
            return

        if row["status"] == "banned":
            await _reply_v2(
                interaction,
                f"{e('cross')} **This key has been banned.**\nContact staff if you believe this is an error.",
                color=0xED4245,
            )
            return

        ok = register_key_to_discord(key, member.id)
        if not ok:
            await _reply_v2(
                interaction,
                f"{e('cross')} **This key is already linked to another account.**\nContact staff for assistance.",
                color=0xED4245,
            )
            return

        verified_role = guild.get_role(CONFIG["verified_role_id"])
        if verified_role and verified_role not in member.roles:
            await member.add_roles(verified_role, reason="Key verification")

        expires = row["expires_at"] or "Never"
        product = row["product"] or "default"

        await _reply_v2(
            interaction,
            (
                f"{e('verify')} **Verified successfully.**\n"
                f"You now have access to the server.\n\n"
                f"**Key** `{key}`\n"
                f"**Product** {product}\n"
                f"**Expires** {expires}"
            ),
            color=0x57F287,
        )

        acct_age = (datetime.now(timezone.utc) - member.created_at).days
        await send_log(
            title="User Verified",
            description=(
                f"{member.mention}\n"
                f"`{member.name}` - `{member.id}`"
            ),
            color=0x57F287,
            webhook_key="wh_verifications",
            thumbnail_url=str(member.display_avatar.url),
            fields=[
                {"name": "Key",          "value": f"`{key}`",         "inline": True},
                {"name": "Product",      "value": product,            "inline": True},
                {"name": "Expires",      "value": expires,            "inline": True},
                {"name": "Account Age",  "value": f"{acct_age:,} days","inline": True},
                {"name": "Joined Server","value": f"<t:{int(member.joined_at.timestamp())}:R>" if member.joined_at else "Unknown", "inline": True},
            ],
            footer=f"User ID: {member.id}",
        )


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify", style=discord.ButtonStyle.success, custom_id="verify_button")
    async def verify_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        verified_role = interaction.guild.get_role(CONFIG["verified_role_id"])
        if verified_role and verified_role in interaction.user.roles:
            await _reply_v2(
                interaction,
                f"{e('verify')} You are already verified.",
                color=0x57F287,
            )
            return
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


@bot.event
async def on_ready():
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
    bot.add_view(VerifyView())
    bot.add_view(HWIDView())
    bot.add_view(SetupPingsView())

    guild = bot.get_guild(CONFIG["guild_id"])
    if guild:
        # Ticket categories are created on demand when tickets are opened,
        # and deleted when they become empty - no startup setup needed.
        await _setup_emojis(guild)
    else:
        log.warning("Guild %s not found - skipping emoji setup", CONFIG["guild_id"])

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
    await _reply_v2(interaction, text, color=0x2b2d31)


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
    await _reply_v2(interaction, text, color=0x5865F2)


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

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    start_health_server(CONFIG["api_port"])
    bot.run(CONFIG["token"])
