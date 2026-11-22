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
):
    """
    Send an embed log to the appropriate staff Discord channel via webhook.
    Uses standard Discord embed format (webhooks don't support Components v2).
    """
    url = CONFIG.get(webhook_key) or CONFIG.get("log_webhook_url")
    if not url:
        log.debug("send_log: no webhook URL for key=%s - skipping", webhook_key)
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

    payload = {"embeds": [embed]}

    try:
        async with aiohttp.ClientSession() as session:
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


_PLACEHOLDER_BANNER = "https://media1.tenor.com/m/0mL6VQxtdE0AAAAC/cat-kitty.gif"


def _v2_banner() -> list:
    """Return a MediaGallery banner. Uses LOGO_URL if set, otherwise placeholder GIF."""
    url = CONFIG.get("logo_url") or _PLACEHOLDER_BANNER
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
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        "## Tickets\n"
        "Choose a category. A private channel opens and staff meet you there."
    )})
    body.append({"type": 14})
    for cat_id, cat in TICKET_CATEGORIES.items():
        em = _emoji_in_text(cat["emoji_key"])
        prefix = f"{em} " if em else ""
        body.append(_v2_section(
            f"{prefix}**{cat['label']}**\n-# {cat['desc']}",
            cat["label"],
            f"ticket_open_{cat_id}",
            btn_emoji_name=cat["emoji_key"],
        ))
    return _v2_container(body)


def _verify_panel_payload() -> dict:
    em = _emoji_in_text("verify")
    prefix = f"{em} " if em else ""
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        "## Verification\n"
        "To access this server you need to verify your license key."
    )})
    body.append({"type": 14})
    body.append(_v2_section(
        f"{prefix}**Link your license key**\n"
        "-# Your key is linked to your Discord account permanently. One key per account.",
        "Verify",
        "verify_button",
        btn_emoji_name="verify",
        btn_style=3,
    ))
    return _v2_container(body)


def _hwid_panel_payload() -> dict:
    em = _emoji_in_text("chip")
    prefix = f"{em} " if em else ""
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        "## HWID Reset\n"
        "Changed hardware or reinstalled Windows? Reset your HWID here."
    )})
    body.append({"type": 14})
    body.append(_v2_section(
        f"{prefix}**Reset your hardware ID**\n"
        "-# Limited resets available. Used all resets? Open a ticket instead.\n"
        "-# HWID resets are logged and monitored.",
        "Reset HWID",
        "hwid_reset_button",
        btn_emoji_name="chip",
    ))
    return _v2_container(body)


def _rules_panel_payload() -> dict:
    em = _emoji_in_text("dot")
    prefix = f"{em} " if em else "- "
    rules = [
        ("Respect everyone",    "Harassment, discrimination, and toxicity are not tolerated."),
        ("No sharing keys",     "License keys are non-transferable. Sharing a key results in a permanent ban."),
        ("No chargebacks",      "Initiating a chargeback voids your license immediately with no refund."),
        ("No leaking",          "Do not share, leak, or redistribute any files or software from this server."),
        ("No ban evasion",      "Attempting to bypass a ban results in a permanent blacklist."),
        ("Use correct channels","Keep discussions in their respective channels."),
        ("No advertising",      "Advertising other products or services without permission is not allowed."),
        ("Follow Discord ToS",  "All Discord Terms of Service rules apply at all times."),
    ]
    rule_lines = "\n".join(f"{prefix}**{n}** - {v}" for n, v in rules)
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        "## Server Rules\n"
        "By being in this server you agree to the following rules. "
        "Violations may result in removal or key termination.\n\n"
        f"{rule_lines}\n\n"
        "-# Last updated by staff"
    )})
    return _v2_container(body)


def _setup_info_payload(ticket_ref: str, alerts_ref: str) -> dict:
    em_arrow = _emoji_in_text("arrow")
    em_warn  = _emoji_in_text("warn")
    bullet = f"{em_arrow} " if em_arrow else "- "
    warn   = f"{em_warn} " if em_warn  else "! "
    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        "## Awaiting Setup?\n"
        "Complete every step below, then wait for the Setup Team.\n\n"
        f"{bullet}**Get Setup Pings** - Click the button below. Click again to remove.\n\n"
        f"{bullet}**Open a Ticket** - Open a setup ticket in {ticket_ref}. "
        "Your Invoice ID is in your DMs.\n\n"
        f"{bullet}**Wait for the Team** - Check {alerts_ref} regularly. "
        "Ping them in your ticket **once** with your AnyDesk code and invoice ID.\n\n"
        f"{warn}Do **NOT** ping staff unless they have announced availability.\n\n"
        "-# Failing to follow these steps may delay your setup."
    )})
    body.append({"type": 14})
    body.append(_v2_section(
        f"{em_arrow + ' ' if em_arrow else ''}Toggle setup pings - get notified when the team is available.",
        "Setup Pings",
        "setup_pings_toggle",
        btn_emoji_name="arrow",
    ))
    return _v2_container(body)


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


# ─── TICKET VIEWS ─────────────────────────────────────────────────────────────

TICKET_CATEGORIES = {
    "support":    {"label": "Support",            "cat_name": "Support",          "channel_prefix": "support",    "emoji_key": "ticket",  "desc": "Product support or general enquiries", "config_key": "ticket_cat_support"},
    "setup":      {"label": "Setup",              "cat_name": "Setup",            "channel_prefix": "setup",      "emoji_key": "arrow",   "desc": "First time setup",                    "config_key": "ticket_cat_setup"},
    "purchase":   {"label": "Purchase / Renewal", "cat_name": "Purchase-Renewal", "channel_prefix": "purchase",   "emoji_key": "shield",  "desc": "Purchase or renew",                   "config_key": "ticket_cat_purchase"},
    "management": {"label": "Management",         "cat_name": "Management",       "channel_prefix": "management", "emoji_key": "key",     "desc": "Management help",                     "config_key": "ticket_cat_management"},
}

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
        await close_ticket(interaction)

    @discord.ui.button(label="Claim", style=discord.ButtonStyle.secondary, custom_id="ticket_claim")
    async def claim_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            f"**{interaction.user.mention}** has claimed this ticket.", ephemeral=False
        )


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

    # Build a clean channel name: {prefix}-{safe-username}
    safe_name = re.sub(r"[^a-z0-9]", "-", member.name.lower())[:20].strip("-") or str(member.id)
    channel_name = f"{cat_info['channel_prefix']}-{safe_name}"

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

    channel = await guild.create_text_channel(
        name=channel_name,
        category=ticket_category,
        overwrites=overwrites,
        topic=f"{cat_info['label']} | {member} ({member.id})",
    )

    text = (
        f"## {e('ticket')} {cat_info['label']} Ticket\n\n"
        f"Hey {member.mention}, thanks for reaching out.\n\n"
        f"**Category** {cat_info['desc']}\n\n"
        "Describe your issue and a staff member will be with you shortly.\n"
        "Use the **Close Ticket** button below when your issue is resolved.\n\n"
        f"-# Ticket opened by {member}"
    )
    mention_str = admin_role.mention if admin_role else ""
    await channel.send(
        content=f"{member.mention} {mention_str}",
        embed=_make_embed(text, 0x2b2d31),
        view=TicketControlView(),
    )

    await _reply_v2(
        interaction,
        f"{e('arrow')} **Ticket opened.**\nHead to your private channel: [{channel.name}]({channel.jump_url})",
        color=0x57F287,
    )

    await send_log(
        title=f"{e('ticket')} Ticket Opened",
        description=(
            f"**User** {member.mention} (`{member.id}`)\n"
            f"**Category** {cat_info['label']}\n"
            f"**Channel** {channel.mention}"
        ),
        color=0x57F287,
        webhook_key="wh_tickets_opened",
    )


async def _dm_ticket_closed(
    channel: discord.TextChannel,
    closed_by: discord.Member,
    transcript: str,
) -> None:
    """DM the ticket opener when their ticket is closed, with a transcript file."""
    if not channel.topic:
        return
    # Channel topic is set as: "{cat_label} | {member} ({member.id})"
    match = re.search(r'\((\d+)\)\s*$', channel.topic)
    if not match:
        return

    try:
        opener_id = int(match.group(1))
        opener = channel.guild.get_member(opener_id)
        if not opener:
            return

        # Parse category label from topic
        cat_label = channel.topic.split(" | ")[0] if " | " in channel.topic else "Unknown"

        summary = (
            f"## Ticket Closed\n\n"
            f"**Channel** {channel.name}\n"
            f"**Category** {cat_label}\n"
            f"**Closed by** {closed_by}\n\n"
            "Your full conversation transcript is attached."
        )

        file = discord.File(
            io.BytesIO(transcript.encode("utf-8")),
            filename=f"transcript-{channel.name}.txt",
        )
        await opener.send(embed=_make_embed(summary, 0x2b2d31), file=file)
        log.info("DMed transcript to %s (%d) for %s", opener, opener_id, channel.name)

    except discord.Forbidden:
        log.info("Cannot DM ticket opener %s - DMs are disabled", match.group(1))
    except Exception as exc:
        log.warning("Failed to DM ticket opener: %s", exc)


async def close_ticket(interaction: discord.Interaction):
    channel = interaction.channel
    admin_role = interaction.guild.get_role(CONFIG["admin_role_id"])
    is_admin = admin_role and admin_role in interaction.user.roles

    if not is_admin and not channel.name.startswith("ticket-"):
        await _reply_v2(interaction, f"{e('cross')} You cannot close this ticket.", color=0xED4245)
        return

    await interaction.response.send_message("Closing ticket in 5 seconds...")

    # Collect full transcript (all messages including bot ones for context)
    messages = []
    msg_count = 0
    async for msg in channel.history(limit=500, oldest_first=True):
        msg_count += 1
        if not msg.author.bot:
            content = msg.content or "[attachment/embed]"
            messages.append(f"[{msg.created_at.strftime('%Y-%m-%d %H:%M')}] {msg.author}: {content}")
    transcript = "\n".join(messages) if messages else f"No user messages recorded ({msg_count} total)."

    # Send staff Discord logs
    await send_log(
        title=f"{e('ticket')} Ticket Closed",
        description=(
            f"**Channel** {channel.name}\n"
            f"**Closed by** {interaction.user.mention}\n"
            f"**Messages** {msg_count}"
        ),
        color=0xED4245,
        webhook_key="wh_tickets_closed",
    )
    if transcript:
        await send_log(
            title=f"Transcript - {channel.name}",
            description=f"```\n{transcript[:1900]}\n```",
            color=0x5865F2,
            webhook_key="wh_ticket_transcripts",
        )

    # DM the ticket opener with the full transcript as a file
    await _dm_ticket_closed(channel, interaction.user, transcript)

    # Stash cat_id before the channel is deleted (we need it for cleanup)
    closing_cat_id = _cat_id_for_channel(channel)

    await asyncio.sleep(5)
    await channel.delete(reason=f"Ticket closed by {interaction.user}")

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

        await send_log(
            title=f"{e('verify')} User Verified",
            description=(
                f"**User** {member.mention} (`{member.id}`)\n"
                f"**Key** `{key}`\n"
                f"**Product** {product}"
            ),
            color=0x57F287,
            webhook_key="wh_verifications",
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
            await send_log(
                title=f"{e('chip')} HWID Reset",
                description=f"**User** {interaction.user.mention} (`{interaction.user.id}`)",
                color=0xFEE75C,
                webhook_key="wh_hwid_resets",
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
        await send_log(
            title=f"{e('chip')} HWID Reset",
            description=f"**User** {interaction.user.mention} (`{interaction.user.id}`)",
            color=0xFEE75C,
            webhook_key="wh_hwid_resets",
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
