#!/usr/bin/env python3
"""
Void Bot - Public-facing Discord bot
Tickets, product panels, payment methods, changelogs, verification
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
from datetime import datetime, timezone
from typing import Optional
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

# ─── ENV / CONFIG ─────────────────────────────────────────────────────────────

def env(key: str, default=None):
    return os.environ.get(key, default)

def env_int(key: str, default: int = 0) -> int:
    val = os.environ.get(key, "").strip()
    try:
        return int(val) if val else default
    except ValueError:
        return default

CONFIG = {
    "token":               env("VOID_TOKEN",                    "YOUR_BOT_TOKEN"),
    "guild_id":            env_int("VOID_GUILD_ID"),
    "staff_role_id":       env_int("VOID_STAFF_ROLE_ID"),
    "admin_role_id":       env_int("VOID_ADMIN_ROLE_ID"),
    "ticket_category_id":  env_int("VOID_TICKET_CATEGORY_ID"),
    "verified_role_id":    env_int("VOID_VERIFIED_ROLE_ID"),
    "logo_url":            env("VOID_LOGO_URL",                 ""),
    "brand_name":          env("VOID_BRAND_NAME",               "Void"),
    "customer_cl_webhook": env("VOID_CUSTOMER_CHANGELOG_WEBHOOK", ""),
    "db_path":             env("DB_PATH",                       "/data/keylock.db"),
    "api_port":            env_int("VOID_PORT", env_int("PORT", 8081)),
}

# ─── LOGGING ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("VoidBot")

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def init_db(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            discord_id      TEXT PRIMARY KEY,
            key             TEXT UNIQUE NOT NULL,
            hwid            TEXT,
            product         TEXT NOT NULL DEFAULT 'default',
            status          TEXT NOT NULL DEFAULT 'active',
            registered_at   TEXT NOT NULL,
            expires_at      TEXT,
            hwid_resets     INTEGER NOT NULL DEFAULT 0,
            last_seen       TEXT,
            ip_last         TEXT,
            notes           TEXT,
            ban_reason      TEXT,
            fac_reset_auth  INTEGER NOT NULL DEFAULT 0,
            fac_auth_key    TEXT
        );
        CREATE TABLE IF NOT EXISTS key_pool (
            key         TEXT PRIMARY KEY,
            product     TEXT NOT NULL DEFAULT 'default',
            visibility  TEXT NOT NULL DEFAULT 'private',
            created_at  TEXT NOT NULL,
            expires_at  TEXT,
            claimed     INTEGER NOT NULL DEFAULT 0,
            created_by  TEXT,
            notes       TEXT
        );
        CREATE TABLE IF NOT EXISTS void_tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id  TEXT UNIQUE NOT NULL,
            guild_id    TEXT NOT NULL,
            user_id     TEXT NOT NULL,
            category    TEXT NOT NULL,
            claimed_by  TEXT,
            created_at  TEXT NOT NULL,
            closed_at   TEXT,
            status      TEXT NOT NULL DEFAULT 'open',
            transcript  TEXT
        );
    """)
    conn.commit()
    # Migrations
    for migration in [
        "ALTER TABLE key_pool ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'",
        "ALTER TABLE users ADD COLUMN fac_reset_auth INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN fac_auth_key TEXT",
    ]:
        try:
            conn.execute(migration)
            conn.commit()
        except Exception:
            pass
    log.info("Database ready: %s", path)
    return conn

DB: sqlite3.Connection = None

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# ─── EMOJI SYSTEM ─────────────────────────────────────────────────────────────

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

def _emoji_in_text(key: str) -> str:
    val = EMOJIS.get(key, "")
    return "" if "EMOJI_ID" in val else val

def _emoji_obj(name: str) -> dict:
    val = EMOJIS.get(name, "")
    if "EMOJI_ID" in val or not val:
        return {}
    m = re.match(r"<:(\w+):(\d+)>", val)
    return {"id": m.group(2), "name": m.group(1)} if m else {}

async def _setup_emojis(guild: discord.Guild) -> None:
    try:
        import cairosvg
    except ImportError:
        log.warning("cairosvg not installed - skipping emoji setup")
        return
    emoji_dir = os.path.join(os.path.dirname(__file__), "emojis")
    if not os.path.isdir(emoji_dir):
        return
    existing = {e.name: e for e in await guild.fetch_emojis()}
    for key, filename in _EMOJI_FILE_MAP.items():
        svg_path = os.path.join(emoji_dir, f"{filename}.svg")
        if not os.path.isfile(svg_path):
            continue
        if "EMOJI_ID" not in EMOJIS.get(key, "EMOJI_ID"):
            continue
        try:
            if filename in existing:
                e = existing[filename]
            else:
                png_bytes = cairosvg.svg2png(url=svg_path, output_width=128, output_height=128)
                e = await guild.create_custom_emoji(name=filename, image=png_bytes)
                log.info("Created emoji :%s: (id=%s)", e.name, e.id)
            EMOJIS[key] = f"<:{e.name}:{e.id}>"
        except Exception as exc:
            log.warning("Emoji setup failed for %s: %s", key, exc)

# ─── COMPONENTS V2 HELPERS ────────────────────────────────────────────────────

FLAGS_CV2 = 1 << 15

def _v2_banner() -> list:
    url = CONFIG.get("logo_url", "")
    if not url:
        return []
    return [{"type": 12, "items": [{"media": {"url": url}}]}]

def _v2_container(body: list, accent: int = 0x2b2d31) -> dict:
    return {
        "flags": FLAGS_CV2,
        "components": [{"type": 17, "accent_color": accent, "components": body}],
    }

def _v2_section(text: str, btn_label: str, btn_custom_id: str,
                btn_emoji_name: str = "", btn_style: int = 2) -> dict:
    btn: dict = {"type": 2, "style": btn_style, "label": btn_label, "custom_id": btn_custom_id}
    em = _emoji_obj(btn_emoji_name)
    if em:
        btn["emoji"] = em
    return {
        "type": 9,
        "components": [{"type": 10, "content": text}],
        "accessory": btn,
    }

# ─── REST HELPER ──────────────────────────────────────────────────────────────

async def _post_channel_v2(channel: discord.TextChannel, payload: dict) -> None:
    async with aiohttp.ClientSession() as session:
        url = f"https://discord.com/api/v10/channels/{channel.id}/messages"
        headers = {"Authorization": f"Bot {CONFIG['token']}", "Content-Type": "application/json"}
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status not in (200, 201):
                log.error("Panel post failed %s: %s", resp.status, await resp.text())

async def _post_webhook_v2(webhook_url: str, payload: dict) -> None:
    async with aiohttp.ClientSession() as session:
        p = {"flags": payload["flags"], "components": payload["components"]}
        async with session.post(webhook_url, json=p) as resp:
            if resp.status not in (200, 201, 204):
                log.error("Webhook post failed %s", resp.status)

# ─── CONFIG: TICKET CATEGORIES ────────────────────────────────────────────────

TICKET_CATEGORIES = {
    "support": {
        "label":     "Support",
        "desc":      "Product support or general enquiries",
        "emoji_key": "ticket",
    },
    "purchase": {
        "label":     "Purchase",
        "desc":      "Purchase or renew your subscription",
        "emoji_key": "key",
    },
    "management": {
        "label":     "Management",
        "desc":      "Management help and escalations",
        "emoji_key": "shield",
    },
    "media": {
        "label":     "Media",
        "desc":      "Media enquiries",
        "emoji_key": "arrow",
    },
}

# ─── CONFIG: PRODUCTS ─────────────────────────────────────────────────────────

PRODUCTS = {
    "public": {
        "label":       "Public Bypass",
        "tag":         "STANDARD TIER",
        "desc":        (
            "Our public build delivers strong, reliable performance for everyday use. "
            "Active and consistent users may later qualify for access to our private build."
        ),
        "invite_only": False,
        "image_url":   env("VOID_PUBLIC_IMAGE_URL", ""),
        "features": [
            "Windows 10 / 11 compatible",
            "Fully streamproof - NVIDIA, AMD, Discord, OBS, AnyDesk",
            "Taskbar and Alt Tab proof",
            "Bypasses all scanners and checking tools",
            "User friendly GUI",
            "Force crack, force freeze, and more exclusive features",
            "Anti AnyDesk / RustDesk / TeamViewer",
            "Destruction in under a second",
        ],
        "pricing": [
            ("1 Month",  "$45"),
            ("3 Months", "$110"),
            ("Lifetime", "$250"),
        ],
        "accent":    0x5865F2,
        "emoji_key": "shield",
    },
    "private": {
        "label":       "Private Bypass",
        "tag":         "INVITE ONLY",
        "desc":        (
            "Our private build is reserved for trusted, vetted users. "
            "Access is granted exclusively through existing private members or staff - "
            "a more advanced, refined experience with a strictly limited user base."
        ),
        "invite_only": True,
        "image_url":   env("VOID_PRIVATE_IMAGE_URL", ""),
        "features": [
            "Windows 10 / 11 compatible",
            "Fully streamproof - NVIDIA, AMD, Discord, OBS, AnyDesk",
            "Taskbar and Alt Tab proof",
            "Bypasses all scanners and checking tools",
            "User friendly GUI",
            "Advanced exclusive features not in public build",
            "Force crack, force freeze, and more",
            "Anti AnyDesk / RustDesk / TeamViewer",
            "Destruction in under a second",
        ],
        "pricing": [
            ("1 Month",  "$70"),
            ("3 Months", "$195"),
            ("6 Months", "$270"),
            ("Lifetime", "$325"),
        ],
        "accent":    0xFEE75C,
        "emoji_key": "lock",
    },
}

# ─── PANEL PAYLOADS ───────────────────────────────────────────────────────────

def _ticket_panel_payload() -> dict:
    em_ticket = _emoji_in_text("ticket")
    em_dot    = _emoji_in_text("dot")
    pfx    = f"{em_ticket} " if em_ticket else "\U0001f3ab "
    bullet = f"{em_dot} "   if em_dot   else "- "

    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"## {pfx}Void Tickets\n"
        "-# Choose a category. A private channel opens and staff meet you there."
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
            f"void_ticket_open_{cat_id}",
            btn_emoji_name=cat["emoji_key"],
        ))
    return _v2_container(body, accent=0x5865F2)


def _product_panel_payload(product_id: str) -> dict:
    p        = PRODUCTS[product_id]
    brand    = CONFIG.get("brand_name", "Void")
    em_dot   = _emoji_in_text("dot")
    em_warn  = _emoji_in_text("warn")
    em_lock  = _emoji_in_text("lock")
    em_key   = _emoji_in_text("key")
    em_prod  = _emoji_in_text(p["emoji_key"])
    bullet   = f"{em_dot} "   if em_dot   else "- "
    warn_pfx = f"{em_warn} "  if em_warn  else "⚠️ "
    lock_pfx = f"{em_lock} "  if em_lock  else "\U0001f512 "
    key_pfx  = f"{em_key} "   if em_key   else "\U0001f511 "
    prod_pfx = f"{em_prod} "  if em_prod  else ""

    # Header: emoji inline with ## heading, brand tag as subtext
    header_txt = f"## {prod_pfx}{p['label']}\n-# {brand.upper()} - {p['tag']}"

    body: list = []
    body.extend(_v2_banner())

    # Header block - with thumbnail if image URL is set
    img = p.get("image_url", "")
    if img:
        body.append({
            "type": 9,
            "components": [{"type": 10, "content": header_txt}],
            "accessory": {
                "type": 11,
                "media": {"url": img},
                "description": p["label"],
            },
        })
    else:
        body.append({"type": 10, "content": header_txt})

    # About section
    body.append({"type": 14})
    body.append({"type": 10, "content": f"{prod_pfx}**ABOUT**\n{bullet}{p['desc']}"})

    # Invite only warning block
    if p["invite_only"]:
        body.append({"type": 14})
        body.append({"type": 10, "content": (
            f"{lock_pfx}**INVITE ONLY**\n"
            f"{bullet}Access granted through existing private members or staff only.\n"
            f"{bullet}Not available for direct purchase."
        )})

    # Features
    body.append({"type": 14})
    features_txt = "\n".join(f"{bullet}{f}" for f in p["features"])
    body.append({"type": 10, "content": f"{prod_pfx}**FEATURES**\n{features_txt}"})

    # Pricing
    body.append({"type": 14})
    pricing_lines = [f"{bullet}**{label}** - {price}" for label, price in p["pricing"]]
    body.append({"type": 10, "content": f"{key_pfx}**PRICING**\n" + "\n".join(pricing_lines)})

    # CTA button section
    body.append({"type": 14})
    if p["invite_only"]:
        body.append(_v2_section(
            f"{warn_pfx}**REQUEST ACCESS**\n{bullet}Contact staff or an existing private member to get an invite.",
            "OPEN TICKET",
            "void_ticket_open_purchase",
            btn_emoji_name="key",
            btn_style=3,
        ))
    else:
        body.append(_v2_section(
            f"{key_pfx}**SECURE YOUR ACCESS**\n{bullet}Start your order by opening a support ticket.",
            "BUY NOW",
            "void_ticket_open_purchase",
            btn_emoji_name="key",
            btn_style=3,
        ))
    return _v2_container(body, accent=p["accent"])


def _payment_panel_payload() -> dict:
    em_key   = _emoji_in_text("key")
    em_warn  = _emoji_in_text("warn")
    em_dot   = _emoji_in_text("dot")
    em_cross = _emoji_in_text("cross")
    pfx    = f"{em_key} "   if em_key   else "\U0001f4b3 "
    warn   = f"{em_warn} "  if em_warn  else "⚠️ "
    bullet = f"{em_dot} "   if em_dot   else "- "
    cross  = f"{em_cross} " if em_cross else "❌ "

    body: list = []
    body.extend(_v2_banner())
    body.append({"type": 10, "content": (
        f"## {pfx}Payment Methods\n"
        "-# All prices are in USD only."
    )})
    body.append({"type": 14})
    body.append({"type": 10, "content": (
        f"{bullet}**PayPal** (Friends & Family)\n"
        f"{bullet}**Bank Transfer**\n"
        f"{bullet}**CashApp**\n"
        f"{bullet}**Giftcard**\n"
        f"{bullet}**Crypto**"
    )})
    body.append({"type": 14})
    body.append({"type": 10, "content": (
        f"{warn}**ALL PAYMENTS MUST BE CONFIRMED BY STAFF ONLY.**\n"
        "If anyone claims they can get you access otherwise, report it to management immediately.\n\n"
        f"{cross}**Chargebacks void your license with no refund.**"
    )})
    body.append({"type": 14})
    body.append({"type": 10, "content": (
        "-# Have a question about another payment method? Open a support ticket."
    )})
    return _v2_container(body, accent=0x57F287)


def _verify_panel_payload() -> dict:
    em_lock   = _emoji_in_text("lock")
    em_key    = _emoji_in_text("key")
    em_verify = _emoji_in_text("verify")
    em_dot    = _emoji_in_text("dot")
    lock_pfx   = f"{em_lock} "   if em_lock   else "\U0001f512 "
    key_pfx    = f"{em_key} "    if em_key    else "\U0001f511 "
    verify_pfx = f"{em_verify} " if em_verify else ""
    bullet     = f"{em_dot} "    if em_dot    else "- "

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
        "void_verify_button",
        btn_emoji_name="verify",
        btn_style=3,
    ))
    return _v2_container(body, accent=0x57F287)


def _changelog_payload(product_ref: str, date: str, added: str, removed: str) -> dict:
    em_bell = _emoji_in_text("bell")
    bell_pfx = f"{em_bell} " if em_bell else "\U0001f514 "

    added_lines   = "\n".join(f"\x1b[2;32m{l}\x1b[0m" for l in added.strip().splitlines() if l.strip())
    removed_lines = (
        "\n".join(f"\x1b[2;31m{l}\x1b[0m" for l in removed.strip().splitlines() if l.strip())
        if removed.strip() else ""
    )

    body: list = []
    body.append({"type": 10, "content": f"## {bell_pfx}New Changelog"})
    body.append({"type": 14})
    body.append({"type": 10, "content": f"**Product:** {product_ref}\n**Date:** {date}"})
    body.append({"type": 14})
    body.append({"type": 10, "content": f"**Added:**\n```ansi\n{added_lines}\n```"})
    if removed_lines:
        body.append({"type": 14})
        body.append({"type": 10, "content": f"**Removed:**\n```ansi\n{removed_lines}\n```"})
    body.append({"type": 14})
    body.append({"type": 10, "content": "-# Review and share feedback in the appropriate channel."})
    return _v2_container(body, accent=0x5865F2)

# ─── TICKET SYSTEM ────────────────────────────────────────────────────────────

_ticket_lock = asyncio.Lock()

async def _next_ticket_number(guild_id: int) -> int:
    row = DB.execute(
        "SELECT COUNT(*) AS cnt FROM void_tickets WHERE guild_id=?", (str(guild_id),)
    ).fetchone()
    return (row["cnt"] or 0) + 1


async def _open_ticket(interaction: discord.Interaction, category_id: str) -> None:
    async with _ticket_lock:
        cat = TICKET_CATEGORIES.get(category_id)
        if not cat:
            await interaction.response.send_message("Unknown category.", ephemeral=True)
            return

        # Check for existing open ticket in this category
        existing = DB.execute(
            "SELECT channel_id FROM void_tickets WHERE user_id=? AND guild_id=? AND category=? AND status='open'",
            (str(interaction.user.id), str(interaction.guild.id), category_id)
        ).fetchone()
        if existing:
            ch = interaction.guild.get_channel(int(existing["channel_id"]))
            if ch:
                await interaction.response.send_message(
                    f"You already have an open {cat['label']} ticket: {ch.mention}", ephemeral=True
                )
                return

        await interaction.response.defer(ephemeral=True)

        guild = interaction.guild
        num   = await _next_ticket_number(guild.id)

        # Resolve ticket category channel
        ticket_cat = None
        cat_id_cfg = CONFIG.get("ticket_category_id", 0)
        if cat_id_cfg:
            ticket_cat = guild.get_channel(cat_id_cfg)
        if not ticket_cat:
            for c in guild.categories:
                if c.name.upper() in ("TICKETS", "TICKET", "VOID TICKETS"):
                    ticket_cat = c
                    break
        if not ticket_cat:
            ticket_cat = await guild.create_category("TICKETS")

        # Permissions
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            interaction.user:   discord.PermissionOverwrite(
                read_messages=True, send_messages=True, attach_files=True, embed_links=True
            ),
            guild.me: discord.PermissionOverwrite(
                read_messages=True, send_messages=True, manage_channels=True, manage_messages=True
            ),
        }
        staff_role_id  = CONFIG.get("staff_role_id", 0)
        admin_role_id  = CONFIG.get("admin_role_id", 0)
        for role_id in (staff_role_id, admin_role_id):
            if role_id:
                role = guild.get_role(role_id)
                if role:
                    overwrites[role] = discord.PermissionOverwrite(
                        read_messages=True, send_messages=True,
                        manage_messages=True, manage_channels=True
                    )

        channel = await ticket_cat.create_text_channel(
            name=f"{category_id}-{num:04d}",
            overwrites=overwrites,
            topic=f"Ticket #{num:04d} | {cat['label']} | {interaction.user.display_name}",
        )

        DB.execute(
            "INSERT INTO void_tickets (channel_id, guild_id, user_id, category, created_at) VALUES (?,?,?,?,?)",
            (str(channel.id), str(guild.id), str(interaction.user.id), category_id, now_iso())
        )
        DB.commit()

        # Build opening panel
        em_ticket = _emoji_in_text("ticket")
        em_dot    = _emoji_in_text("dot")
        pfx    = f"{em_ticket} " if em_ticket else "\U0001f3ab "
        bullet = f"{em_dot} "   if em_dot   else "- "

        body: list = []
        body.append({"type": 10, "content": (
            f"## {pfx}Ticket #{num:04d} - {cat['label']}\n"
            f"-# Opened by {interaction.user.mention}"
        )})
        body.append({"type": 14})
        body.append({"type": 10, "content": (
            f"{bullet}Describe your issue or request below.\n"
            f"{bullet}Staff will be with you shortly.\n"
            f"{bullet}Use the **Close** button when resolved."
        )})

        payload = _v2_container(body, accent=0x5865F2)
        await _post_channel_v2(channel, payload)

        # Ping row with control buttons
        mention_parts = [interaction.user.mention]
        if staff_role_id:
            mention_parts.append(f"<@&{staff_role_id}>")
        await channel.send(content=" ".join(mention_parts), view=TicketControlView())

        await interaction.followup.send(
            f"Your ticket has been opened: {channel.mention}", ephemeral=True
        )
        log.info("Opened ticket %04d (%s) for %s", num, category_id, interaction.user.id)


class TicketControlView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Claim", style=discord.ButtonStyle.primary,
                       custom_id="void_ticket_claim", emoji="\U0001f4cc")
    async def claim(self, interaction: discord.Interaction, button: discord.ui.Button):
        staff_role_id = CONFIG.get("staff_role_id", 0)
        admin_role_id = CONFIG.get("admin_role_id", 0)
        is_staff = any(r.id in (staff_role_id, admin_role_id) for r in interaction.user.roles)
        if not is_staff and staff_role_id:
            await interaction.response.send_message("Only staff can claim tickets.", ephemeral=True)
            return
        DB.execute(
            "UPDATE void_tickets SET claimed_by=? WHERE channel_id=?",
            (str(interaction.user.id), str(interaction.channel.id))
        )
        DB.commit()
        try:
            await interaction.channel.edit(
                topic=interaction.channel.topic + f" | Claimed by {interaction.user.display_name}"
            )
        except Exception:
            pass
        await interaction.response.send_message(
            f"\U0001f4cc **Claimed by {interaction.user.mention}**"
        )

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger,
                       custom_id="void_ticket_close", emoji="\U0001f512")
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        # Build transcript
        lines = []
        async for msg in interaction.channel.history(limit=500, oldest_first=True):
            ts = msg.created_at.strftime("%Y-%m-%d %H:%M")
            content = msg.content or ("[embed]" if msg.embeds else "[attachment]")
            lines.append(f"[{ts}] {msg.author.display_name}: {content}")
        transcript = "\n".join(lines)

        DB.execute(
            "UPDATE void_tickets SET status='closed', closed_at=?, transcript=? WHERE channel_id=?",
            (now_iso(), transcript, str(interaction.channel.id))
        )
        DB.commit()

        await interaction.followup.send("Closing in 5 seconds...")
        await asyncio.sleep(5)
        try:
            await interaction.channel.delete(reason=f"Closed by {interaction.user.display_name}")
        except Exception as e:
            log.warning("Channel delete failed: %s", e)

# ─── VERIFICATION SYSTEM ──────────────────────────────────────────────────────

class VerifyModal(discord.ui.Modal, title="License Verification"):
    key_input = discord.ui.TextInput(
        label="License Key",
        placeholder="e.g. KL-XXXXX-XXXXX-XXXXX-XXXXX",
        min_length=5,
        max_length=64,
        style=discord.TextStyle.short,
    )

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        key     = self.key_input.value.strip().upper()
        user_id = str(interaction.user.id)

        already = DB.execute("SELECT discord_id FROM users WHERE discord_id=?", (user_id,)).fetchone()
        if already:
            await interaction.followup.send("Your account is already verified.", ephemeral=True)
            return

        pool_row = DB.execute("SELECT * FROM key_pool WHERE key=? AND claimed=0", (key,)).fetchone()
        user_row = DB.execute("SELECT * FROM users WHERE key=?", (key,)).fetchone()

        if not pool_row and not user_row:
            await interaction.followup.send(
                "Invalid or already-claimed key. Check your key and try again.", ephemeral=True
            )
            return

        if user_row and user_row["discord_id"] != user_id:
            await interaction.followup.send(
                "That key is already linked to another account.", ephemeral=True
            )
            return

        if pool_row:
            DB.execute(
                """INSERT OR IGNORE INTO users
                   (discord_id, key, product, status, registered_at, expires_at)
                   VALUES (?,?,?,?,?,?)""",
                (user_id, key, pool_row["product"], "active", now_iso(), pool_row["expires_at"])
            )
            DB.execute("UPDATE key_pool SET claimed=1 WHERE key=?", (key,))
            DB.commit()

        verified_role_id = CONFIG.get("verified_role_id", 0)
        if verified_role_id:
            role = interaction.guild.get_role(verified_role_id)
            if role:
                try:
                    await interaction.user.add_roles(role, reason="Verified via Void Bot")
                except Exception as e:
                    log.warning("Could not assign verified role: %s", e)

        await interaction.followup.send(
            "Your license has been verified. Welcome.", ephemeral=True
        )
        log.info("Verified user %s with key %s***", user_id, key[:8])

# ─── CHANGELOG MODAL ──────────────────────────────────────────────────────────

class ChangelogModal(discord.ui.Modal, title="Post Changelog"):
    product_input = discord.ui.TextInput(
        label="Product / Channel",
        placeholder="e.g. #fivem-external or Public Bypass",
        max_length=100,
        style=discord.TextStyle.short,
    )
    date_input = discord.ui.TextInput(
        label="Date",
        placeholder="e.g. 2026/11/22",
        max_length=20,
        style=discord.TextStyle.short,
    )
    added_input = discord.ui.TextInput(
        label="Added / Changed",
        placeholder="One change per line",
        style=discord.TextStyle.paragraph,
        max_length=1000,
    )
    removed_input = discord.ui.TextInput(
        label="Removed (optional)",
        placeholder="One item per line",
        style=discord.TextStyle.paragraph,
        required=False,
        max_length=500,
    )

    def __init__(self, channel: discord.TextChannel):
        super().__init__()
        self._channel = channel
        self.date_input.default = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        product_ref = self.product_input.value.strip()
        date        = self.date_input.value.strip()
        added       = self.added_input.value.strip()
        removed     = (self.removed_input.value or "").strip()

        payload = _changelog_payload(product_ref, date, added, removed)
        await _post_channel_v2(self._channel, payload)

        wh = CONFIG.get("customer_cl_webhook", "")
        sent_to_customer = False
        if wh:
            try:
                await _post_webhook_v2(wh, payload)
                sent_to_customer = True
            except Exception as e:
                log.warning("Customer changelog webhook failed: %s", e)

        note = " Also posted to customer Discord." if sent_to_customer else ""
        await interaction.followup.send(f"Changelog posted.{note}", ephemeral=True)

# ─── BOT SETUP ────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

def _is_staff(interaction: discord.Interaction) -> bool:
    ids = {CONFIG.get("staff_role_id", 0), CONFIG.get("admin_role_id", 0)} - {0}
    return any(r.id in ids for r in interaction.user.roles)

def _guild_obj() -> Optional[discord.Object]:
    gid = CONFIG.get("guild_id", 0)
    return discord.Object(id=gid) if gid else None

@bot.event
async def on_ready():
    global DB
    if DB is None:
        DB = init_db(CONFIG["db_path"])
    log.info("Void Bot ready: %s", bot.user)
    guild = bot.get_guild(CONFIG["guild_id"])
    if guild:
        await _setup_emojis(guild)
    bot.add_view(TicketControlView())
    g = _guild_obj()
    await tree.sync(guild=g)
    log.info("Commands synced to guild %s", CONFIG["guild_id"])

@bot.event
async def on_interaction(interaction: discord.Interaction):
    if interaction.type != discord.InteractionType.component:
        return
    cid = interaction.data.get("custom_id", "")

    # Ticket open buttons
    if cid.startswith("void_ticket_open_"):
        cat = cid.removeprefix("void_ticket_open_")
        await _open_ticket(interaction, cat)
        return

    # Ticket claim / close (handled by TicketControlView persistent view)
    if cid in ("void_ticket_claim", "void_ticket_close"):
        return

    # Verify button
    if cid == "void_verify_button":
        await interaction.response.send_modal(VerifyModal())
        return

# ─── SLASH COMMANDS ───────────────────────────────────────────────────────────

@tree.command(name="tickets", description="Post the ticket panel", guild=_guild_obj())
async def cmd_tickets(interaction: discord.Interaction):
    if not _is_staff(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _ticket_panel_payload())
    await interaction.followup.send("Ticket panel posted.", ephemeral=True)


@tree.command(name="product", description="Post a product panel", guild=_guild_obj())
@app_commands.describe(product="Which product to post")
@app_commands.choices(product=[
    app_commands.Choice(name="Public Bypass",  value="public"),
    app_commands.Choice(name="Private Bypass", value="private"),
])
async def cmd_product(interaction: discord.Interaction, product: str):
    if not _is_staff(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _product_panel_payload(product))
    await interaction.followup.send(f"{product.capitalize()} product panel posted.", ephemeral=True)


@tree.command(name="payment", description="Post the payment methods panel", guild=_guild_obj())
async def cmd_payment(interaction: discord.Interaction):
    if not _is_staff(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _payment_panel_payload())
    await interaction.followup.send("Payment panel posted.", ephemeral=True)


@tree.command(name="verify", description="Post the verification panel", guild=_guild_obj())
async def cmd_verify(interaction: discord.Interaction):
    if not _is_staff(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    await _post_channel_v2(interaction.channel, _verify_panel_payload())
    await interaction.followup.send("Verification panel posted.", ephemeral=True)


@tree.command(name="changelog", description="Post a changelog (also sends to customer Discord)", guild=_guild_obj())
async def cmd_changelog(interaction: discord.Interaction):
    if not _is_staff(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return
    await interaction.response.send_modal(ChangelogModal(interaction.channel))


@tree.command(name="setup", description="Auto-create all Void Bot channels", guild=_guild_obj())
async def cmd_setup(interaction: discord.Interaction):
    if not _is_staff(interaction):
        await interaction.response.send_message("No permission.", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    # Find or create VOID BOT category
    void_cat = None
    for c in guild.categories:
        if c.name.upper() in ("VOID BOT", "VOID", "BOT"):
            void_cat = c
            break
    if not void_cat:
        void_cat = await guild.create_category("VOID BOT")

    created = []
    for ch_name in ("verify", "tickets", "product-public", "product-private",
                    "payment-methods", "changelogs", "rules"):
        if not discord.utils.get(void_cat.channels, name=ch_name):
            await guild.create_text_channel(ch_name, category=void_cat)
            created.append(ch_name)

    msg = f"Setup complete. Category: **{void_cat.name}**."
    if created:
        msg += f" Created: {', '.join('#' + c for c in created)}."
    await interaction.followup.send(msg, ephemeral=True)

# ─── HEALTH CHECK ─────────────────────────────────────────────────────────────

class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *args):
        pass

def _run_health(port: int):
    HTTPServer(("0.0.0.0", port), _Health).serve_forever()

# ─── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = CONFIG["api_port"]
    threading.Thread(target=_run_health, args=(port,), daemon=True).start()
    log.info("Health check on :%d", port)
    bot.run(CONFIG["token"])
