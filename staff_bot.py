"""
KeyLock Staff Bot
-----------------
Ticket system linked to the main KeyLock bot via shared SQLite DB.

Ticket types:
  - HWID reset (free)      -> staff approves -> main bot auto-runs /fac reset_free
  - HWID reset (paid)      -> staff marks paid -> main bot auto-runs /fac reset_paid + role
  - FAC auth (free)        -> staff approves -> main bot auto-runs /fac authorize_free
  - FAC auth (paid)        -> staff marks paid -> main bot auto-runs /fac authorize_paid + role
  - General                -> staff handles in thread, closes manually

Both bots point at the same DB_PATH volume on Railway.
All ticket actions are logged to the main server via LOG_WEBHOOK_URL.
"""

import os
import sqlite3
import logging
import asyncio
import aiohttp
import hashlib
import secrets
import string
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import discord
from discord import app_commands
from discord.ext import tasks, commands

# ─── CONFIG ───────────────────────────────────────────────────────────────────

def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip()

def env_int(key: str, default: int = 0) -> int:
    val = os.environ.get(key, "").strip()
    try:
        return int(val) if val else default
    except ValueError:
        return default

CONFIG = {
    "token":               env("DISCORD_TOKEN"),
    "guild_id":            env_int("GUILD_ID"),
    "admin_role_id":       env_int("ADMIN_ROLE_ID"),
    "ticket_category_id":  env_int("TICKET_CATEGORY_ID"),
    "log_channel_id":      env_int("LOG_CHANNEL_ID"),
    "log_webhook_url":     env("LOG_WEBHOOK_URL"),
    "db_path":             env("DB_PATH", "/data/keylock.db"),
    "main_guild_id":       env_int("MAIN_GUILD_ID"),
    "void_guild_id":       env_int("VOID_GUILD_ID"),
    # keys shared with main bot commands
    "loader_log_channel_id": env_int("LOADER_LOG_CHANNEL_ID"),
    "verified_role_id":    env_int("VERIFIED_ROLE_ID"),
    "banned_role_id":      env_int("BANNED_ROLE_ID"),
    "fac_paid_role_id":    env_int("FAC_PAID_ROLE_ID"),
    "hwid_paid_role_id":   env_int("HWID_PAID_ROLE_ID"),
    "max_hwid_resets":     env_int("MAX_HWID_RESETS", 1),
    "key_prefix":          env("KEY_PREFIX", "KL"),
    "api_port":            env_int("PORT", 8080),
}

# ─── LOGGING ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("staffbot.log"), logging.StreamHandler()],
)
log = logging.getLogger("StaffBot")

# ─── DATABASE ─────────────────────────────────────────────────────────────────

DB: sqlite3.Connection = None

def init_db(path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    # Shared tables: void_bot owns schema, staff_bot uses IF NOT EXISTS as a safety net
    # (in case staff_bot starts before void_bot on first deploy)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS tickets (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_num      TEXT NOT NULL DEFAULT '0000',
            channel_id      TEXT UNIQUE NOT NULL,
            guild_id        TEXT NOT NULL DEFAULT '',
            bot_source      TEXT NOT NULL DEFAULT 'staff',
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
            resolution      TEXT,
            transcript      TEXT,
            notes           TEXT
        );
        CREATE TABLE IF NOT EXISTS ticket_messages (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id   INTEGER NOT NULL REFERENCES tickets(id),
            author_id   TEXT NOT NULL,
            content     TEXT NOT NULL,
            timestamp   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payments (
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
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            bot_source  TEXT NOT NULL DEFAULT 'staff',
            action      TEXT NOT NULL,
            actor_id    TEXT,
            target_id   TEXT,
            detail      TEXT
        );
    """)
    conn.commit()
    # Schema guards in case void_bot added columns staff_bot's minimal CREATE missed
    for _migration in [
        "ALTER TABLE tickets ADD COLUMN ticket_num TEXT NOT NULL DEFAULT '0000'",
        "ALTER TABLE tickets ADD COLUMN guild_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE tickets ADD COLUMN bot_source TEXT NOT NULL DEFAULT 'staff'",
        "ALTER TABLE tickets ADD COLUMN category TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE tickets ADD COLUMN type TEXT",
        "ALTER TABLE tickets ADD COLUMN closed_by TEXT",
        "ALTER TABLE tickets ADD COLUMN payment_status TEXT NOT NULL DEFAULT 'none'",
        "ALTER TABLE tickets ADD COLUMN invoice_id TEXT",
        "ALTER TABLE tickets ADD COLUMN paid_at TEXT",
        "ALTER TABLE tickets ADD COLUMN resolution TEXT",
        "ALTER TABLE tickets ADD COLUMN transcript TEXT",
        "ALTER TABLE tickets ADD COLUMN assigned_to TEXT",
        "ALTER TABLE payments ADD COLUMN amount TEXT",
        "ALTER TABLE payments ADD COLUMN method TEXT",
        "ALTER TABLE audit_log ADD COLUMN bot_source TEXT NOT NULL DEFAULT 'staff'",
        "ALTER TABLE key_pool ADD COLUMN invoice_id TEXT",
    ]:
        try:
            conn.execute(_migration)
            conn.commit()
        except Exception:
            pass
    return conn

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

async def _get_member(guild: discord.Guild, user_id: int) -> Optional[discord.Member]:
    """Fetch a guild member by ID, returns None if not in server."""
    m = guild.get_member(user_id)
    if m:
        return m
    try:
        return await guild.fetch_member(user_id)
    except (discord.NotFound, discord.HTTPException):
        return None

def audit_staff(action: str, actor_id: str = None, target_id: str = None, detail: str = None):
    DB.execute(
        "INSERT INTO audit_log (timestamp, bot_source, action, actor_id, target_id, detail) VALUES (?,?,?,?,?,?)",
        (now_iso(), 'staff', action, actor_id, target_id, detail)
    )
    DB.commit()

# ─── KEY / HWID UTILITIES ─────────────────────────────────────────────────────

def hash_hwid(raw: str) -> str:
    return hashlib.sha256(raw.strip().lower().encode()).hexdigest()

def gen_key(prefix: str = "KL", segments: int = 4, seg_len: int = 5) -> str:
    charset = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(charset) for _ in range(seg_len)) for _ in range(segments)]
    return f"{prefix}-" + "-".join(parts)

def gen_fac_key() -> str:
    charset = string.ascii_uppercase + string.digits
    token = "".join(secrets.choice(charset) for _ in range(16))
    return f"FAC-{token[:4]}-{token[4:8]}-{token[8:12]}-{token[12:16]}"

async def _member_in_guilds(bot: "StaffBot", user_id: int, *guild_ids: int) -> tuple[bool, str]:
    """
    Check if user_id is a member of any of the given guild IDs.
    Returns (found: bool, reason: str).
    Bot must be in those guilds for the check to work.
    """
    checked = False
    for gid in guild_ids:
        if not gid:
            continue
        guild = bot.get_guild(gid)
        if not guild:
            continue
        checked = True
        try:
            member = guild.get_member(user_id) or await guild.fetch_member(user_id)
            if member:
                return True, f"member of {guild.name}"
        except discord.NotFound:
            pass
        except Exception as e:
            log.warning("Member check failed guild=%s user=%s: %s", gid, user_id, e)
    if not checked:
        return True, "guilds not reachable by this bot - skipping check"
    return False, "not a member of customer or void Discord"

# ─── EMBED HELPERS ────────────────────────────────────────────────────────────

def err_embed(title: str, desc: str) -> discord.Embed:
    return discord.Embed(title=title, description=desc, color=discord.Color.red())

def ok_embed(title: str, desc: str = None) -> discord.Embed:
    return discord.Embed(title=title, description=desc, color=discord.Color.green())

def warn_embed(title: str, desc: str) -> discord.Embed:
    return discord.Embed(title=title, description=desc, color=discord.Color.orange())

BRAND_COLOR = discord.Color(0xFF69B4)  # Staff brand pink

TICKET_COLORS = {
    "hwid_free":  discord.Color.blue(),
    "hwid_paid":  discord.Color.gold(),
    "fac_free":   discord.Color.purple(),
    "fac_paid":   discord.Color.gold(),
    "general":    BRAND_COLOR,
}

TICKET_LABELS = {
    "hwid_free":  "HWID Reset (Free)",
    "hwid_paid":  "HWID Reset (Paid)",
    "fac_free":   "FAC Auth (Free)",
    "fac_paid":   "FAC Auth (Paid)",
    "general":    "General Support",
}

# ─── DISCORD COMPONENT V2 HELPERS ─────────────────────────────────────────────

FLAGS_CV2 = 1 << 15  # IS_COMPONENTS_V2 message flag

def _sv2_container(body: list, accent: int = 0xFF69B4) -> dict:
    """Wrap body components in a V2 container."""
    return {
        "flags": FLAGS_CV2,
        "components": [{"type": 17, "accent_color": accent, "components": body}],
    }

def _sv2_text(content: str) -> dict:
    return {"type": 10, "content": content}

def _sv2_sep(divider: bool = True, spacing: int = 1) -> dict:
    return {"type": 14, "divider": divider, "spacing": spacing}

def _sv2_section(text: str, btn_label: str, btn_custom_id: str, btn_style: int = 2) -> dict:
    return {
        "type": 9,
        "components": [_sv2_text(text)],
        "accessory": {
            "type": 2,
            "style": btn_style,
            "label": btn_label,
            "custom_id": btn_custom_id,
        },
    }

async def _staff_post_v2(channel: discord.TextChannel, payload: dict) -> int | None:
    """POST a V2 component message to a channel and return the message ID."""
    async with aiohttp.ClientSession() as session:
        url = f"https://discord.com/api/v10/channels/{channel.id}/messages"
        headers = {
            "Authorization": f"Bot {CONFIG['token']}",
            "Content-Type": "application/json",
        }
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status in (200, 201):
                data = await resp.json()
                return int(data["id"])
            text = await resp.text()
            log.error("[v2_post] %s %s", resp.status, text)
            return None

def _build_infoboard_payload() -> dict:
    """Build the staff info/command reference panel as a V2 component payload."""
    accent = 0xFF69B4  # Staff pink
    body: list = []

    # Header
    body.append(_sv2_text(
        "# 048 Staff Panel\n"
        "-# Internal command reference and system overview."
    ))
    body.append(_sv2_sep())

    # Ticket management
    body.append(_sv2_text(
        "## Ticket Management\n"
        "- `/panel [channel]` - Post the ticket creation panel to a channel\n"
        "- `/tickets [status]` - List tickets by status (open / approved / closed)\n"
        "- `/ticketlookup <user>` - Full ticket + license summary for a user\n"
        "- `/addnote <user> <note>` - Attach a note to a user's license record\n"
        "-# Ticket types: HWID Reset (Free/Paid) - FAC Auth (Free/Paid) - General"
    ))
    body.append(_sv2_sep())

    # User / license management
    body.append(_sv2_text(
        "## User Management\n"
        "- `/lookup <user>` - Full user record across all bots\n"
        "- `/ban <user> [reason]` - Ban a user from the service\n"
        "- `/unban <user>` - Remove a service ban\n"
        "- `/revoke <user>` - Revoke a user's license key\n"
        "- `/resethwid <user>` - Manually reset HWID binding\n"
        "- `/hwid <user>` - View current HWID for a user\n"
        "- `/extend <user> <days>` - Extend license expiry by N days\n"
        "- `/setproduct <user> <product>` - Change a user's product tier\n"
        "- `/grantresets <user> <count>` - Grant extra HWID reset credits\n"
        "- `/wipeuser <user>` - Permanently wipe all data for a user"
    ))
    body.append(_sv2_sep())

    # Key management
    body.append(_sv2_text(
        "## Key Management\n"
        "- `/keygen <product> <days> [count]` - Generate one or more license keys\n"
        "- `/listkeys [product]` - List keys in the pool (unused)\n"
        "- `/deletekey <key>` - Remove a key from the pool\n"
        "- `/listusers [product]` - List all registered users\n"
        "- `/purgeexpired` - Remove all expired license records"
    ))
    body.append(_sv2_sep())

    # System commands
    body.append(_sv2_text(
        "## System Commands\n"
        "- `/stats` - Live DB snapshot: users, keys, tickets, logins\n"
        "- `/auditlog [count]` - View recent staff audit log entries\n"
        "- `/announce <channel> <message>` - Broadcast a message to a channel\n"
        "- `/register <user> <key>` - Manually register a user to a key\n"
        "- `/mystatus` - Check your own license status\n"
        "- `/fac <user>` - View or manage FAC auth state\n"
        "- `/pin <message_id>` - Pin a message in the current channel\n"
        "- `/invite` - Get a bot invite link"
    ))
    body.append(_sv2_sep())

    # Notes footer
    body.append(_sv2_text(
        "-# All commands require the Staff role.\n"
        "-# Lookup and ban commands search across all Discord servers the bot is in.\n"
        "-# Ticket transcripts and audit logs are stored in the shared database."
    ))

    return _sv2_container(body, accent=accent)

# ─── WEBHOOK LOG (cross-bot to main server) ───────────────────────────────────

async def webhook_log(embed: discord.Embed):
    """Post an embed to the main server log channel via webhook."""
    url = CONFIG.get("log_webhook_url")
    if not url:
        return
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "embeds": [{
                    "title":       embed.title,
                    "description": embed.description or "",
                    "color":       embed.color.value if embed.color else 0x5865F2,
                    "fields":      [{"name": f.name, "value": f.value, "inline": f.inline} for f in embed.fields],
                    "footer":      {"text": embed.footer.text} if embed.footer.text else {},
                    "timestamp":   datetime.now(timezone.utc).isoformat(),
                }]
            }
            await session.post(url, json=payload)
    except Exception as ex:
        log.warning("Webhook log failed: %s", ex)

# ─── BOT ──────────────────────────────────────────────────────────────────────

class StaffBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        g = discord.Object(id=CONFIG["guild_id"])
        self.tree.copy_global_to(guild=g)
        stale_checker.start()

    async def on_ready(self):
        log.info("StaffBot online: %s (%d)", self.user, self.user.id)
        g = discord.Object(id=CONFIG["guild_id"])
        try:
            synced = await self.tree.sync(guild=g)
            log.info("Commands synced: %d", len(synced))
        except Exception as e:
            log.error("Sync failed: %s", e)
        asyncio.create_task(self._setup_log_channels())

    async def _setup_log_channels(self):
        """Create log channel structure in staff Discord and generate webhooks.
        Runs on every boot - skips channels/webhooks that already exist so it
        is safe to re-run after adding new channels to STRUCTURE."""

        STRUCTURE = [
            {"name": "MAIN BOT LOGS",     "key": "MAIN",     "channels": [
                "purchases","verifications","tickets-opened","tickets-closed",
                "ticket-transcripts","ticket-notes","key-generated","bans","automod"
            ]},
            {"name": "CUSTOMER BOT LOGS", "key": "CUSTOMER", "channels": [
                "verifications","hwid-resets",
                "tickets-opened","tickets-closed","ticket-transcripts",
                "ticket-notes","key-generated","bans","automod"
            ]},
            {"name": "CHEAT LOGS",        "key": "CHEAT",    "channels": [
                "hwid-resets","key-events","bans","errors",
                "loader-events","hwid-flags","license-checks","anomalies"
            ]},
        ]

        guild = self.get_guild(CONFIG["guild_id"])
        if not guild:
            log.error("[setup] Could not find staff guild %d", CONFIG["guild_id"])
            return

        log.info("[setup] Starting log channel setup in %s", guild.name)
        existing_cats = {c.name.upper(): c for c in guild.categories}

        webhooks = {}
        try:
            for sec in STRUCTURE:
                cat_key   = sec["name"].upper()
                cat_obj   = existing_cats.get(cat_key)
                if not cat_obj:
                    cat_obj = await guild.create_category(sec["name"])
                    log.info("[setup]   Created category: %s", sec["name"])
                    await asyncio.sleep(0.5)
                else:
                    log.info("[setup]   Category exists: %s", sec["name"])

                for ch_name in sec["channels"]:
                    env_key = f"WEBHOOK_{sec['key']}_{ch_name.upper().replace('-','_')}"
                    # Scope lookup to THIS category so same-named channels in
                    # different sections (e.g. #verifications in MAIN vs CUSTOMER)
                    # are created independently rather than reusing the wrong one.
                    ch_obj = discord.utils.get(cat_obj.channels, name=ch_name)
                    if not ch_obj:
                        ch_obj = await guild.create_text_channel(ch_name, category=cat_obj)
                        log.info("[setup]     Created #%s in %s", ch_name, sec["name"])
                        await asyncio.sleep(0.4)
                    else:
                        log.info("[setup]     Channel #%s exists in %s", ch_name, sec["name"])

                    # Reuse existing LogDash webhook if present, create if not
                    existing_whs = await ch_obj.webhooks()
                    logdash_wh = next((w for w in existing_whs if w.name.startswith("LogDash-")), None)
                    if logdash_wh:
                        wh = logdash_wh
                        log.info("[setup]     Webhook exists: %s", env_key)
                    else:
                        wh = await ch_obj.create_webhook(name=f"LogDash-{sec['key']}")
                        log.info("[setup]     Webhook created: %s=%s", env_key, wh.url)
                    webhooks[env_key] = wh.url
                    await asyncio.sleep(0.3)

            # Write to persistent volume
            env_path = "/data/webhooks.env"
            with open(env_path, "w") as f:
                for k, v in sorted(webhooks.items()):
                    f.write(f'{k}="{v}"\n')
            log.info("[setup] Wrote %d webhook URLs to %s", len(webhooks), env_path)

            # Print all in one block so it's easy to copy from Railway logs
            log.info("[setup] ===== RAILWAY ENV VARS - PASTE INTO SERVICES =====")
            for k, v in sorted(webhooks.items()):
                log.info("[setup] %s=%s", k, v)
            log.info("[setup] ===== END WEBHOOK VARS =====")

            log.info("[setup] Setup complete. %d webhooks tracked.", len(webhooks))

        except Exception as exc:
            log.error("[setup] Setup failed: %s", exc, exc_info=True)

    async def log_embed(self, e: discord.Embed):
        """Proxy so ported admin commands can call await BOT.log_embed(e)."""
        await webhook_log(e)

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.CheckFailure):
            # Predicate sends "Access Denied" itself; safety net if it couldn't respond
            try:
                e = err_embed("Access Denied", "You don't have permission to use this command.")
                if interaction.response.is_done():
                    await interaction.followup.send(embed=e, ephemeral=True)
                else:
                    await interaction.response.send_message(embed=e, ephemeral=True)
            except Exception:
                pass
            return
        log.error("Command error /%s: %s", interaction.command.name if interaction.command else "?", error)
        e = err_embed("Something went wrong", "An internal error occurred. Contact staff if this persists.")
        try:
            if interaction.response.is_done():
                await interaction.followup.send(embed=e, ephemeral=True)
            else:
                await interaction.response.send_message(embed=e, ephemeral=True)
        except Exception:
            pass

BOT: StaffBot = None

# ─── ADMIN CHECK ──────────────────────────────────────────────────────────────

def staff_only():
    async def predicate(i: discord.Interaction) -> bool:
        rid = CONFIG["admin_role_id"]
        if not rid:
            if i.user.guild_permissions.administrator:
                return True
        else:
            role = i.guild.get_role(rid)
            if role and role in i.user.roles:
                return True
        e = err_embed("Access Denied", "Staff only.")
        try:
            if not i.response.is_done():
                await i.response.send_message(embed=e, ephemeral=True)
        except Exception:
            pass
        return False
    return app_commands.check(predicate)

# ─── BACKGROUND: STALE TICKET ALERTS ─────────────────────────────────────────

@tasks.loop(hours=6)
async def stale_checker():
    """Alert on tickets open more than 24h with no assigned staff."""
    rows = DB.execute(
        "SELECT * FROM tickets WHERE status='open' AND assigned_to IS NULL"
    ).fetchall()
    if not rows:
        return
    guild = BOT.get_guild(CONFIG["guild_id"])
    log_ch = BOT.get_channel(CONFIG["log_channel_id"])
    if not log_ch or not guild:
        return
    for row in rows:
        opened = datetime.fromisoformat(row["opened_at"])
        age_h = (datetime.now(timezone.utc) - opened).total_seconds() / 3600
        if age_h >= 24:
            ch = guild.get_channel(int(row["channel_id"]))
            ch_mention = ch.mention if ch else f"(channel gone: {row['channel_id']})"
            e = warn_embed(
                "Stale Ticket",
                f"Ticket {ch_mention} has been open for {int(age_h)}h with no assigned staff."
            )
            e.add_field(name="User",   value=f"<@{row['discord_id']}>", inline=True)
            e.add_field(name="Type",   value=TICKET_LABELS.get(row["type"], row["type"]), inline=True)
            e.set_footer(text=ts())
            await log_ch.send(embed=e)

# ─── TICKET PANEL ─────────────────────────────────────────────────────────────

class TicketTypeSelect(discord.ui.Select):
    def __init__(self):
        options = [
            discord.SelectOption(label="HWID Reset - Free",        value="hwid_free",  description="Ticket approved, no payment required",       emoji="🔄"),
            discord.SelectOption(label="HWID Reset - Paid",        value="hwid_paid",  description="Payment required before reset is processed",  emoji="💳"),
            discord.SelectOption(label="FAC Auth Reset - Free",    value="fac_free",   description="Ticket approved, no payment required",       emoji="🔑"),
            discord.SelectOption(label="FAC Auth Reset - Paid",    value="fac_paid",   description="Payment required before auth is granted",    emoji="💳"),
            discord.SelectOption(label="General Support",          value="general",    description="Any other question or issue",                emoji="💬"),
        ]
        super().__init__(placeholder="Select ticket type...", options=options, min_values=1, max_values=1)

    async def callback(self, interaction: discord.Interaction):
        ticket_type = self.values[0]
        await interaction.response.defer(ephemeral=True)

        did = str(interaction.user.id)

        # Check if user already has an open ticket
        existing = DB.execute(
            "SELECT channel_id FROM tickets WHERE discord_id=? AND status='open'", (did,)
        ).fetchone()
        if existing:
            ch = interaction.guild.get_channel(int(existing["channel_id"]))
            ch_str = ch.mention if ch else f"channel ID {existing['channel_id']}"
            await interaction.followup.send(
                embed=warn_embed("Ticket Already Open", f"You already have an open ticket: {ch_str}"),
                ephemeral=True
            )
            return

        # Check if user is registered in main bot DB
        user_row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()

        # Create ticket channel
        category = interaction.guild.get_channel(CONFIG["ticket_category_id"])
        label = TICKET_LABELS.get(ticket_type, ticket_type).lower().replace(" ", "-").replace("(", "").replace(")", "")
        channel_name = f"{label}-{interaction.user.name[:12]}"

        overwrites = {
            interaction.guild.default_role: discord.PermissionOverwrite(read_messages=False),
            interaction.user:               discord.PermissionOverwrite(read_messages=True, send_messages=True),
        }
        # Give staff role access
        staff_role = interaction.guild.get_role(CONFIG["admin_role_id"])
        if staff_role:
            overwrites[staff_role] = discord.PermissionOverwrite(read_messages=True, send_messages=True, manage_messages=True)

        try:
            ch = await interaction.guild.create_text_channel(
                channel_name,
                category=category,
                overwrites=overwrites,
                topic=f"Ticket for {interaction.user} ({did}) | Type: {ticket_type}"
            )
        except Exception as ex:
            await interaction.followup.send(embed=err_embed("Channel Error", f"Could not create ticket channel: {ex}"), ephemeral=True)
            return

        # Write to unified tickets table
        DB.execute(
            """INSERT INTO tickets
               (discord_id, channel_id, guild_id, bot_source, type, category, status, opened_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (did, str(ch.id), str(interaction.guild.id), 'staff',
             ticket_type, ticket_type, "open", now_iso())
        )
        DB.commit()
        audit_staff("TICKET_OPEN", actor_id=did, detail=f"type={ticket_type} channel={ch.id}")

        # Build opening embed in ticket channel
        needs_payment = ticket_type in ("hwid_paid", "fac_paid")
        color = TICKET_COLORS.get(ticket_type, BRAND_COLOR)

        e = discord.Embed(
            title=f"Ticket - {TICKET_LABELS[ticket_type]}",
            description=(
                f"Hey {interaction.user.mention}, thanks for opening a ticket.\n\n"
                + ("**Payment is required** before this can be processed. Staff will send you payment details shortly.\n\n" if needs_payment else "")
                + "Please describe your issue below. Staff will be with you shortly."
            ),
            color=color
        )

        # Pull user info from main DB if registered
        if user_row:
            from datetime import datetime as dt
            expires = user_row["expires_at"][:10] if user_row["expires_at"] else "Never"
            e.add_field(name="License Status", value=user_row["status"].upper(),   inline=True)
            e.add_field(name="Product",        value=user_row["product"],          inline=True)
            e.add_field(name="Expires",        value=expires,                      inline=True)
            e.add_field(name="HWID Bound",     value="Yes" if user_row["hwid"] else "No", inline=True)
            e.add_field(name="FAC Auth",       value="✅ Active" if user_row["fac_reset_auth"] else "❌ None", inline=True)
        else:
            e.add_field(name="License", value="Not registered in main bot", inline=False)

        e.set_footer(text=f"Opened by {interaction.user} - {ts()}")

        view = TicketActionView()
        await ch.send(content=interaction.user.mention, embed=e, view=view)
        await interaction.followup.send(
            embed=ok_embed("Ticket Created", f"Your ticket has been opened: {ch.mention}"),
            ephemeral=True
        )

        # Log to staff log channel and main server webhook
        log_e = discord.Embed(
            title="New Ticket",
            description=f"{interaction.user.mention} (`{did}`) opened a ticket.",
            color=color
        )
        log_e.add_field(name="Type",    value=TICKET_LABELS[ticket_type], inline=True)
        log_e.add_field(name="Channel", value=ch.mention,                 inline=True)
        log_e.add_field(name="Payment", value="Required" if needs_payment else "None", inline=True)
        log_e.set_footer(text=ts())

        log_ch = BOT.get_channel(CONFIG["log_channel_id"])
        if log_ch:
            await log_ch.send(embed=log_e)
        await webhook_log(log_e)


class TicketTypeView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        self.add_item(TicketTypeSelect())


# ─── TICKET ACTION BUTTONS ────────────────────────────────────────────────────

class TicketActionView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Claim",        style=discord.ButtonStyle.primary,   custom_id="ticket_claim",   emoji="👋")
    async def claim(self, interaction: discord.Interaction, button: discord.ui.Button):
        row = DB.execute("SELECT * FROM tickets WHERE channel_id=?", (str(interaction.channel_id),)).fetchone()
        if not row:
            await interaction.response.send_message(embed=err_embed("Not Found", "No ticket linked to this channel."), ephemeral=True)
            return
        if row["assigned_to"]:
            await interaction.response.send_message(
                embed=warn_embed("Already Claimed", f"This ticket is already claimed by <@{row['assigned_to']}>."),
                ephemeral=True
            )
            return
        DB.execute("UPDATE tickets SET assigned_to=? WHERE channel_id=?", (str(interaction.user.id), str(interaction.channel_id)))
        DB.commit()
        audit_staff("TICKET_CLAIMED", actor_id=str(interaction.user.id), target_id=row["discord_id"])
        e = ok_embed("Ticket Claimed", f"{interaction.user.mention} has claimed this ticket.")
        e.set_footer(text=ts())
        await interaction.response.send_message(embed=e)

    @discord.ui.button(label="Mark Paid",    style=discord.ButtonStyle.success,   custom_id="ticket_paid",    emoji="💳")
    async def mark_paid(self, interaction: discord.Interaction, button: discord.ui.Button):
        row = DB.execute("SELECT * FROM tickets WHERE channel_id=?", (str(interaction.channel_id),)).fetchone()
        if not row:
            await interaction.response.send_message(embed=err_embed("Not Found", "No ticket linked to this channel."), ephemeral=True)
            return
        if row["type"] not in ("hwid_paid", "fac_paid"):
            await interaction.response.send_message(embed=warn_embed("Not a Paid Ticket", "This ticket type does not require payment."), ephemeral=True)
            return
        DB.execute("UPDATE tickets SET payment_status='paid' WHERE channel_id=?", (str(interaction.channel_id),))
        DB.commit()
        audit_staff("TICKET_PAID", actor_id=str(interaction.user.id), target_id=row["discord_id"])
        e = ok_embed("Payment Confirmed", f"Payment marked as received by {interaction.user.mention}.")
        e.add_field(name="User", value=f"<@{row['discord_id']}>", inline=True)
        e.set_footer(text=ts())
        await interaction.response.send_message(embed=e)

        # Cross-log to main server
        await webhook_log(e)

    @discord.ui.button(label="Approve",      style=discord.ButtonStyle.success,   custom_id="ticket_approve", emoji="✅")
    async def approve(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        row = DB.execute("SELECT * FROM tickets WHERE channel_id=?", (str(interaction.channel_id),)).fetchone()
        if not row:
            await interaction.followup.send(embed=err_embed("Not Found", "No ticket linked to this channel."), ephemeral=True)
            return

        ttype = row["type"]
        did = row["discord_id"]

        # Paid tickets must have payment confirmed first
        if ttype in ("hwid_paid", "fac_paid") and row["payment_status"] != "paid":
            await interaction.followup.send(
                embed=warn_embed("Payment Not Confirmed", "Mark payment received before approving a paid ticket."),
                ephemeral=True
            )
            return

        user_row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
        if not user_row:
            await interaction.followup.send(embed=err_embed("Not Registered", "User has no license record in the main bot."), ephemeral=True)
            return

        # Execute the action directly on the shared DB
        result_lines = []
        role_assigned = False

        if ttype in ("hwid_free", "hwid_paid"):
            DB.execute("UPDATE users SET hwid=NULL, hwid_resets=hwid_resets+1 WHERE discord_id=?", (did,))
            DB.commit()
            audit_staff("TICKET_HWID_RESET", actor_id=str(interaction.user.id), target_id=did,
                        detail=f"ticket_id={row['id']} paid={ttype=='hwid_paid'}")
            result_lines.append("HWID cleared - user can bind a new machine on next launch.")

            if ttype == "hwid_paid":
                role_assigned = await _try_assign_role(interaction, did, "hwid_paid_role_id")
                result_lines.append(f"HWID paid role: {'assigned' if role_assigned else 'failed - check bot permissions'}.")

        elif ttype in ("fac_free", "fac_paid"):
            if user_row["fac_reset_auth"]:
                await interaction.followup.send(
                    embed=warn_embed("Already Authorized", f"<@{did}> already has an active FAC auth. Revoke first."),
                    ephemeral=True
                )
                return
            DB.execute("UPDATE users SET fac_reset_auth=1 WHERE discord_id=?", (did,))
            DB.commit()
            audit_staff("TICKET_FAC_GRANTED", actor_id=str(interaction.user.id), target_id=did,
                        detail=f"ticket_id={row['id']} paid={ttype=='fac_paid'}")
            result_lines.append("FAC reset authorized. Auth key DM'd to user.")

            if ttype == "fac_paid":
                role_assigned = await _try_assign_role(interaction, did, "fac_paid_role_id")
                result_lines.append(f"FAC paid role: {'assigned' if role_assigned else 'failed - check bot permissions'}.")

        # Update ticket status
        DB.execute(
            "UPDATE tickets SET status='approved', closed_at=?, closed_by=?, resolution=? WHERE channel_id=?",
            (now_iso(), str(interaction.user.id), ttype, str(interaction.channel_id))
        )
        DB.commit()

        # DM user
        try:
            user_obj = await BOT.fetch_user(int(did))
            dm_e = discord.Embed(
                title="Ticket Approved",
                description=_approval_dm_text(ttype),
                color=discord.Color.green()
            )
            if ttype in ("fac_free", "fac_paid"):
                dm_e.add_field(name="FAC Auth Key", value=f"`{user_row['fac_auth_key']}`", inline=False)
            dm_e.set_footer(text="Contact support if you encounter any issues.")
            await user_obj.send(embed=dm_e)
        except Exception:
            result_lines.append("DM failed - user may have DMs disabled.")

        e = ok_embed(
            "Ticket Approved",
            "\n".join(result_lines)
        )
        e.add_field(name="User",        value=f"<@{did}>",          inline=True)
        e.add_field(name="Type",        value=TICKET_LABELS[ttype], inline=True)
        e.add_field(name="Approved By", value=str(interaction.user), inline=True)
        e.set_footer(text=ts())
        await interaction.followup.send(embed=e)
        await webhook_log(e)

        # Archive the channel
        try:
            await interaction.channel.edit(
                name=f"closed-{interaction.channel.name}",
                overwrites={interaction.guild.default_role: discord.PermissionOverwrite(read_messages=False)}
            )
        except Exception:
            pass

    @discord.ui.button(label="Close",        style=discord.ButtonStyle.danger,    custom_id="ticket_close",   emoji="🔒")
    async def close(self, interaction: discord.Interaction, button: discord.ui.Button):
        row = DB.execute("SELECT * FROM tickets WHERE channel_id=?", (str(interaction.channel_id),)).fetchone()
        if not row:
            await interaction.response.send_message(embed=err_embed("Not Found", "No ticket linked to this channel."), ephemeral=True)
            return
        DB.execute(
            "UPDATE tickets SET status='closed', closed_at=?, closed_by=? WHERE channel_id=?",
            (now_iso(), str(interaction.user.id), str(interaction.channel_id))
        )
        DB.commit()
        audit_staff("TICKET_CLOSED", actor_id=str(interaction.user.id), target_id=row["discord_id"])

        e = discord.Embed(
            title="Ticket Closed",
            description=f"Closed by {interaction.user.mention}. Channel will be deleted in 10 seconds.",
            color=discord.Color.red()
        )
        e.set_footer(text=ts())
        await interaction.response.send_message(embed=e)
        await webhook_log(e)
        await asyncio.sleep(10)
        try:
            await interaction.channel.delete(reason=f"Ticket closed by {interaction.user}")
        except Exception:
            pass


# ─── HELPERS ──────────────────────────────────────────────────────────────────

async def _try_assign_role(interaction: discord.Interaction, did: str, role_key: str) -> bool:
    """Try to assign a configured role to a user in the guild. Returns True if assigned."""
    role_id = CONFIG.get(role_key)
    if not role_id:
        return False
    role = interaction.guild.get_role(int(role_id))
    if not role:
        return False
    try:
        member = interaction.guild.get_member(int(did)) or await interaction.guild.fetch_member(int(did))
        await member.add_roles(role, reason=f"Ticket approved by {interaction.user}")
        return True
    except Exception as ex:
        log.warning("Role assign failed (%s): %s", role_key, ex)
        return False

def _approval_dm_text(ttype: str) -> str:
    return {
        "hwid_free": "Your HWID reset request has been approved. Launch the loader to bind your new machine.",
        "hwid_paid": "Your payment has been received and your HWID reset has been approved. Launch the loader to bind your new machine.",
        "fac_free":  "Your FAC auth request has been approved. Present your auth key when prompted by the loader.",
        "fac_paid":  "Your payment has been received and your FAC auth request has been approved. Present your auth key when prompted by the loader.",
        "general":   "Your support ticket has been resolved. Feel free to open a new ticket if you need further help.",
    }.get(ttype, "Your ticket has been approved.")


# ─── MAIN BOT COMMANDS (ported to staff bot) ──────────────────────────────────
# All license management commands live here so staff bot is the only bot
# users and admins interact with. Main bot handles loader API only.

# ── User commands ──

@app_commands.command(name="register",
    description="Activate your license key and bind your HWID to your Discord account.")
@app_commands.describe(
    key="Your license key (from the seller)",
    hwid="Your Hardware ID (shown in the launcher)"
)
async def cmd_register(i: discord.Interaction, key: str, hwid: str):
    await i.response.defer(ephemeral=True)
    did = str(i.user.id)

    if DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=warn_embed(
            "Already Registered",
            "You already have an active license on this account.\nRun `/mystatus` to view it."
        ), ephemeral=True)
        return

    pool = DB.execute("SELECT * FROM key_pool WHERE key=? AND claimed=0", (key.strip().upper(),)).fetchone()
    if not pool:
        audit_staff("REGISTER_FAIL_BAD_KEY", actor_id=did, detail=f"key={key[:20]}")
        await i.followup.send(embed=err_embed(
            "Invalid Key",
            "That key doesn't exist or has already been used.\nContact support if you believe this is an error."
        ), ephemeral=True)
        return

    if DB.execute("SELECT 1 FROM users WHERE key=?", (key.strip().upper(),)).fetchone():
        audit_staff("REGISTER_FAIL_KEY_TAKEN", actor_id=did)
        await i.followup.send(embed=err_embed(
            "Key Already Claimed",
            "That key is registered to another account. Contact support."
        ), ephemeral=True)
        return

    hashed = hash_hwid(hwid)
    if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
        audit_staff("REGISTER_FAIL_HWID_BANNED", actor_id=did)
        await i.followup.send(embed=err_embed(
            "Hardware Banned",
            "Your hardware ID is on the ban list. Contact support to appeal."
        ), ephemeral=True)
        return

    if pool["expires_at"]:
        try:
            if datetime.now(timezone.utc) > datetime.fromisoformat(pool["expires_at"]):
                await i.followup.send(embed=warn_embed(
                    "Key Expired",
                    "That key expired before it could be activated. Contact support for a replacement."
                ), ephemeral=True)
                return
        except Exception:
            pass

    fac_key = gen_fac_key()
    DB.execute(
        "INSERT INTO users (discord_id,key,hwid,product,status,registered_at,expires_at,fac_auth_key) VALUES (?,?,?,?,?,?,?,?)",
        (did, key.strip().upper(), hashed, pool["product"], "active", now_iso(), pool["expires_at"], fac_key)
    )
    DB.execute("UPDATE key_pool SET claimed=1 WHERE key=?", (key.strip().upper(),))
    DB.commit()

    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr:
            await i.user.add_roles(vr, reason="KeyLock: registered")
    except Exception as ex:
        log.warning("Role grant failed: %s", ex)

    audit_staff("REGISTER_SUCCESS", actor_id=did, detail=f"key={key[:20]} product={pool['product']}")

    prod_icon = "🌐" if pool["product"] == "public" else "🔒"
    e = discord.Embed(
        title="License Activated",
        description="Your key has been validated and your hardware ID is now bound to this account.",
        color=discord.Color.green()
    )
    e.add_field(name="Product", value=f"{prod_icon} {pool['product']}", inline=True)
    e.add_field(name="Expires", value=fmt_dt(pool["expires_at"]), inline=True)
    e.add_field(name="​", value="​", inline=True)
    e.add_field(
        name="FAC Auth Key",
        value=f"`{fac_key}`\nSave this. You'll need it if you ever request a hardware reset.",
        inline=False
    )
    e.set_footer(text=f"ID: {i.user.id}")
    await i.followup.send(embed=e, ephemeral=True)

    log_e = discord.Embed(
        title="New Registration",
        description=f"<@{did}> (`{did}`) activated a new license.",
        color=discord.Color.green()
    )
    log_e.add_field(name="Product", value=f"{prod_icon} {pool['product']}", inline=True)
    log_e.add_field(name="Expires", value=fmt_dt(pool["expires_at"]), inline=True)
    log_e.add_field(name="FAC Auth Key", value=f"`{fac_key}`", inline=False)
    log_e.set_footer(text=ts())
    await BOT.log_embed(log_e)


@app_commands.command(name="mystatus", description="Check your license status.")
async def cmd_mystatus(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (str(i.user.id),)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed(
            "Not Registered",
            "You don't have a license on this account. Contact an admin to get one."
        ), ephemeral=True)
        return

    s = effective_status(row)
    prod_icon = "🌐" if row["product"] == "public" else "🔒"
    e = discord.Embed(title="Your License", color=status_color(s))
    e.add_field(name="Status", value=f"{status_emoji(s)} {s.upper()}", inline=True)
    e.add_field(name="Product", value=f"{prod_icon} {row['product']}", inline=True)
    e.add_field(name="Expires", value=fmt_dt(row["expires_at"]), inline=True)
    e.add_field(name="Registered", value=fmt_dt(row["registered_at"]), inline=True)
    e.add_field(name="Last Seen", value=fmt_ts(row["last_seen"]), inline=True)
    e.add_field(name="​", value="​", inline=True)
    if row["ban_reason"]:
        e.add_field(name="Reason", value=row["ban_reason"], inline=False)
    e.set_footer(text=f"ID: {i.user.id}")
    await i.followup.send(embed=e, ephemeral=True)


# ── Helpers shared by admin commands ──

async def autocomplete_duration(i: discord.Interaction, current: str):
    options = ["1day", "3days", "1week", "2weeks", "1month", "3months", "6months", "1year", "lifetime"]
    return [app_commands.Choice(name=o, value=o) for o in options if current.lower() in o]

async def autocomplete_product(i: discord.Interaction, current: str):
    options = ["private", "public"]
    return [app_commands.Choice(name=o, value=o) for o in options if current.lower() in o]

PRODUCT_ICONS: dict[str, str] = {
    "private":  "🔒",
    "public":   "🌐",
    "lifetime": "♾️",
    "trial":    "⏳",
    "default":  "🔑",
}

DURATION_PRESETS = {
    "1day":    timedelta(days=1),
    "3days":   timedelta(days=3),
    "1week":   timedelta(weeks=1),
    "2weeks":  timedelta(weeks=2),
    "1month":  timedelta(days=30),
    "3months": timedelta(days=90),
    "6months": timedelta(days=180),
    "1year":   timedelta(days=365),
    "lifetime": None,
}


# Alias so ported admin commands that call audit() work without changes
audit = audit_staff

admin_only = staff_only  # admin commands use same role gate on the staff bot


# ─── ADMIN COMMANDS (ported from main bot) ────────────────────────────────────

@app_commands.command(name="keygen", description="[ADMIN] Generate a key and optionally DM it to a user.")
@app_commands.describe(
    product="private or public (both work in the loader)",
    duration="How long the key is valid for",
    deliver_to="DM the key directly to this user",
    invoice_id="Invoice/payment ID to link this key to (required for paid orders)",
    notes="Admin notes attached to this key"
)
@app_commands.autocomplete(duration=autocomplete_duration, product=autocomplete_product)
@admin_only()
async def cmd_keygen(i: discord.Interaction,
                     product: str = "private",
                     duration: Optional[str] = "lifetime",
                     deliver_to: Optional[discord.User] = None,
                     invoice_id: Optional[str] = None,
                     notes: Optional[str] = None):
    try:
        await i.response.defer(ephemeral=True)
    except Exception as e:
        log.error("keygen defer failed: %s", e)
        return

    prod = (product or "private").lower().strip()
    dur_key = (duration or "lifetime").lower().replace(" ", "")
    if dur_key not in DURATION_PRESETS:
        opts = ", ".join(f"`{k}`" for k in DURATION_PRESETS)
        await i.followup.send(embed=err_embed("Invalid Duration", f"Choose one of: {opts}"), ephemeral=True)
        return

    delta = DURATION_PRESETS[dur_key]
    exp_iso = None
    expires_label = "Lifetime"
    if delta is not None:
        exp_dt = datetime.now(timezone.utc) + delta
        exp_iso = exp_dt.isoformat()
        expires_label = exp_dt.strftime("%Y-%m-%d")

    # Guild membership check when delivering to a user
    if deliver_to:
        in_guild, reason = await _member_in_guilds(
            BOT, deliver_to.id,
            CONFIG.get("main_guild_id", 0),
            CONFIG.get("void_guild_id", 0),
        )
        if not in_guild:
            await i.followup.send(
                embed=err_embed(
                    "Membership Check Failed",
                    f"{deliver_to.mention} is not a member of the customer or void Discord.\n"
                    f"Key not generated. Confirm they have joined before delivering a key."
                ),
                ephemeral=True,
            )
            return

    vis = "public" if prod == "public" else "private"
    inv = (invoice_id or "").strip().upper() or None
    k = gen_key(CONFIG["key_prefix"])
    DB.execute(
        "INSERT OR IGNORE INTO key_pool "
        "(key,product,visibility,created_at,expires_at,created_by,notes,invoice_id) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (k, prod, vis, now_iso(), exp_iso, str(i.user.id), notes, inv)
    )
    DB.commit()
    audit("KEYGEN", actor_id=str(i.user.id),
          detail=f"product={prod} duration={dur_key}" + (f" invoice={inv}" if inv else ""))

    # If delivering, link the key to the user's Discord ID immediately
    if deliver_to:
        already = DB.execute(
            "SELECT key FROM users WHERE discord_id=?", (str(deliver_to.id),)
        ).fetchone()
        if not already:
            fac_key = gen_fac_key()
            DB.execute(
                """INSERT OR IGNORE INTO users
                   (discord_id, key, product, status, registered_at, expires_at, fac_auth_key, notes)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (str(deliver_to.id), k, prod, "active", now_iso(), exp_iso, fac_key,
                 f"Key delivered by {i.user} via /keygen")
            )
            DB.execute("UPDATE key_pool SET claimed=1 WHERE key=?", (k,))
            DB.commit()
            audit("KEY_LINKED", actor_id=str(i.user.id), target_id=str(deliver_to.id),
                  detail=f"key={k[:20]} product={prod}")

        # Write a payments record so the invoice is discoverable across bots
        if inv:
            DB.execute(
                """INSERT OR IGNORE INTO payments
                   (invoice_id, discord_id, key, product, amount, method, expires_at, paid_at, confirmed_by)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (inv, str(deliver_to.id), k, prod, None, None, exp_iso, now_iso(), str(i.user.id))
            )
            DB.commit()
            audit("PAYMENT_LINKED", actor_id=str(i.user.id), target_id=str(deliver_to.id),
                  detail=f"invoice={inv} key={k[:20]}")

    prod_icon = "🌐" if prod == "public" else "🔒"
    dm_status = None
    if deliver_to:
        dm_embed = discord.Embed(
            title="Your License Key",
            description="Your key is ready. Open the loader and enter it to activate your license.",
            color=BRAND_COLOR,
        )
        dm_embed.add_field(name="Key", value=f"```{k}```", inline=False)
        dm_embed.add_field(name="Product", value=f"{prod_icon} {prod}", inline=True)
        dm_embed.add_field(name="Valid For", value=expires_label, inline=True)
        dm_embed.set_footer(text="Keep this key private - do not share it with anyone.")
        try:
            await deliver_to.send(embed=dm_embed)
            dm_status = f"Delivered to {deliver_to.mention}"
            audit("KEY_DELIVERED", actor_id=str(i.user.id), target_id=str(deliver_to.id),
                  detail=f"key={k[:20]} product={prod}")
        except discord.Forbidden:
            dm_status = f"DM failed - {deliver_to.mention} has DMs closed"
        except Exception as e:
            dm_status = f"DM failed - {e}"

    linked_note = " Key linked to Discord ID." if deliver_to else " Key added to pool (unclaimed)."
    result_embed = discord.Embed(
        title="Key Generated",
        description=f"New `{prod}` key created.{linked_note}",
        color=discord.Color.green(),
    )
    result_embed.add_field(name="Product", value=f"{prod_icon} `{prod}`", inline=True)
    result_embed.add_field(name="Valid For", value=f"`{expires_label}`", inline=True)
    result_embed.add_field(name="​", value="​", inline=True)
    result_embed.add_field(name="License Key", value=f"```\n{k}\n```", inline=False)
    if inv:
        result_embed.add_field(name="Invoice ID", value=f"`{inv}`", inline=False)
    if dm_status:
        result_embed.add_field(name="Delivery", value=dm_status, inline=False)
    if notes:
        result_embed.add_field(name="Notes", value=notes, inline=False)
    result_embed.set_footer(text=f"By {i.user} - {ts()}")
    await i.followup.send(embed=result_embed, ephemeral=True)
    await BOT.log_embed(result_embed)


@app_commands.command(name="lookup",
    description="[ADMIN] Look up a user by Discord mention, ID, or license key.")
@app_commands.describe(query="@mention, Discord ID, or license key")
@admin_only()
async def cmd_lookup(i: discord.Interaction, query: str):
    await i.response.defer(ephemeral=True)
    clean = query.strip().lstrip("<@!").rstrip(">")
    row = (
        DB.execute("SELECT * FROM users WHERE discord_id=?", (clean,)).fetchone() or
        DB.execute("SELECT * FROM users WHERE key=?", (query.strip().upper(),)).fetchone()
    )
    if not row:
        await i.followup.send(embed=err_embed("Not Found", f"No user matched `{query}`."), ephemeral=True)
        return

    did = row["discord_id"]
    s = effective_status(row)

    total_ok = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status='ok'", (did,)
    ).fetchone()[0]
    total_all = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=?", (did,)
    ).fetchone()[0]
    failed = total_all - total_ok

    all_ips = DB.execute(
        "SELECT DISTINCT ip FROM login_log WHERE discord_id=? AND ip IS NOT NULL", (did,)
    ).fetchall()
    ip_list = [r["ip"] for r in all_ips]

    alts: list[str] = []
    if ip_list:
        placeholders = ",".join("?" * len(ip_list))
        alt_rows = DB.execute(
            f"SELECT DISTINCT discord_id FROM login_log WHERE ip IN ({placeholders}) AND discord_id != ?",
            ip_list + [did]
        ).fetchall()
        alts = [r["discord_id"] for r in alt_rows]

    hwid_alts: list[str] = []
    if row["hwid"]:
        hwid_rows = DB.execute(
            "SELECT discord_id FROM users WHERE hwid=? AND discord_id != ?",
            (row["hwid"], did)
        ).fetchall()
        hwid_alts = [r["discord_id"] for r in hwid_rows]

    recent = DB.execute(
        "SELECT status, ip, timestamp FROM login_log WHERE discord_id=? ORDER BY id DESC LIMIT 5", (did,)
    ).fetchall()

    audit_rows = DB.execute(
        "SELECT action, timestamp FROM audit_log WHERE target_id=? ORDER BY id DESC LIMIT 5", (did,)
    ).fetchall()

    # Try to find member across staff, main, and customer guilds
    member = None
    member_guild_name = None
    for guild_id in filter(None, [i.guild.id, CONFIG.get("main_guild_id"), CONFIG.get("void_guild_id")]):
        g = bot.get_guild(guild_id) or i.guild
        try:
            m = g.get_member(int(did)) or await g.fetch_member(int(did))
            if m:
                member = m
                member_guild_name = g.name
                break
        except Exception:
            continue

    if member:
        disc_str = f"<@{did}> (`{member}` / `{did}`)"
        joined = member.joined_at.strftime("%Y-%m-%d") if member.joined_at else "Unknown"
        joined += f" - {member_guild_name}" if member_guild_name and member_guild_name != i.guild.name else ""
        created = member.created_at.strftime("%Y-%m-%d")
        roles_str = ", ".join(r.name for r in member.roles if r.name != "@everyone") or "None"
        avatar_url = member.display_avatar.url
    else:
        disc_str = f"<@{did}> (`{did}`)"
        joined = "Not found in any linked server"
        created = "Unknown"
        roles_str = "N/A"
        avatar_url = None

    open_ticket: sqlite3.Row | None = None
    try:
        open_ticket = DB.execute(
            "SELECT id, type, status, payment_status, opened_at, assigned_to FROM tickets "
            "WHERE discord_id=? AND status IN ('open','claimed') ORDER BY id DESC LIMIT 1",
            (did,)
        ).fetchone()
    except sqlite3.OperationalError:
        pass

    prod_icon = PRODUCT_ICONS.get(row["product"], "🔑")
    has_alts = bool(alts or hwid_alts)

    flags = []
    if has_alts:         flags.append(f"⚠️ {len(alts)} IP-shared / {len(hwid_alts)} HWID-shared account(s) detected")
    if failed > 5:       flags.append(f"⚠️ {failed} failed login attempt(s)")
    if len(ip_list) > 3: flags.append(f"⚠️ {len(ip_list)} unique IPs on record")
    if open_ticket:      flags.append(f"🎫 Open ticket #{open_ticket['id']} ({open_ticket['type'].replace('_', ' ')})")
    desc = disc_str + ("\n\n" + "\n".join(flags) if flags else "")

    e = discord.Embed(title="User Lookup", description=desc, color=status_color(s))
    if avatar_url:
        e.set_thumbnail(url=avatar_url)

    e.add_field(name="Status",   value=f"{status_emoji(s)} {s.upper()}", inline=True)
    e.add_field(name="Product",  value=f"{prod_icon} {row['product']}",  inline=True)
    e.add_field(name="Expires",  value=fmt_dt(row["expires_at"]),         inline=True)
    e.add_field(name="Registered", value=fmt_dt(row["registered_at"]), inline=True)
    e.add_field(name="Last Seen",  value=fmt_ts(row["last_seen"]),      inline=True)
    e.add_field(name="Last IP",    value=f"`{row['ip_last']}`" if row["ip_last"] else "N/A", inline=True)
    hwid_val = f"Bound - {row['hwid_resets']} reset(s) used" if row["hwid"] else "Not bound"
    fac_val  = f"{'✅' if row['fac_reset_auth'] else '❌'} Auth'd  |  Key: `{row['fac_auth_key']}`" if row["fac_auth_key"] else ("✅ Authorized" if row["fac_reset_auth"] else "❌ Not authorized")
    sess_val = f"{total_ok} ok / {failed} failed / {len(ip_list)} unique IP(s)"
    e.add_field(name="HWID",         value=hwid_val,  inline=True)
    e.add_field(name="FAC Reset",    value=fac_val,   inline=True)
    e.add_field(name="Sessions",     value=sess_val,  inline=True)
    e.add_field(name="Account Created", value=created,         inline=True)
    e.add_field(name="Server Joined",   value=joined,          inline=True)
    e.add_field(name="Roles",           value=roles_str[:100], inline=True)
    ip_str = "  ".join(f"`{ip_addr}`" for ip_addr in ip_list[:12]) if ip_list else "None on record"
    e.add_field(name=f"Known IPs ({len(ip_list)})", value=ip_str, inline=False)
    if open_ticket:
        t_type = open_ticket["type"].replace("_", " ").title()
        t_pay  = open_ticket["payment_status"].replace("_", " ")
        t_date = open_ticket["opened_at"][:10]
        t_who  = f"<@{open_ticket['assigned_to']}>" if open_ticket["assigned_to"] else "Unassigned"
        t_val  = f"#{open_ticket['id']} - {t_type}\nStatus: **{open_ticket['status']}** | Payment: {t_pay}\nOpened: {t_date} | {t_who}"
        e.add_field(name="🎫 Open Ticket", value=t_val, inline=False)
    if alts:
        alt_str = " ".join(f"<@{a}>" for a in alts[:8])
        e.add_field(name=f"IP-Shared Accounts ({len(alts)})", value=alt_str, inline=False)
    if hwid_alts:
        h_str = " ".join(f"<@{a}>" for a in hwid_alts[:8])
        e.add_field(name=f"HWID-Shared Accounts ({len(hwid_alts)})", value=h_str, inline=False)
    # Payment history from payments table (populated by void_bot on purchase confirmation)
    payment_rows = []
    try:
        payment_rows = DB.execute(
            "SELECT invoice_id, product, expires_at, paid_at, confirmed_by, notes "
            "FROM payments WHERE discord_id=? ORDER BY id DESC LIMIT 5",
            (did,)
        ).fetchall()
    except sqlite3.OperationalError:
        pass
    if payment_rows:
        p_lines = []
        for p in payment_rows:
            paid_date = p["paid_at"][:10] if p["paid_at"] else "?"
            exp_str   = p["expires_at"][:10] if p["expires_at"] else "lifetime"
            p_lines.append(f"`{p['invoice_id']}` - {p['product']} - expires {exp_str} - paid {paid_date}")
        e.add_field(name=f"Payment History ({len(payment_rows)})", value="\n".join(p_lines), inline=False)

    e.add_field(name="License Key", value=f"`{row['key']}`", inline=False)
    if recent:
        lines = []
        for r in recent:
            stamp = r["timestamp"][:16].replace("T", " ")
            lines.append(f"`{r['status']:15s}` {r['ip'] or 'N/A':>15s}  {stamp}")
        e.add_field(name="Recent Logins", value="```\n" + "\n".join(lines) + "\n```", inline=False)
    if audit_rows:
        a_lines = [f"`{r['action']}` - {r['timestamp'][:10]}" for r in audit_rows]
        e.add_field(name="Recent Actions", value="\n".join(a_lines), inline=False)
    if row["ban_reason"]:
        e.add_field(name="Ban Reason", value=row["ban_reason"], inline=False)
    if row["notes"]:
        e.add_field(name="Notes", value=f"```{row['notes'][-300:]}```", inline=False)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="ban", description="[ADMIN] Ban a user - blocks loader, bans HWID + IP, kicks from server.")
@app_commands.describe(user="Target user", reason="Ban reason")
@admin_only()
async def cmd_ban(i: discord.Interaction, user: discord.User, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return

    ban_reason = reason or "No reason given"
    DB.execute("UPDATE users SET status='banned', ban_reason=? WHERE discord_id=?", (ban_reason, did))

    hwid_banned = False
    if row["hwid"]:
        try:
            DB.execute(
                "INSERT OR IGNORE INTO hwid_bans (hwid,reason,banned_at,banned_by) VALUES (?,?,?,?)",
                (row["hwid"], f"Auto: user ban - {ban_reason}", now_iso(), str(i.user.id))
            )
            hwid_banned = True
        except Exception as ex:
            log.warning("HWID ban during user ban failed: %s", ex)

    ip_banned = False
    if row["ip_last"]:
        try:
            DB.execute(
                "INSERT OR IGNORE INTO hwid_bans (hwid,reason,banned_at,banned_by) VALUES (?,?,?,?)",
                (f"IP:{row['ip_last']}", f"Auto: user ban - {ban_reason}", now_iso(), str(i.user.id))
            )
            ip_banned = True
        except Exception as ex:
            log.warning("IP ban during user ban failed: %s", ex)

    DB.commit()

    try:
        member = await _get_member(i.guild, user.id)
        if member:
            vr = i.guild.get_role(CONFIG["verified_role_id"])
            br = i.guild.get_role(CONFIG["banned_role_id"])
            if vr and vr in member.roles:
                await member.remove_roles(vr, reason="KeyLock ban")
            if br:
                await member.add_roles(br, reason="KeyLock ban")
    except Exception:
        pass

    kicked = False
    try:
        member = await _get_member(i.guild, user.id)
        if member:
            await member.kick(reason=f"KeyLock ban: {ban_reason}")
            kicked = True
    except Exception as ex:
        log.warning("Kick failed for %s: %s", did, ex)

    audit("BAN", actor_id=str(i.user.id), target_id=did, detail=ban_reason)

    actions = ["License blocked"]
    if hwid_banned: actions.append("HWID banned")
    if ip_banned:   actions.append(f"IP banned (`{row['ip_last']}`)")
    if kicked:      actions.append("Kicked from server")

    e = discord.Embed(
        title="User Banned",
        description="\n".join(f"- {a}" for a in actions),
        color=discord.Color.red()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=False)
    e.add_field(name="Reason", value=ban_reason, inline=True)
    e.add_field(name="Banned By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


@app_commands.command(name="unban", description="[ADMIN] Unban a user's license.")
@app_commands.describe(user="Target user")
@admin_only()
async def cmd_unban(i: discord.Interaction, user: discord.User):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET status='active', ban_reason=NULL WHERE discord_id=?", (did,))
    DB.commit()
    try:
        member = await _get_member(i.guild, user.id)
        if member:
            vr = i.guild.get_role(CONFIG["verified_role_id"])
            br = i.guild.get_role(CONFIG["banned_role_id"])
            if vr:
                await member.add_roles(vr, reason="KeyLock unban")
            if br and br in member.roles:
                await member.remove_roles(br, reason="KeyLock unban")
    except Exception:
        pass
    audit("UNBAN", actor_id=str(i.user.id), target_id=did)
    e = discord.Embed(
        title="User Unbanned",
        description="License restored to active. Verified role re-granted.",
        color=discord.Color.green()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Unbanned By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


@app_commands.command(name="revoke", description="[ADMIN] Permanently revoke a license.")
@app_commands.describe(user="Target user", reason="Reason")
@admin_only()
async def cmd_revoke(i: discord.Interaction, user: discord.User, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET status='revoked', ban_reason=? WHERE discord_id=?", (reason or "Revoked", did))
    DB.commit()
    try:
        member = await _get_member(i.guild, user.id)
        if member:
            vr = i.guild.get_role(CONFIG["verified_role_id"])
            if vr and vr in member.roles:
                await member.remove_roles(vr, reason="KeyLock revoke")
    except Exception:
        pass
    audit("REVOKE", actor_id=str(i.user.id), target_id=did, detail=reason)
    e = discord.Embed(
        title="License Revoked",
        description="License permanently revoked. Verified role removed.",
        color=BRAND_COLOR
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=False)
    e.add_field(name="Reason", value=reason or "No reason given", inline=True)
    e.add_field(name="Revoked By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


@app_commands.command(name="addnote_admin", description="[ADMIN] Append an admin note to a user (by mention/ID).")
@app_commands.describe(user="Target user", note="Note text")
@admin_only()
async def cmd_addnote(i: discord.Interaction, user: discord.User, note: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT notes FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    stamp = f"[{now_iso()[:10]} - {i.user}] {note}"
    existing = row["notes"] or ""
    DB.execute("UPDATE users SET notes=? WHERE discord_id=?", ((existing + "\n" + stamp).strip(), did))
    DB.commit()
    audit("ADD_NOTE", actor_id=str(i.user.id), target_id=did, detail=note[:100])
    e = discord.Embed(title="Note Added", description=f"```{note[:300]}```", color=BRAND_COLOR)
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Added By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="resethwid", description="[ADMIN] Force-reset or rebind a user's HWID.")
@app_commands.describe(user="Target user", new_hwid="New HWID to bind (blank = clear)")
@admin_only()
async def cmd_resethwid(i: discord.Interaction, user: discord.User, new_hwid: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    hashed = hash_hwid(new_hwid) if new_hwid else None
    DB.execute("UPDATE users SET hwid=?, hwid_resets=hwid_resets+1 WHERE discord_id=?", (hashed, did))
    DB.commit()
    audit("HWID_RESET_ADMIN", actor_id=str(i.user.id), target_id=did, detail="set" if hashed else "cleared")
    action_label = "Rebound" if hashed else "Cleared"
    e = discord.Embed(
        title=f"HWID {action_label}",
        description="Next loader launch will bind the new hardware ID." if hashed else "HWID cleared - user can bind a new machine on next launch.",
        color=discord.Color.orange()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Reset By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="hwid", description="[ADMIN] Ban or unban a hardware ID globally.")
@app_commands.describe(action="Action to perform", raw_hwid="Raw HWID string from the loader", reason="Reason (required for ban)")
@app_commands.choices(action=[
    app_commands.Choice(name="ban   - block this HWID globally", value="ban"),
    app_commands.Choice(name="unban - remove the HWID ban",      value="unban"),
])
@admin_only()
async def cmd_hwid(i: discord.Interaction, action: str, raw_hwid: str, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    action = action.lower().strip()
    if action not in ("ban", "unban"):
        await i.followup.send(embed=err_embed("Invalid Action", "Use `ban` or `unban`."), ephemeral=True)
        return
    hashed = hash_hwid(raw_hwid)
    if action == "ban":
        try:
            DB.execute("INSERT INTO hwid_bans (hwid,reason,banned_at,banned_by) VALUES (?,?,?,?)",
                       (hashed, reason or "No reason given", now_iso(), str(i.user.id)))
            DB.commit()
        except sqlite3.IntegrityError:
            await i.followup.send(embed=warn_embed("Already Banned", "That HWID is already on the global ban list."), ephemeral=True)
            return
        audit("HWID_BAN", actor_id=str(i.user.id), detail=hashed[:16])
        e = discord.Embed(
            title="HWID Banned",
            description="Hardware ID added to the global ban list. Any user binding this HWID will be blocked at the loader.",
            color=discord.Color.red()
        )
        e.add_field(name="Hash (truncated)", value=f"`{hashed[:24]}...`", inline=False)
        e.add_field(name="Reason", value=reason or "None given", inline=True)
        e.add_field(name="Banned By", value=str(i.user), inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)
        await BOT.log_embed(e)
    else:
        cur = DB.execute("DELETE FROM hwid_bans WHERE hwid=?", (hashed,))
        DB.commit()
        if cur.rowcount == 0:
            await i.followup.send(embed=err_embed("Not Found", "That HWID is not on the ban list."), ephemeral=True)
            return
        audit("HWID_UNBAN", actor_id=str(i.user.id), detail=hashed[:16])
        e = discord.Embed(title="HWID Unbanned", description="Hardware ID removed from the global ban list.", color=discord.Color.green())
        e.add_field(name="Removed By", value=str(i.user), inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="extend", description="[ADMIN] Set or extend a user's expiry date.")
@app_commands.describe(user="Target user", expires="New expiry YYYY-MM-DD")
@admin_only()
async def cmd_extend(i: discord.Interaction, user: discord.User, expires: str):
    await i.response.defer(ephemeral=True)
    exp_iso = parse_date(expires)
    if not exp_iso:
        await i.followup.send(embed=err_embed("Invalid Date", "Use the format `YYYY-MM-DD` e.g. `2026-12-31`."), ephemeral=True)
        return
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET expires_at=?, status='active', ban_reason=NULL WHERE discord_id=?", (exp_iso, did))
    DB.commit()
    audit("EXTEND", actor_id=str(i.user.id), target_id=did, detail=f"new_expiry={expires}")
    e = discord.Embed(title="Expiry Updated", description="License status set to active with the new expiry date.", color=discord.Color.green())
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="New Expiry", value=f"`{expires}`", inline=True)
    e.add_field(name="Updated By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="setproduct", description="[ADMIN] Change a user's product tier.")
@app_commands.describe(user="Target user", product="New product name")
@admin_only()
async def cmd_setproduct(i: discord.Interaction, user: discord.User, product: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET product=? WHERE discord_id=?", (product, did))
    DB.commit()
    audit("SET_PRODUCT", actor_id=str(i.user.id), target_id=did, detail=f"product={product}")
    prod_icon = "🌐" if product == "public" else "🔒"
    e = discord.Embed(title="Product Updated", description="Tier change takes effect on next loader launch.", color=BRAND_COLOR)
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="New Product", value=f"{prod_icon} `{product}`", inline=True)
    e.add_field(name="Updated By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="grantresets", description="[ADMIN] Give a user extra HWID reset uses.")
@app_commands.describe(user="Target user", count="Adjust reset counter by this amount (negative = grant more)")
@admin_only()
async def cmd_grantresets(i: discord.Interaction, user: discord.User, count: int = -1):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT hwid_resets FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    old_val = row["hwid_resets"]
    new_val = max(0, old_val + count)
    DB.execute("UPDATE users SET hwid_resets=? WHERE discord_id=?", (new_val, did))
    DB.commit()
    audit("GRANT_RESETS", actor_id=str(i.user.id), target_id=did, detail=f"delta={count} new_val={new_val}")
    max_r = CONFIG["max_hwid_resets"]
    slots_left = max(0, max_r - new_val)
    e = discord.Embed(
        title="HWID Resets Updated",
        description=f"Counter adjusted by `{count:+d}`. User now has `{slots_left}` reset slot(s) remaining.",
        color=BRAND_COLOR
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Counter", value=f"`{old_val}` -> `{new_val}`", inline=True)
    e.add_field(name="Updated By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="fac", description="[ADMIN] Manage FAC reset authorization for a user.")
@app_commands.describe(
    action="Action to perform",
    user="Target user",
    reason="Reason (required for authorize; optional for revoke)",
    ticket="Ticket ID or reference (optional, for authorize)"
)
@app_commands.choices(action=[
    app_commands.Choice(name="authorize (no payment) - ticket approved, free FAC auth",   value="authorize_free"),
    app_commands.Choice(name="authorize (paid)       - payment received, FAC + role",     value="authorize_paid"),
    app_commands.Choice(name="reset (no payment)     - clear HWID, free reset",           value="reset_free"),
    app_commands.Choice(name="reset (paid)           - clear HWID, payment + role",       value="reset_paid"),
    app_commands.Choice(name="revoke                 - remove their FAC auth",            value="revoke"),
    app_commands.Choice(name="check                  - view current status",              value="check"),
])
@admin_only()
async def cmd_fac(i: discord.Interaction, action: str, user: discord.User,
                  reason: Optional[str] = None, ticket: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    action = action.lower().strip()
    if action not in ("authorize_free", "authorize_paid", "reset_free", "reset_paid", "revoke", "check"):
        await i.followup.send(embed=err_embed("Invalid Action", "Pick an option from the dropdown."), ephemeral=True)
        return

    did = str(user.id)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return

    if action in ("authorize_free", "authorize_paid"):
        paid = action == "authorize_paid"
        if not reason:
            await i.followup.send(embed=err_embed("Reason Required", "A reason is required when authorizing a FAC reset."), ephemeral=True)
            return
        if row["fac_reset_auth"]:
            e = discord.Embed(
                title="Already Authorized",
                description=f"<@{did}> already has an active FAC reset authorization. Revoke it first if you need to re-issue.",
                color=discord.Color.orange()
            )
            e.add_field(name="FAC Auth Key", value=f"`{row['fac_auth_key']}`", inline=False)
            await i.followup.send(embed=e, ephemeral=True)
            return
        DB.execute("UPDATE users SET fac_reset_auth=1 WHERE discord_id=?", (did,))
        DB.commit()
        detail = f"paid={paid} reason={reason}" + (f" ticket={ticket}" if ticket else "")
        audit("FAC_AUTH_GRANTED", actor_id=str(i.user.id), target_id=did, detail=detail)

        role_assigned = False
        if paid:
            fac_role_id = CONFIG.get("fac_paid_role_id")
            if fac_role_id:
                fac_role = i.guild.get_role(fac_role_id)
                if fac_role:
                    try:
                        member = await _get_member(i.guild, user.id)
                        if member:
                            await member.add_roles(fac_role, reason=f"FAC paid - authorized by {i.user}")
                            role_assigned = True
                    except Exception as re:
                        log.warning("Failed to assign FAC paid role: %s", re)

        auth_type = "Payment Received" if paid else "Ticket Approved (No Payment)"
        e = discord.Embed(
            title="FAC Reset Authorized",
            description=(
                "Payment confirmed - FAC reset approved and role assigned." if paid
                else "Ticket approved - FAC reset authorized, no payment required."
            ),
            color=discord.Color.green()
        )
        e.add_field(name="User",          value=f"<@{did}> (`{did}`)", inline=False)
        e.add_field(name="Auth Type",     value=auth_type,             inline=True)
        e.add_field(name="Authorized By", value=str(i.user),           inline=True)
        if ticket:
            e.add_field(name="Ticket",    value=ticket,                inline=True)
        e.add_field(name="Reason",        value=reason,                inline=False)
        e.add_field(name="FAC Auth Key",  value=f"`{row['fac_auth_key']}`", inline=True)
        if paid:
            e.add_field(name="Role Assigned", value="Yes" if role_assigned else "Failed - check bot permissions", inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)
        await BOT.log_embed(e)
        try:
            dm_e = discord.Embed(
                title="FAC Reset Approved",
                description=(
                    "Your payment has been received and your hardware reset request has been approved."
                    if paid else
                    "Your request to reset your hardware ID has been approved. Present your auth key when prompted by the loader."
                ),
                color=discord.Color.green()
            )
            dm_e.add_field(name="FAC Auth Key", value=f"`{row['fac_auth_key']}`", inline=False)
            dm_e.set_footer(text="Contact support if you encounter any issues.")
            await user.send(embed=dm_e)
        except Exception:
            pass

    elif action in ("reset_free", "reset_paid"):
        paid = action == "reset_paid"
        DB.execute("UPDATE users SET hwid=NULL, hwid_resets=hwid_resets+1 WHERE discord_id=?", (did,))
        DB.commit()
        detail = f"paid={paid}" + (f" reason={reason}" if reason else "") + (f" ticket={ticket}" if ticket else "")
        audit("HWID_RESET_FAC", actor_id=str(i.user.id), target_id=did, detail=detail)

        role_assigned = False
        if paid:
            hwid_role_id = CONFIG.get("hwid_paid_role_id")
            if hwid_role_id:
                hwid_role = i.guild.get_role(hwid_role_id)
                if hwid_role:
                    try:
                        member = await _get_member(i.guild, user.id)
                        if member:
                            await member.add_roles(hwid_role, reason=f"HWID reset paid - authorized by {i.user}")
                            role_assigned = True
                    except Exception as re:
                        log.warning("Failed to assign HWID paid role: %s", re)

        reset_type = "Payment Received" if paid else "Ticket Approved (No Payment)"
        e = discord.Embed(
            title="HWID Reset Approved",
            description=(
                "Payment confirmed - HWID cleared and role assigned. User can bind a new machine on next launch."
                if paid else
                "Ticket approved - HWID cleared. User can bind a new machine on next launch."
            ),
            color=discord.Color.green()
        )
        e.add_field(name="User",       value=f"<@{did}> (`{did}`)", inline=False)
        e.add_field(name="Reset Type", value=reset_type,            inline=True)
        e.add_field(name="Reset By",   value=str(i.user),           inline=True)
        if ticket:
            e.add_field(name="Ticket", value=ticket,                inline=True)
        if reason:
            e.add_field(name="Reason", value=reason,                inline=False)
        if paid:
            e.add_field(name="Role Assigned", value="Yes" if role_assigned else "Failed - check bot permissions", inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)
        await BOT.log_embed(e)
        try:
            dm_e = discord.Embed(
                title="HWID Reset Approved",
                description=(
                    "Your payment has been received and your hardware reset has been approved. Launch the loader to bind your new machine."
                    if paid else
                    "Your HWID reset request has been approved. Launch the loader to bind your new machine."
                ),
                color=discord.Color.green()
            )
            dm_e.set_footer(text="Contact support if you encounter any issues.")
            await user.send(embed=dm_e)
        except Exception:
            pass

    elif action == "revoke":
        if not row["fac_reset_auth"]:
            await i.followup.send(embed=warn_embed("Not Authorized", f"<@{did}> does not have an active FAC authorization to revoke."), ephemeral=True)
            return
        DB.execute("UPDATE users SET fac_reset_auth=0 WHERE discord_id=?", (did,))
        DB.commit()
        audit("FAC_AUTH_REVOKED", actor_id=str(i.user.id), target_id=did, detail=reason or "No reason given")
        e = discord.Embed(
            title="FAC Authorization Revoked",
            description="User can no longer perform a FAC-authorized hardware reset.",
            color=discord.Color.orange()
        )
        e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
        e.add_field(name="Reason", value=reason or "No reason given", inline=True)
        e.add_field(name="Revoked By", value=str(i.user), inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)
        await BOT.log_embed(e)

    else:  # check
        authorized = bool(row["fac_reset_auth"])
        status_str = "Authorized" if authorized else "Not Authorized"
        e = discord.Embed(
            title="FAC Reset Status",
            description=f"<@{did}> (`{did}`)",
            color=discord.Color.green() if authorized else discord.Color.red()
        )
        e.add_field(name="FAC Status", value=f"{'✅' if authorized else '❌'} {status_str}", inline=True)
        e.add_field(name="FAC Auth Key", value=f"`{row['fac_auth_key']}`" if row["fac_auth_key"] else "N/A", inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="listusers", description="[ADMIN] Browse registered users.")
@app_commands.describe(status="Filter: active, banned, revoked", product="Filter by product", limit="Results to show (max 25)")
@admin_only()
async def cmd_listusers(i: discord.Interaction,
                        status: Optional[str] = None,
                        product: Optional[str] = None,
                        limit: app_commands.Range[int, 1, 25] = 15):
    await i.response.defer(ephemeral=True)
    q = "SELECT * FROM users WHERE 1=1"
    p = []
    if status:
        q += " AND status=?"; p.append(status)
    if product:
        q += " AND product=?"; p.append(product)
    q += " ORDER BY registered_at DESC LIMIT ?"; p.append(limit)
    rows = DB.execute(q, p).fetchall()
    if not rows:
        await i.followup.send(embed=err_embed("No Users Found", "No users match that filter."), ephemeral=True)
        return
    lines = []
    for r in rows:
        s = effective_status(r)
        lines.append(f"{status_emoji(s)} `{r['discord_id']}` - {r['product']} - expires {fmt_dt(r['expires_at'])}")
    filters = []
    if status: filters.append(f"status: {status}")
    if product: filters.append(f"product: {product}")
    desc = ("Filters: " + ", ".join(filters) + "\n\n") if filters else ""
    desc += "\n".join(lines)
    e = discord.Embed(title="Registered Users", description=desc, color=BRAND_COLOR)
    e.set_footer(text=f"{len(rows)} result(s) shown - {ts()}")
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="listkeys", description="[ADMIN] Browse unclaimed keys in the pool.")
@app_commands.describe(product="Filter by product", limit="Max results (1-50)")
@admin_only()
async def cmd_listkeys(i: discord.Interaction,
                       product: Optional[str] = None,
                       limit: app_commands.Range[int, 1, 50] = 20):
    await i.response.defer(ephemeral=True)
    q = "SELECT * FROM key_pool WHERE claimed=0"
    p = []
    if product:
        q += " AND product=?"; p.append(product)
    q += " ORDER BY created_at DESC LIMIT ?"; p.append(limit)
    rows = DB.execute(q, p).fetchall()
    if not rows:
        await i.followup.send(embed=warn_embed("No Unclaimed Keys", "The key pool is empty" + (f" for product `{product}`" if product else "") + "."), ephemeral=True)
        return
    lines = []
    for r in rows:
        vis_icon = "🌐" if r["visibility"] == "public" else "🔒"
        lines.append(f"{vis_icon} `{r['key']}` - {r['product']} - expires {fmt_dt(r['expires_at'])}")
    desc = (f"Filtered to product: `{product}`\n\n" if product else "") + "\n".join(lines)
    e = discord.Embed(title="Key Pool", description=desc, color=BRAND_COLOR)
    e.set_footer(text=f"{len(rows)} unclaimed key(s) shown - {ts()}")
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="deletekey", description="[ADMIN] Delete an unclaimed key from the pool.")
@app_commands.describe(key="The key to delete")
@admin_only()
async def cmd_deletekey(i: discord.Interaction, key: str):
    await i.response.defer(ephemeral=True)
    cur = DB.execute("DELETE FROM key_pool WHERE key=? AND claimed=0", (key.strip().upper(),))
    DB.commit()
    if cur.rowcount == 0:
        await i.followup.send(embed=err_embed("Not Found", "Key not found in the pool or already claimed."), ephemeral=True)
        return
    audit("DELETE_KEY", actor_id=str(i.user.id), detail=f"key={key[:20]}")
    e = discord.Embed(title="Key Deleted", description="The key has been permanently removed from the pool.", color=discord.Color.red())
    e.add_field(name="Key", value=f"`{key.strip().upper()}`", inline=False)
    e.add_field(name="Deleted By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="auditlog", description="[ADMIN] View audit log with optional filters.")
@app_commands.describe(limit="Entries to show (max 25)", user="Filter by Discord mention or ID", action="Filter by action keyword e.g. BAN")
@admin_only()
async def cmd_auditlog(i: discord.Interaction,
                       limit: app_commands.Range[int, 1, 25] = 15,
                       user: Optional[str] = None,
                       action: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    q = "SELECT * FROM audit_log WHERE 1=1"
    p = []
    if user:
        clean = user.strip().lstrip("<@!").rstrip(">")
        q += " AND (actor_id=? OR target_id=?)"; p += [clean, clean]
    if action:
        q += " AND action LIKE ?"; p.append(f"%{action.upper()}%")
    q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
    rows = DB.execute(q, p).fetchall()
    if not rows:
        await i.followup.send(embed=err_embed("No Entries Found", "No audit entries match that filter."), ephemeral=True)
        return
    lines = []
    for r in rows:
        stamp = r["timestamp"][:16].replace("T", " ")
        actor = r["actor_id"] or "-"
        detail = f" | {r['detail'][:40]}" if r["detail"] else ""
        lines.append(f"[{stamp}] {r['action']} | {actor}{detail}")
    filters = []
    if user: filters.append(f"user: {user}")
    if action: filters.append(f"action: {action}")
    desc = ("Filters: " + ", ".join(filters) + "\n\n") if filters else ""
    desc += "```\n" + "\n".join(lines) + "\n```"
    e = discord.Embed(title="Audit Log", description=desc, color=BRAND_COLOR)
    e.set_footer(text=f"{len(rows)} entries shown - {ts()}")
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="stats", description="[ADMIN] Full system stats.")
@admin_only()
async def cmd_stats(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    total   = DB.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active  = DB.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    banned  = DB.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0]
    revoked = DB.execute("SELECT COUNT(*) FROM users WHERE status='revoked'").fetchone()[0]
    unclaim = DB.execute("SELECT COUNT(*) FROM key_pool WHERE claimed=0").fetchone()[0]
    claimed = DB.execute("SELECT COUNT(*) FROM key_pool WHERE claimed=1").fetchone()[0]
    hwbans  = DB.execute("SELECT COUNT(*) FROM hwid_bans").fetchone()[0]
    logs    = DB.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    today   = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logins_today = DB.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action='API_VERIFY_OK' AND timestamp LIKE ?",
        (today + "%",)
    ).fetchone()[0]
    regs_today = DB.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action='REGISTER_SUCCESS' AND timestamp LIKE ?",
        (today + "%",)
    ).fetchone()[0]
    e = discord.Embed(title="System Overview", description="Live snapshot of all license, key, and activity data.", color=BRAND_COLOR)
    e.add_field(name="Total Users",          value=str(total),         inline=True)
    e.add_field(name="Active",               value=str(active),        inline=True)
    e.add_field(name="Banned",               value=str(banned),        inline=True)
    e.add_field(name="Revoked",              value=str(revoked),       inline=True)
    e.add_field(name="Unclaimed Keys",       value=str(unclaim),       inline=True)
    e.add_field(name="Claimed Keys",         value=str(claimed),       inline=True)
    e.add_field(name="HWID/IP Bans",         value=str(hwbans),        inline=True)
    e.add_field(name="Audit Entries",        value=str(logs),          inline=True)
    e.add_field(name="​",               value="​",           inline=True)
    e.add_field(name="Logins Today",         value=str(logins_today),  inline=True)
    e.add_field(name="Registrations Today",  value=str(regs_today),    inline=True)
    e.add_field(name="​",               value="​",           inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="announce",
    description="[ADMIN] Send a styled embed announcement to any channel.")
@app_commands.describe(
    channel="Target channel",
    title="Announcement title",
    message="Body (use \\n for new lines)",
    color="Hex accent color e.g. 00ff88"
)
@admin_only()
async def cmd_announce(i: discord.Interaction,
                       channel: discord.TextChannel,
                       title: str, message: str,
                       color: Optional[str] = "00ff88"):
    await i.response.defer(ephemeral=True)
    try:
        c = int(color.lstrip("#"), 16)
        dc = discord.Color(c)
    except Exception:
        dc = discord.Color.green()
    body_text = message.replace("\\n", "\n")
    ann_embed = discord.Embed(title=title, description=body_text, color=dc)
    ann_embed.set_footer(text=i.guild.name)
    await channel.send(embed=ann_embed)
    audit("ANNOUNCE", actor_id=str(i.user.id), detail=f"channel={channel.id} title={title[:50]}")
    e = discord.Embed(title="Announcement Sent", description=f"Your announcement has been posted to {channel.mention}.", color=discord.Color.green())
    e.add_field(name="Title", value=title, inline=True)
    e.add_field(name="Channel", value=channel.mention, inline=True)
    e.add_field(name="Sent By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="purgeexpired",
    description="[ADMIN] Revoke all expired licenses and strip roles now.")
@admin_only()
async def cmd_purgeexpired(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    rows = DB.execute(
        "SELECT * FROM users WHERE status='active' AND expires_at IS NOT NULL"
    ).fetchall()
    count = 0
    for row in rows:
        if is_expired(row):
            DB.execute("UPDATE users SET status='revoked', ban_reason='Manual purge: expired' WHERE discord_id=?",
                       (row["discord_id"],))
            count += 1
            try:
                m = await i.guild.fetch_member(int(row["discord_id"]))
                vr = i.guild.get_role(CONFIG["verified_role_id"])
                if vr and vr in m.roles:
                    await m.remove_roles(vr, reason="License expired")
            except Exception:
                pass
    DB.commit()
    audit("PURGE_EXPIRED", actor_id=str(i.user.id), detail=f"revoked {count}")
    e = discord.Embed(
        title="Purge Complete",
        description=f"Scanned all active licenses. `{count}` expired record(s) revoked and roles stripped.",
        color=discord.Color.orange()
    )
    e.add_field(name="Revoked", value=str(count), inline=True)
    e.add_field(name="Run By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="wipeuser",
    description="[ADMIN] Completely wipe a user's registration (frees their key).")
@app_commands.describe(user="Target user", confirm="Type CONFIRM to proceed")
@admin_only()
async def cmd_wipeuser(i: discord.Interaction, user: discord.User, confirm: str = ""):
    await i.response.defer(ephemeral=True)
    if confirm != "CONFIRM":
        await i.followup.send(embed=err_embed("Confirmation Required", "Pass `confirm: CONFIRM` to wipe a user. This action is permanent and cannot be undone."), ephemeral=True)
        return
    did = str(user.id)
    row = DB.execute("SELECT key FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record to wipe."), ephemeral=True)
        return
    DB.execute("DELETE FROM users WHERE discord_id=?", (did,))
    DB.execute("UPDATE key_pool SET claimed=0 WHERE key=?", (row["key"],))
    DB.commit()
    try:
        member = await _get_member(i.guild, user.id)
        if member:
            vr = i.guild.get_role(CONFIG["verified_role_id"])
            if vr and vr in member.roles:
                await member.remove_roles(vr, reason="KeyLock wipe")
    except Exception:
        pass
    audit("WIPE_USER", actor_id=str(i.user.id), target_id=did)
    e = discord.Embed(
        title="User Wiped",
        description="All registration data removed. Their key has been returned to the pool.",
        color=discord.Color.dark_red()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Key", value="Returned to pool", inline=True)
    e.add_field(name="Wiped By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


@app_commands.command(name="invite", description="[ADMIN] Get the bot invite URL.")
@admin_only()
async def cmd_invite(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    perms = discord.Permissions(
        send_messages=True,
        embed_links=True,
        manage_roles=True,
        read_messages=True,
        use_application_commands=True,
    )
    url = discord.utils.oauth_url(BOT.user.id, permissions=perms)
    e = discord.Embed(title="Bot Invite", description="Use this link to add the bot to another server.", color=BRAND_COLOR)
    e.add_field(name="Invite Link", value=url, inline=False)
    e.add_field(name="Permissions", value="Send Messages, Manage Roles, Read Messages, Slash Commands", inline=False)
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="test", description="[ADMIN] Simulate any loader event and show full user state.")
@app_commands.describe(
    event="LOGIN, HWID_MISMATCH, HWID_BANNED, IP_BANNED, STATUS_BLOCKED, DESTRUCT, INJECT_FAIL, CRASH, CHEAT_START, CHEAT_STOP",
    user="Target user",
    fake_ip="IP to simulate (default: 127.0.0.1)",
    fake_hwid="Raw HWID string to use (default: bound HWID or test value)",
    detail="Extra detail string for macro events"
)
@admin_only()
async def cmd_test(i: discord.Interaction,
                   event: str,
                   user: discord.User,
                   fake_ip: Optional[str] = "127.0.0.1",
                   fake_hwid: Optional[str] = None,
                   detail: Optional[str] = None):
    await i.response.defer(ephemeral=True)

    VALID_EVENTS = {
        "LOGIN", "HWID_MISMATCH", "HWID_BANNED", "IP_BANNED", "STATUS_BLOCKED",
        "DESTRUCT", "INJECT_FAIL", "CRASH", "CHEAT_START", "CHEAT_STOP"
    }
    event = event.upper().strip()
    if event not in VALID_EVENTS:
        opts = ", ".join(f"`{v}`" for v in sorted(VALID_EVENTS))
        await i.followup.send(embed=err_embed("Invalid Event", f"Valid events:\n{opts}"), ephemeral=True)
        return

    did = str(user.id)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record. Use `/seed` to create one."), ephemeral=True)
        return

    ip = fake_ip or "127.0.0.1"
    real_hwid_hash = row["hwid"] or hash_hwid("TEST_HWID_" + did)
    test_hwid_hash = hash_hwid(fake_hwid) if fake_hwid else real_hwid_hash
    fired: list[str] = []

    if event == "LOGIN":
        DB.execute(
            "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
            (did, real_hwid_hash, ip, now_iso(), row["product"], "ok")
        )
        DB.execute("UPDATE users SET last_seen=?, ip_last=? WHERE discord_id=?", (now_iso(), ip, did))
        DB.commit()
        fired.append("Login log entry written")
        fired.append("last_seen + ip_last updated")

    elif event == "HWID_MISMATCH":
        mismatch_hash = hash_hwid(fake_hwid or ("MISMATCH_TEST_" + did))
        DB.execute(
            "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
            (did, mismatch_hash, ip, now_iso(), row["product"], "hwid_mismatch")
        )
        DB.commit()
        fired.append("HWID mismatch log entry written")

    elif event in ("HWID_BANNED", "IP_BANNED", "STATUS_BLOCKED"):
        fired.append(f"{event} simulated (no DB change - check main bot loader logs)")

    else:
        fired.append(f"{event} macro event simulated (no DB change - check main bot loader logs)")

    audit(f"TEST_{event}", actor_id=str(i.user.id), target_id=did, detail=f"ip={ip}")

    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
    s = effective_status(row)
    total_ok  = DB.execute("SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status='ok'", (did,)).fetchone()[0]
    total_all = DB.execute("SELECT COUNT(*) FROM login_log WHERE discord_id=?", (did,)).fetchone()[0]
    failed    = total_all - total_ok
    recent_logs = DB.execute(
        "SELECT status, ip, timestamp FROM login_log WHERE discord_id=? ORDER BY id DESC LIMIT 5", (did,)
    ).fetchall()
    hwid_banned = bool(DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (real_hwid_hash,)).fetchone())
    ip_banned   = bool(DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (f"IP:{ip}",)).fetchone())

    prod_icon = PRODUCT_ICONS.get(row["product"], "🔑")
    e1 = discord.Embed(title=f"Simulated: {event}", description="Event fired. Check the main bot's loader log channel for loader-side embeds.", color=BRAND_COLOR)
    e1.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=False)
    e1.add_field(name="Simulated IP", value=f"`{ip}`", inline=True)
    e1.add_field(name="HWID", value=f"`{real_hwid_hash[:16]}...`", inline=True)
    e1.add_field(name="​", value="​", inline=True)
    e1.add_field(name="Actions Taken", value="\n".join(f"- {f}" for f in fired), inline=False)
    e1.set_footer(text=ts())

    e2 = discord.Embed(title="Live User State", description="Current DB state after the simulated event.", color=status_color(s))
    e2.add_field(name="Status", value=f"{status_emoji(s)} {s.upper()}", inline=True)
    e2.add_field(name="Product", value=f"{prod_icon} {row['product']}", inline=True)
    e2.add_field(name="Expires", value=fmt_dt(row["expires_at"]), inline=True)
    e2.add_field(name="Last Seen", value=fmt_ts(row["last_seen"]), inline=True)
    e2.add_field(name="Last IP", value=f"`{row['ip_last']}`" if row["ip_last"] else "N/A", inline=True)
    e2.add_field(name="FAC Auth", value=f"{'✅' if row['fac_reset_auth'] else '❌'} {'Authorized' if row['fac_reset_auth'] else 'Not Authorized'}", inline=True)
    e2.add_field(name="Sessions (ok)", value=str(total_ok), inline=True)
    e2.add_field(name="Failed Attempts", value=str(failed), inline=True)
    e2.add_field(name="​", value="​", inline=True)
    e2.add_field(name="HWID Banned", value="Yes" if hwid_banned else "No", inline=True)
    e2.add_field(name="IP Banned", value="Yes" if ip_banned else "No", inline=True)
    if row["ban_reason"]:
        e2.add_field(name="Ban Reason", value=row["ban_reason"], inline=False)
    e2.set_footer(text=ts())

    if recent_logs:
        log_lines = []
        for r in recent_logs:
            stamp = r["timestamp"][:16].replace("T", " ")
            log_lines.append(f"[{stamp}] {r['status']:20s} {r['ip']}")
        e3 = discord.Embed(title="Recent Login Log", description="```\n" + "\n".join(log_lines) + "\n```", color=BRAND_COLOR)
    else:
        e3 = discord.Embed(title="Recent Login Log", description="No login entries recorded yet.", color=BRAND_COLOR)
    e3.set_footer(text=f"Showing last {len(recent_logs)} of {total_all} entries")

    await i.followup.send(embeds=[e1, e2, e3], ephemeral=True)


@app_commands.command(name="seed", description="[ADMIN] Create a test user record for any Discord user so all commands work on them.")
@app_commands.describe(
    user="Target user to seed",
    product="Product tier (default: private)",
    duration="Lifetime, 1month, etc (default: lifetime)",
    fake_hwid="Raw HWID string to bind (default: auto-generated)",
    fake_ip="IP to record as last known (default: 127.0.0.1)"
)
@app_commands.autocomplete(duration=autocomplete_duration, product=autocomplete_product)
@admin_only()
async def cmd_seed(i: discord.Interaction,
                   user: discord.User,
                   product: str = "private",
                   duration: str = "lifetime",
                   fake_hwid: Optional[str] = None,
                   fake_ip: Optional[str] = "127.0.0.1"):
    await i.response.defer(ephemeral=True)
    did = str(user.id)

    existing = DB.execute("SELECT key FROM users WHERE discord_id=?", (did,)).fetchone()
    if existing:
        await i.followup.send(embed=warn_embed(
            "Already Registered",
            f"<@{did}> already has a license (`{existing['key']}`).\nUse `/lookup` to view or `/wipeuser` to reset first."
        ), ephemeral=True)
        return

    prod = product.lower().strip()
    dur_key = duration.lower().replace(" ", "")
    if dur_key not in DURATION_PRESETS:
        opts = ", ".join(f"`{k}`" for k in DURATION_PRESETS)
        await i.followup.send(embed=err_embed("Bad Duration", f"Choose one: {opts}"), ephemeral=True)
        return

    delta = DURATION_PRESETS[dur_key]
    exp_iso = None
    expires_label = "Lifetime"
    if delta is not None:
        exp_dt = datetime.now(timezone.utc) + delta
        exp_iso = exp_dt.isoformat()
        expires_label = exp_dt.strftime("%Y-%m-%d")

    k = gen_key(CONFIG["key_prefix"])
    ip = fake_ip or "127.0.0.1"
    hwid_raw = fake_hwid or f"SEED_HWID_{did}"
    hwid_hash = hash_hwid(hwid_raw)
    fac_key = gen_fac_key()

    DB.execute(
        "INSERT OR IGNORE INTO key_pool (key,product,visibility,created_at,expires_at,created_by,notes) VALUES (?,?,?,?,?,?,?)",
        (k, prod, prod, now_iso(), exp_iso, str(i.user.id), "Seeded test record")
    )
    DB.execute("UPDATE key_pool SET claimed=1 WHERE key=?", (k,))
    DB.execute(
        "INSERT INTO users (discord_id,key,hwid,product,status,registered_at,expires_at,ip_last,last_seen,fac_auth_key) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (did, k, hwid_hash, prod, "active", now_iso(), exp_iso, ip, now_iso(), fac_key)
    )
    DB.execute(
        "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
        (did, hwid_hash, ip, now_iso(), prod, "ok")
    )
    DB.commit()

    try:
        member = await _get_member(i.guild, user.id)
        if member:
            vr = i.guild.get_role(CONFIG["verified_role_id"])
            if vr:
                await member.add_roles(vr, reason="KeyLock seed")
    except Exception:
        pass

    audit("SEED_USER", actor_id=str(i.user.id), target_id=did,
          detail=f"product={prod} duration={dur_key}")

    prod_icon = PRODUCT_ICONS.get(prod, "🔑")
    e = discord.Embed(
        title="Test Record Seeded",
        description=f"<@{did}> is now fully registered. All commands and simulations will work on this user.",
        color=discord.Color.green()
    )
    e.add_field(name="Product",    value=f"{prod_icon} `{prod}`", inline=True)
    e.add_field(name="Expires",    value=f"`{expires_label}`",    inline=True)
    e.add_field(name="Seeded By",  value=str(i.user),             inline=True)
    e.add_field(name="License Key", value=f"`{k}`",               inline=False)
    e.add_field(name="HWID Bound", value=f"`{hwid_raw}`",         inline=True)
    e.add_field(name="Seeded IP",  value=f"`{ip}`",               inline=True)
    e.add_field(name="FAC Auth Key", value=f"`{fac_key}`",        inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


# ─── SLASH COMMANDS ───────────────────────────────────────────────────────────

@app_commands.command(name="panel", description="[STAFF] Post the ticket creation panel.")
@app_commands.describe(channel="Channel to post the panel in (defaults to current)")
@staff_only()
async def cmd_panel(i: discord.Interaction, channel: Optional[discord.TextChannel] = None):
    await i.response.defer(ephemeral=True)
    target = channel or i.channel
    e = discord.Embed(
        title="048 Support",
        description=(
            "Select a ticket type below to open a support ticket.\n\n"
            "**HWID Reset** - Rebind your loader to a new machine.\n"
            "**FAC Auth Reset** - Get a one-time hardware auth reset key.\n"
            "**General** - Any other question or issue.\n\n"
            "Free tickets are handled case by case. Paid tickets require payment before processing."
        ),
        color=BRAND_COLOR
    )
    e.set_footer(text="048 Support System")
    await target.send(embed=e, view=TicketTypeView())
    await i.followup.send(embed=ok_embed("Panel Posted", f"Panel sent to {target.mention}."), ephemeral=True)


@app_commands.command(name="infoboard", description="[STAFF] Post the staff command reference panel.")
@app_commands.describe(channel="Channel to post the infoboard in (defaults to current)")
@staff_only()
async def cmd_infoboard(i: discord.Interaction, channel: Optional[discord.TextChannel] = None):
    await i.response.defer(ephemeral=True)
    target = channel or i.channel
    payload = _build_infoboard_payload()
    msg_id = await _staff_post_v2(target, payload)
    if msg_id:
        await i.followup.send(
            embed=ok_embed("Infoboard Posted", f"Staff reference panel sent to {target.mention}."),
            ephemeral=True,
        )
    else:
        await i.followup.send(
            embed=err_embed("Post Failed", "Could not post the infoboard. Check bot permissions."),
            ephemeral=True,
        )


@app_commands.command(name="ticketlookup", description="[STAFF] Look up a user's license info from the main bot DB.")
@app_commands.describe(query="@mention or Discord ID")
@staff_only()
async def cmd_ticketlookup(i: discord.Interaction, query: str):
    await i.response.defer(ephemeral=True)
    clean = query.strip().lstrip("<@!").rstrip(">")
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (clean,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Found", f"No license record for `{query}`."), ephemeral=True)
        return

    did = row["discord_id"]
    total = DB.execute("SELECT COUNT(*) FROM login_log WHERE discord_id=?", (did,)).fetchone()[0]
    failed = DB.execute("SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status!='ok'", (did,)).fetchone()[0]
    open_ticket = DB.execute("SELECT channel_id, type, opened_at FROM tickets WHERE discord_id=? AND status='open'", (did,)).fetchone()
    past_tickets = DB.execute("SELECT COUNT(*) FROM tickets WHERE discord_id=?", (did,)).fetchone()[0]

    e = discord.Embed(
        title="License Lookup (Staff)",
        description=f"<@{did}> (`{did}`)",
        color=BRAND_COLOR
    )
    e.add_field(name="Status",      value=row["status"].upper(),                   inline=True)
    e.add_field(name="Product",     value=row["product"],                          inline=True)
    e.add_field(name="Expires",     value=(row["expires_at"] or "Never")[:10],     inline=True)
    e.add_field(name="HWID Bound",  value="Yes" if row["hwid"] else "No",         inline=True)
    e.add_field(name="FAC Auth",    value="✅ Active" if row["fac_reset_auth"] else "❌ None", inline=True)
    e.add_field(name="Logins",      value=f"{total - failed} ok / {failed} failed", inline=True)
    e.add_field(name="Open Ticket", value=f"<#{open_ticket['channel_id']}> ({TICKET_LABELS.get(open_ticket['type'], open_ticket['type'])})" if open_ticket else "None", inline=False)
    e.add_field(name="Past Tickets", value=str(past_tickets), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="tickets", description="[STAFF] List open tickets.")
@app_commands.describe(status="Filter by status (open, approved, closed)")
@staff_only()
async def cmd_tickets(i: discord.Interaction, status: str = "open"):
    await i.response.defer(ephemeral=True)
    rows = DB.execute(
        "SELECT * FROM tickets WHERE status=? ORDER BY id DESC LIMIT 20", (status,)
    ).fetchall()
    if not rows:
        await i.followup.send(embed=ok_embed("No Tickets", f"No tickets with status `{status}`."), ephemeral=True)
        return

    lines = []
    for r in rows:
        age = ""
        try:
            opened = datetime.fromisoformat(r["opened_at"])
            age_h = int((datetime.now(timezone.utc) - opened).total_seconds() / 3600)
            age = f" ({age_h}h ago)"
        except Exception:
            pass
        assigned = f" - <@{r['assigned_to']}>" if r["assigned_to"] else " - unassigned"
        lines.append(f"<#{r['channel_id']}> `{TICKET_LABELS.get(r['type'], r['type'])}` <@{r['discord_id']}>{assigned}{age}")

    e = discord.Embed(
        title=f"Tickets - {status.title()} ({len(rows)})",
        description="\n".join(lines),
        color=BRAND_COLOR
    )
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="addnote", description="[STAFF] Add a note to a user's license record (visible in main bot /lookup).")
@app_commands.describe(query="@mention or Discord ID", note="Note to append")
@staff_only()
async def cmd_addnote_staff(i: discord.Interaction, query: str, note: str):
    await i.response.defer(ephemeral=True)
    clean = query.strip().lstrip("<@!").rstrip(">")
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (clean,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Found", f"No license record for `{query}`."), ephemeral=True)
        return
    existing = row["notes"] or ""
    new_notes = (existing + "\n" if existing else "") + f"[{ts()}] [STAFF] {note}"
    DB.execute("UPDATE users SET notes=? WHERE discord_id=?", (new_notes, row["discord_id"]))
    DB.commit()
    audit_staff("NOTE_ADDED", actor_id=str(i.user.id), target_id=row["discord_id"], detail=note[:100])
    e = ok_embed("Note Added", f"Note appended to <@{row['discord_id']}>'s record. Visible in `/lookup` on the main bot.")
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="pin", description="[STAFF] Pin a message in any channel by message ID.")
@app_commands.describe(
    message_id="ID of the message to pin",
    channel="Channel the message is in (defaults to current channel)",
)
@staff_only()
async def cmd_pin(i: discord.Interaction, message_id: str, channel: Optional[discord.TextChannel] = None):
    await i.response.defer(ephemeral=True)
    target_channel = channel or i.channel
    try:
        mid = int(message_id.strip())
    except ValueError:
        await i.followup.send(embed=err_embed("Invalid ID", "Message ID must be a number."), ephemeral=True)
        return
    try:
        msg = await target_channel.fetch_message(mid)
    except discord.NotFound:
        await i.followup.send(
            embed=err_embed("Not Found", f"No message with ID `{mid}` found in {target_channel.mention}."),
            ephemeral=True,
        )
        return
    except discord.Forbidden:
        await i.followup.send(
            embed=err_embed("Missing Access", f"I can't read messages in {target_channel.mention}."),
            ephemeral=True,
        )
        return
    if msg.pinned:
        await i.followup.send(
            embed=warn_embed("Already Pinned", f"That message is already pinned in {target_channel.mention}."),
            ephemeral=True,
        )
        return
    try:
        await msg.pin(reason=f"Pinned by staff: {i.user} ({i.user.id})")
    except discord.Forbidden:
        await i.followup.send(
            embed=err_embed("Missing Permissions", "I need **Manage Messages** permission to pin."),
            ephemeral=True,
        )
        return
    except discord.HTTPException as ex:
        await i.followup.send(
            embed=err_embed("Pin Failed", f"Discord returned an error: {ex.text}"),
            ephemeral=True,
        )
        return
    # Build preview of pinned message
    preview = (msg.content[:120] + "...") if len(msg.content) > 120 else msg.content or "[no text content]"
    e = ok_embed("Message Pinned", f"Pinned in {target_channel.mention}.")
    e.add_field(name="Author", value=msg.author.mention, inline=True)
    e.add_field(name="Message", value=f"[Jump]({msg.jump_url})", inline=True)
    e.add_field(name="Preview", value=f"> {preview}", inline=False)
    e.set_footer(text=f"Pinned by {i.user} - {ts()}")
    await i.followup.send(embed=e, ephemeral=True)
    # Log to webhook
    log_e = discord.Embed(
        title="Message Pinned",
        description=f"{i.user.mention} pinned a message in {target_channel.mention}.",
        color=BRAND_COLOR,
    )
    log_e.add_field(name="Message Link", value=f"[Jump to Message]({msg.jump_url})", inline=True)
    log_e.add_field(name="Original Author", value=msg.author.mention, inline=True)
    log_e.add_field(name="Preview", value=f"> {preview}", inline=False)
    log_e.set_footer(text=f"Actor: {i.user} ({i.user.id}) - {ts()}")
    await webhook_log(log_e)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

ALL_COMMANDS = [
    # ticket commands
    cmd_panel, cmd_infoboard, cmd_ticketlookup, cmd_tickets, cmd_addnote_staff,
    # user commands (from main bot)
    cmd_register, cmd_mystatus,
    # admin commands (ported from main bot)
    cmd_keygen, cmd_lookup, cmd_ban, cmd_unban, cmd_revoke,
    cmd_addnote, cmd_resethwid, cmd_hwid,
    cmd_extend, cmd_setproduct, cmd_grantresets,
    cmd_fac,
    cmd_listusers, cmd_listkeys, cmd_deletekey,
    cmd_auditlog, cmd_stats, cmd_announce,
    cmd_purgeexpired, cmd_wipeuser, cmd_invite,
    cmd_test, cmd_seed,
    cmd_pin,
]

async def main():
    global DB, BOT
    DB  = init_db(CONFIG["db_path"])
    BOT = StaffBot()
    for cmd in ALL_COMMANDS:
        BOT.tree.add_command(cmd)
    async with BOT:
        await BOT.start(CONFIG["token"])

if __name__ == "__main__":
    asyncio.run(main())
