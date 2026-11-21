#!/usr/bin/env python3
"""
KeyLock v3 - Production Grade
Register once with key+HWID. Discord ID becomes permanent auth token.
"""

import discord
from discord.ext import commands, tasks
from discord import app_commands
import sqlite3
import hashlib
import secrets
import string
import logging
import asyncio
import json
import os
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

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
    "token":               env("DISCORD_TOKEN",        "YOUR_BOT_TOKEN"),
    "guild_id":            env_int("GUILD_ID"),
    "admin_role_id":       env_int("ADMIN_ROLE_ID"),
    "log_channel_id":      env_int("LOG_CHANNEL_ID"),
    "loader_log_channel_id": env_int("LOADER_LOG_CHANNEL_ID"),  # separate channel for all loader events
    "verified_role_id":    env_int("VERIFIED_ROLE_ID"),
    "banned_role_id":      env_int("BANNED_ROLE_ID"),
    "db_path":             env("DB_PATH",              "/data/keylock.db"),
    "max_hwid_resets":     env_int("MAX_HWID_RESETS",  1),
    "key_prefix":          env("KEY_PREFIX",           "KL"),
    "api_port":            env_int("PORT",             8080),
}

# ─── LOGGING ──────────────────────────────────────────────────────────────────

os.makedirs(os.path.dirname(os.path.abspath(CONFIG["db_path"])), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler("keylock.log"), logging.StreamHandler()],
)
log = logging.getLogger("KeyLock")

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
        -- migration: add visibility to existing DBs
        CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY);

        CREATE TABLE IF NOT EXISTS hwid_bans (
            hwid        TEXT PRIMARY KEY,
            reason      TEXT,
            banned_at   TEXT NOT NULL,
            banned_by   TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            action      TEXT NOT NULL,
            actor_id    TEXT,
            target_id   TEXT,
            ip          TEXT,
            detail      TEXT
        );
        CREATE TABLE IF NOT EXISTS login_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id  TEXT NOT NULL,
            hwid        TEXT,
            ip          TEXT,
            timestamp   TEXT NOT NULL,
            product     TEXT,
            status      TEXT NOT NULL DEFAULT 'ok'
        );
    """)
    conn.commit()
    # Live migration - add visibility column to existing deployments
    try:
        conn.execute("ALTER TABLE key_pool ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'")
        conn.commit()
        log.info("Migration: added key_pool.visibility column")
    except Exception:
        pass  # column already exists
    try:
        conn.execute("ALTER TABLE users ADD COLUMN fac_reset_auth INTEGER NOT NULL DEFAULT 0")
        conn.commit()
        log.info("Migration: added users.fac_reset_auth column")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN fac_auth_key TEXT")
        conn.commit()
        log.info("Migration: added users.fac_auth_key column")
    except Exception:
        pass
    log.info("Database ready: %s", path)
    return conn

DB: sqlite3.Connection = None

# ─── UTILS ────────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def fmt_dt(iso: Optional[str]) -> str:
    if not iso:
        return "Never"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d")
    except Exception:
        return iso[:10]

def fmt_ts(iso: Optional[str]) -> str:
    if not iso:
        return "N/A"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso[:16]

def hash_hwid(raw: str) -> str:
    return hashlib.sha256(raw.strip().lower().encode()).hexdigest()

def gen_key(prefix: str = "KL", segments: int = 4, seg_len: int = 5) -> str:
    charset = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(charset) for _ in range(seg_len)) for _ in range(segments)]
    return f"{prefix}-" + "-".join(parts)

def gen_fac_key() -> str:
    """Generate a unique FAC authorization key shown in the internal system."""
    charset = string.ascii_uppercase + string.digits
    token = "".join(secrets.choice(charset) for _ in range(16))
    return f"FAC-{token[:4]}-{token[4:8]}-{token[8:12]}-{token[12:16]}"

def is_expired(row) -> bool:
    if not row["expires_at"]:
        return False
    try:
        return datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"])
    except Exception:
        return False

def effective_status(row) -> str:
    if row["status"] in ("banned", "revoked"):
        return row["status"]
    if is_expired(row):
        return "expired"
    return row["status"]

def status_color(s: str) -> discord.Color:
    return {
        "active":  discord.Color.green(),
        "banned":  discord.Color.red(),
        "revoked": discord.Color.dark_gray(),
        "expired": discord.Color.orange(),
    }.get(s, discord.Color.blurple())

def status_emoji(s: str) -> str:
    return {
        "active":  "🟢",
        "banned":  "🔴",
        "revoked": "⚫",
        "expired": "🟠",
    }.get(s, "❓")

def audit(action: str, actor_id: str = None, target_id: str = None,
          ip: str = None, detail: str = None):
    DB.execute(
        "INSERT INTO audit_log (timestamp,action,actor_id,target_id,ip,detail) VALUES (?,?,?,?,?,?)",
        (now_iso(), action, actor_id, target_id, ip, detail)
    )
    DB.commit()
    log.info("[%s] actor=%s target=%s %s", action, actor_id, target_id, detail or "")

def parse_date(s: str) -> Optional[str]:
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return s + "T00:00:00+00:00"
    except ValueError:
        return None

# ─── EMBED HELPERS ────────────────────────────────────────────────────────────

def ts() -> str:
    """UTC timestamp string for embed footers."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def err_embed(title: str, description: str) -> discord.Embed:
    """Standard error embed - red with description text."""
    return discord.Embed(title=title, description=description, color=discord.Color.red())

def warn_embed(title: str, description: str) -> discord.Embed:
    """Standard warning embed - orange with description text."""
    return discord.Embed(title=title, description=description, color=discord.Color.orange())

def ok_embed(title: str, description: str = None) -> discord.Embed:
    """Standard success embed - green."""
    return discord.Embed(title=title, description=description, color=discord.Color.green())

# ─── BOT ──────────────────────────────────────────────────────────────────────

class KeyLock(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        # Server Members Intent - enable in Discord Dev Portal -> Bot -> Privileged Gateway Intents.
        # Bot still runs without it; member lookups in some commands will fall back to ID-only display.
        intents.members = True
        intents.message_content = False
        super().__init__(command_prefix="kl!", intents=intents)

    async def start(self, token: str, **kwargs):
        try:
            await super().start(token, **kwargs)
        except discord.errors.PrivilegedIntentsRequired:
            log.warning("Server Members Intent not enabled - retrying without it")
            self.intents.members = False
            await super().start(token, **kwargs)

    async def setup_hook(self):
        g = discord.Object(id=CONFIG["guild_id"])
        self.tree.copy_global_to(guild=g)
        expire_checker.start()

    async def on_ready(self):
        log.info("KeyLock online: %s (%d)", self.user, self.user.id)
        await self.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name="the vault")
        )
        perms = discord.Permissions(
            send_messages=True, embed_links=True,
            manage_roles=True, read_messages=True,
            use_application_commands=True,
        )
        url = discord.utils.oauth_url(self.user.id, permissions=perms)
        log.info("INVITE URL: %s", url)
        # Sync commands once after bot is fully connected
        try:
            g = discord.Object(id=CONFIG["guild_id"])
            synced = await self.tree.sync(guild=g)
            log.info("Commands synced: %d", len(synced))
        except Exception as e:
            log.error("Command sync failed: %s", e)

    async def log_embed(self, embed: discord.Embed):
        ch = self.get_channel(CONFIG["log_channel_id"])
        if ch:
            try:
                await ch.send(embed=embed)
            except Exception as e:
                log.warning("Log send failed: %s", e)

    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        """Global slash command error handler - prevents 'application did not respond'."""
        # CheckFailure means admin_only already sent the deny message - don't double-respond
        if isinstance(error, app_commands.CheckFailure):
            return
        log.error("Slash command error /%s: %s", interaction.command.name if interaction.command else "?", error)
        e = discord.Embed(
            title="Something went wrong",
            description="An internal error occurred. Please try again or contact an admin.",
            color=discord.Color.red()
        )
        try:
            if interaction.response.is_done():
                await interaction.followup.send(embed=e, ephemeral=True)
            else:
                await interaction.response.send_message(embed=e, ephemeral=True)
        except Exception:
            pass

BOT: KeyLock = None

# ─── ADMIN CHECK ──────────────────────────────────────────────────────────────

def admin_only():
    async def predicate(i: discord.Interaction) -> bool:
        rid = CONFIG["admin_role_id"]
        if not rid:
            if i.user.guild_permissions.administrator:
                return True
        else:
            role = i.guild.get_role(rid)
            if role and role in i.user.roles:
                return True
        # Deny - respond immediately (this is always the first response in the failed path)
        e = discord.Embed(
            title="Access Denied",
            description="You don't have permission to use this command.",
            color=discord.Color.red()
        )
        try:
            if not i.response.is_done():
                await i.response.send_message(embed=e, ephemeral=True)
            else:
                await i.followup.send(embed=e, ephemeral=True)
        except Exception:
            pass
        return False
    return app_commands.check(predicate)

# ─── BACKGROUND TASK ──────────────────────────────────────────────────────────

@tasks.loop(hours=1)
async def expire_checker():
    rows = DB.execute(
        "SELECT * FROM users WHERE status='active' AND expires_at IS NOT NULL"
    ).fetchall()
    guild = BOT.get_guild(CONFIG["guild_id"])
    if not guild:
        return
    for row in rows:
        if is_expired(row):
            DB.execute(
                "UPDATE users SET status='revoked', ban_reason='Auto: expired' WHERE discord_id=?",
                (row["discord_id"],)
            )
            DB.commit()
            audit("AUTO_EXPIRE", target_id=row["discord_id"], detail=f"expired at {row['expires_at']}")
            try:
                member = await guild.fetch_member(int(row["discord_id"]))
                vr = guild.get_role(CONFIG["verified_role_id"])
                if vr and vr in member.roles:
                    await member.remove_roles(vr, reason="License expired")
            except Exception:
                pass

# ─── USER COMMANDS ────────────────────────────────────────────────────────────

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
        audit("REGISTER_FAIL_BAD_KEY", actor_id=did, detail=f"key={key[:20]}")
        await i.followup.send(embed=err_embed(
            "Invalid Key",
            "That key doesn't exist or has already been used.\nContact support if you believe this is an error."
        ), ephemeral=True)
        return

    if DB.execute("SELECT 1 FROM users WHERE key=?", (key.strip().upper(),)).fetchone():
        audit("REGISTER_FAIL_KEY_TAKEN", actor_id=did)
        await i.followup.send(embed=err_embed(
            "Key Already Claimed",
            "That key is registered to another account. Contact support."
        ), ephemeral=True)
        return

    hashed = hash_hwid(hwid)
    if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
        audit("REGISTER_FAIL_HWID_BANNED", actor_id=did)
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

    audit("REGISTER_SUCCESS", actor_id=did, detail=f"key={key[:20]} product={pool['product']}")

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


# /resetmyhwid removed - members cannot self-reset HWID. Admins use /resethwid.


# ─── ADMIN COMMANDS ───────────────────────────────────────────────────────────

async def autocomplete_duration(i: discord.Interaction, current: str):
    options = ["1day", "3days", "1week", "2weeks", "1month", "3months", "6months", "1year", "lifetime"]
    return [
        app_commands.Choice(name=o, value=o)
        for o in options if current.lower() in o
    ]

async def autocomplete_product(i: discord.Interaction, current: str):
    options = ["private", "public"]
    return [
        app_commands.Choice(name=o, value=o)
        for o in options if current.lower() in o
    ]

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

@app_commands.command(name="keygen", description="[ADMIN] Generate a key and optionally DM it to a user.")
@app_commands.describe(
    product="private or public (both work in the loader)",
    duration="How long the key is valid for",
    deliver_to="DM the key directly to this user",
    notes="Admin notes attached to this key"
)
@app_commands.autocomplete(duration=autocomplete_duration, product=autocomplete_product)
@admin_only()
async def cmd_keygen(i: discord.Interaction,
                     product: str = "private",
                     duration: Optional[str] = "lifetime",
                     deliver_to: Optional[discord.Member] = None,
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

    # visibility mirrors product name for private/public, else default private
    vis = "public" if prod == "public" else "private"

    k = gen_key(CONFIG["key_prefix"])
    DB.execute(
        "INSERT OR IGNORE INTO key_pool (key,product,visibility,created_at,expires_at,created_by,notes) VALUES (?,?,?,?,?,?,?)",
        (k, prod, vis, now_iso(), exp_iso, str(i.user.id), notes)
    )
    DB.commit()
    audit("KEYGEN", actor_id=str(i.user.id), detail=f"product={prod} duration={dur_key}")

    # DM delivery
    prod_icon = "🌐" if prod == "public" else "🔒"
    dm_status = None
    if deliver_to:
        dm_embed = discord.Embed(
            title="Your License Key",
            description="Your key is ready. Open the loader and enter it to activate your license.",
            color=discord.Color.from_rgb(32, 34, 37),
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

    result_embed = discord.Embed(
        title="Key Generated",
        description=f"New `{prod}` key created and added to the pool.",
        color=discord.Color.green(),
    )
    result_embed.add_field(name="Product", value=f"{prod_icon} `{prod}`", inline=True)
    result_embed.add_field(name="Valid For", value=f"`{expires_label}`", inline=True)
    result_embed.add_field(name="​", value="​", inline=True)
    result_embed.add_field(name="License Key", value=f"```\n{k}\n```", inline=False)
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

    # Pull extra stats from DB
    total_ok = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status='ok'", (did,)
    ).fetchone()[0]
    total_all = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=?", (did,)
    ).fetchone()[0]
    failed = total_all - total_ok

    # Unique IPs
    all_ips = DB.execute(
        "SELECT DISTINCT ip FROM login_log WHERE discord_id=? AND ip IS NOT NULL", (did,)
    ).fetchall()
    ip_list = [r["ip"] for r in all_ips]

    # Alt detection (IP-shared)
    alts: list[str] = []
    if ip_list:
        placeholders = ",".join("?" * len(ip_list))
        alt_rows = DB.execute(
            f"SELECT DISTINCT discord_id FROM login_log WHERE ip IN ({placeholders}) AND discord_id != ?",
            ip_list + [did]
        ).fetchall()
        alts = [r["discord_id"] for r in alt_rows]

    # HWID-shared alts
    hwid_alts: list[str] = []
    if row["hwid"]:
        hwid_rows = DB.execute(
            "SELECT discord_id FROM users WHERE hwid=? AND discord_id != ?",
            (row["hwid"], did)
        ).fetchall()
        hwid_alts = [r["discord_id"] for r in hwid_rows]

    # Last 5 login entries
    recent = DB.execute(
        "SELECT status, ip, timestamp FROM login_log WHERE discord_id=? ORDER BY id DESC LIMIT 5", (did,)
    ).fetchall()

    # Recent audit actions targeting this user (last 5)
    audit_rows = DB.execute(
        "SELECT action, timestamp FROM audit_log WHERE target_id=? ORDER BY id DESC LIMIT 5", (did,)
    ).fetchall()

    # Discord member info
    try:
        member = await i.guild.fetch_member(int(did))
        disc_str = f"<@{did}> (`{member}` / `{did}`)"
        joined = member.joined_at.strftime("%Y-%m-%d") if member.joined_at else "Unknown"
        created = member.created_at.strftime("%Y-%m-%d")
        roles_str = ", ".join(r.name for r in member.roles if r.name != "@everyone") or "None"
        avatar_url = member.display_avatar.url
    except Exception:
        disc_str = f"<@{did}> (`{did}`)"
        joined = "Not in server"
        created = "Unknown"
        roles_str = "N/A"
        avatar_url = None

    prod_icon = PRODUCT_ICONS.get(row["product"], "🔑")
    has_alts = bool(alts or hwid_alts)

    # Description: status flag if anything's wrong
    flags = []
    if has_alts:        flags.append(f"⚠️ {len(alts)} IP-shared / {len(hwid_alts)} HWID-shared account(s) detected")
    if failed > 5:      flags.append(f"⚠️ {failed} failed login attempt(s)")
    if len(ip_list) > 3: flags.append(f"⚠️ {len(ip_list)} unique IPs on record")
    desc = disc_str + ("\n\n" + "\n".join(flags) if flags else "")

    e = discord.Embed(title="User Lookup", description=desc, color=status_color(s))
    if avatar_url:
        e.set_thumbnail(url=avatar_url)

    # Row 1 - license core
    e.add_field(name="Status",   value=f"{status_emoji(s)} {s.upper()}", inline=True)
    e.add_field(name="Product",  value=f"{prod_icon} {row['product']}",  inline=True)
    e.add_field(name="Expires",  value=fmt_dt(row["expires_at"]),         inline=True)

    # Row 2 - dates
    e.add_field(name="Registered", value=fmt_dt(row["registered_at"]), inline=True)
    e.add_field(name="Last Seen",  value=fmt_ts(row["last_seen"]),      inline=True)
    e.add_field(name="Last IP",    value=f"`{row['ip_last']}`" if row["ip_last"] else "N/A", inline=True)

    # Row 3 - hardware / FAC / session stats
    hwid_val = f"Bound - {row['hwid_resets']} reset(s) used" if row["hwid"] else "Not bound"
    fac_val  = f"{'✅' if row['fac_reset_auth'] else '❌'} Auth'd  |  Key: `{row['fac_auth_key']}`" if row["fac_auth_key"] else ("✅ Authorized" if row["fac_reset_auth"] else "❌ Not authorized")
    sess_val = f"{total_ok} ok / {failed} failed / {len(ip_list)} unique IP(s)"
    e.add_field(name="HWID",         value=hwid_val,  inline=True)
    e.add_field(name="FAC Reset",    value=fac_val,   inline=True)
    e.add_field(name="Sessions",     value=sess_val,  inline=True)

    # Row 4 - Discord info
    e.add_field(name="Account Created", value=created,         inline=True)
    e.add_field(name="Server Joined",   value=joined,          inline=True)
    e.add_field(name="Roles",           value=roles_str[:100], inline=True)

    # Known IPs (always show, helps spot multi-IP patterns)
    ip_str = "  ".join(f"`{ip_addr}`" for ip_addr in ip_list[:12]) if ip_list else "None on record"
    e.add_field(name=f"Known IPs ({len(ip_list)})", value=ip_str, inline=False)

    # Alt accounts (only if present)
    if alts:
        alt_str = " ".join(f"<@{a}>" for a in alts[:8])
        e.add_field(name=f"IP-Shared Accounts ({len(alts)})", value=alt_str, inline=False)
    if hwid_alts:
        h_str = " ".join(f"<@{a}>" for a in hwid_alts[:8])
        e.add_field(name=f"HWID-Shared Accounts ({len(hwid_alts)})", value=h_str, inline=False)

    # Key always full-width
    e.add_field(name="License Key", value=f"`{row['key']}`", inline=False)

    # Recent logins inline summary
    if recent:
        lines = []
        for r in recent:
            stamp = r["timestamp"][:16].replace("T", " ")
            lines.append(f"`{r['status']:15s}` {r['ip'] or 'N/A':>15s}  {stamp}")
        e.add_field(name="Recent Logins", value="```\n" + "\n".join(lines) + "\n```", inline=False)

    # Recent admin actions
    if audit_rows:
        a_lines = [f"`{r['action']}` - {r['timestamp'][:10]}" for r in audit_rows]
        e.add_field(name="Recent Actions", value="\n".join(a_lines), inline=False)

    # Ban reason + notes
    if row["ban_reason"]:
        e.add_field(name="Ban Reason", value=row["ban_reason"], inline=False)
    if row["notes"]:
        e.add_field(name="Notes", value=f"```{row['notes'][-300:]}```", inline=False)

    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="ban", description="[ADMIN] Ban a user - blocks loader, bans HWID + IP, kicks from server.")
@app_commands.describe(user="Target user", reason="Ban reason")
@admin_only()
async def cmd_ban(i: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return

    ban_reason = reason or "No reason given"

    # 1 - Mark license banned
    DB.execute("UPDATE users SET status='banned', ban_reason=? WHERE discord_id=?", (ban_reason, did))

    # 2 - Ban HWID if bound
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

    # 3 - Ban IP if on record
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

    # 4 - Strip roles + add banned role
    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        br = i.guild.get_role(CONFIG["banned_role_id"])
        if vr and vr in user.roles:
            await user.remove_roles(vr, reason="KeyLock ban")
        if br:
            await user.add_roles(br, reason="KeyLock ban")
    except Exception:
        pass

    # 5 - Kick from server
    kicked = False
    try:
        await user.kick(reason=f"KeyLock ban: {ban_reason}")
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
async def cmd_unban(i: discord.Interaction, user: discord.Member):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET status='active', ban_reason=NULL WHERE discord_id=?", (did,))
    DB.commit()
    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        br = i.guild.get_role(CONFIG["banned_role_id"])
        if vr:
            await user.add_roles(vr, reason="KeyLock unban")
        if br and br in user.roles:
            await user.remove_roles(br, reason="KeyLock unban")
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
async def cmd_revoke(i: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET status='revoked', ban_reason=? WHERE discord_id=?", (reason or "Revoked", did))
    DB.commit()
    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr and vr in user.roles:
            await user.remove_roles(vr, reason="KeyLock revoke")
    except Exception:
        pass
    audit("REVOKE", actor_id=str(i.user.id), target_id=did, detail=reason)
    e = discord.Embed(
        title="License Revoked",
        description="License permanently revoked. Verified role removed.",
        color=discord.Color.dark_gray()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=False)
    e.add_field(name="Reason", value=reason or "No reason given", inline=True)
    e.add_field(name="Revoked By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


@app_commands.command(name="addnote", description="[ADMIN] Append an admin note to a user.")
@app_commands.describe(user="Target user", note="Note text")
@admin_only()
async def cmd_addnote(i: discord.Interaction, user: discord.Member, note: str):
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
    e = discord.Embed(
        title="Note Added",
        description=f"```{note[:300]}```",
        color=discord.Color.blurple()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Added By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="resethwid", description="[ADMIN] Force-reset or rebind a user's HWID.")
@app_commands.describe(user="Target user", new_hwid="New HWID to bind (blank = clear)")
@admin_only()
async def cmd_resethwid(i: discord.Interaction, user: discord.Member, new_hwid: Optional[str] = None):
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
@app_commands.describe(action="ban or unban", raw_hwid="Raw HWID string from the loader", reason="Reason (required for ban)")
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
        e = discord.Embed(
            title="HWID Unbanned",
            description="Hardware ID removed from the global ban list.",
            color=discord.Color.green()
        )
        e.add_field(name="Removed By", value=str(i.user), inline=True)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="extend", description="[ADMIN] Set or extend a user's expiry date.")
@app_commands.describe(user="Target user", expires="New expiry YYYY-MM-DD")
@admin_only()
async def cmd_extend(i: discord.Interaction, user: discord.Member, expires: str):
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
    e = discord.Embed(
        title="Expiry Updated",
        description="License status set to active with the new expiry date.",
        color=discord.Color.green()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="New Expiry", value=f"`{expires}`", inline=True)
    e.add_field(name="Updated By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="setproduct", description="[ADMIN] Change a user's product tier.")
@app_commands.describe(user="Target user", product="New product name")
@admin_only()
async def cmd_setproduct(i: discord.Interaction, user: discord.Member, product: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return
    DB.execute("UPDATE users SET product=? WHERE discord_id=?", (product, did))
    DB.commit()
    audit("SET_PRODUCT", actor_id=str(i.user.id), target_id=did, detail=f"product={product}")
    prod_icon = "🌐" if product == "public" else "🔒"
    e = discord.Embed(
        title="Product Updated",
        description="Tier change takes effect on next loader launch.",
        color=discord.Color.blurple()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="New Product", value=f"{prod_icon} `{product}`", inline=True)
    e.add_field(name="Updated By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="grantresets", description="[ADMIN] Give a user extra HWID reset uses.")
@app_commands.describe(user="Target user", count="Adjust reset counter by this amount (negative = grant more)")
@admin_only()
async def cmd_grantresets(i: discord.Interaction, user: discord.Member, count: int = -1):
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
        color=discord.Color.blurple()
    )
    e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=True)
    e.add_field(name="Counter", value=f"`{old_val}` -> `{new_val}`", inline=True)
    e.add_field(name="Updated By", value=str(i.user), inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)


@app_commands.command(name="fac", description="[ADMIN] Manage FAC reset authorization for a user.")
@app_commands.describe(
    action="authorize, revoke, or check",
    user="Target user",
    reason="Reason (required for authorize; optional for revoke)",
    ticket="Ticket ID or reference (optional, for authorize)"
)
@admin_only()
async def cmd_fac(i: discord.Interaction, action: str, user: discord.Member,
                  reason: Optional[str] = None, ticket: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    action = action.lower().strip()
    if action not in ("authorize", "revoke", "check"):
        await i.followup.send(embed=err_embed("Invalid Action", "Use `authorize`, `revoke`, or `check`."), ephemeral=True)
        return

    did = str(user.id)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(embed=err_embed("Not Registered", "That user has no license record."), ephemeral=True)
        return

    if action == "authorize":
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
        detail = f"reason={reason}" + (f" ticket={ticket}" if ticket else "")
        audit("FAC_AUTH_GRANTED", actor_id=str(i.user.id), target_id=did, detail=detail)
        e = discord.Embed(
            title="FAC Reset Authorized",
            description="User has been approved for one hardware ID reset. They have been DM'd their auth key.",
            color=discord.Color.green()
        )
        e.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=False)
        e.add_field(name="Reason", value=reason, inline=True)
        if ticket:
            e.add_field(name="Ticket", value=ticket, inline=True)
        e.add_field(name="Authorized By", value=str(i.user), inline=True)
        e.add_field(name="FAC Auth Key", value=f"`{row['fac_auth_key']}`", inline=False)
        e.set_footer(text=ts())
        await i.followup.send(embed=e, ephemeral=True)
        await BOT.log_embed(e)
        try:
            dm_e = discord.Embed(
                title="FAC Reset Approved",
                description="Your request to reset your hardware ID has been approved. Present your auth key when prompted by the loader.",
                color=discord.Color.green()
            )
            dm_e.add_field(name="FAC Auth Key", value=f"`{row['fac_auth_key']}`", inline=False)
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
    e = discord.Embed(
        title=f"Registered Users",
        description=desc,
        color=discord.Color.blurple()
    )
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
    e = discord.Embed(
        title="Key Pool",
        description=desc,
        color=discord.Color.blurple()
    )
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
    e = discord.Embed(
        title="Key Deleted",
        description="The key has been permanently removed from the pool.",
        color=discord.Color.red()
    )
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
    e = discord.Embed(
        title="Audit Log",
        description=desc,
        color=discord.Color.dark_gray()
    )
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
    e = discord.Embed(
        title="System Overview",
        description=f"Live snapshot of all license, key, and activity data.",
        color=discord.Color.blurple()
    )
    e.add_field(name="Total Users", value=str(total), inline=True)
    e.add_field(name="Active", value=str(active), inline=True)
    e.add_field(name="Banned", value=str(banned), inline=True)
    e.add_field(name="Revoked", value=str(revoked), inline=True)
    e.add_field(name="Unclaimed Keys", value=str(unclaim), inline=True)
    e.add_field(name="Claimed Keys", value=str(claimed), inline=True)
    e.add_field(name="HWID/IP Bans", value=str(hwbans), inline=True)
    e.add_field(name="Audit Entries", value=str(logs), inline=True)
    e.add_field(name="​", value="​", inline=True)
    e.add_field(name="Logins Today", value=str(logins_today), inline=True)
    e.add_field(name="Registrations Today", value=str(regs_today), inline=True)
    e.add_field(name="​", value="​", inline=True)
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
    e = discord.Embed(
        title="Announcement Sent",
        description=f"Your announcement has been posted to {channel.mention}.",
        color=discord.Color.green()
    )
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
async def cmd_wipeuser(i: discord.Interaction, user: discord.Member, confirm: str = ""):
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
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr and vr in user.roles:
            await user.remove_roles(vr, reason="KeyLock wipe")
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
    e = discord.Embed(
        title="Bot Invite",
        description="Use this link to add the bot to another server.",
        color=discord.Color.blurple()
    )
    e.add_field(name="Invite Link", value=url, inline=False)
    e.add_field(name="Permissions", value="Send Messages, Manage Roles, Read Messages, Slash Commands", inline=False)
    await i.followup.send(embed=e, ephemeral=True)


async def _loader_log(embed: discord.Embed):
    """Send an embed to the dedicated loader event log channel."""
    ch = BOT.get_channel(CONFIG["loader_log_channel_id"]) or BOT.get_channel(CONFIG["log_channel_id"])
    if ch:
        try:
            await ch.send(embed=embed)
        except Exception as ex:
            log.warning("Loader log send failed: %s", ex)


async def _send_login_log(discord_id: str, ip: str, hwid_hash: str, product: str, expires_at: str):
    """Rich login event log - fires on every successful loader auth."""
    total_ok = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status='ok'", (discord_id,)
    ).fetchone()[0]
    total_all = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=?", (discord_id,)
    ).fetchone()[0]
    failed = total_all - total_ok

    # Previous IP for this user (second-most-recent ok login)
    prev = DB.execute(
        "SELECT ip FROM login_log WHERE discord_id=? AND status='ok' ORDER BY id DESC LIMIT 2",
        (discord_id,)
    ).fetchall()
    prev_ip = prev[1]["ip"] if len(prev) > 1 else None
    ip_changed = prev_ip and prev_ip != ip

    alert = ip_changed
    e = discord.Embed(
        title="Loader Login",
        description=("IP address changed since last session." if alert else "Successful authentication."),
        color=discord.Color.orange() if alert else discord.Color.green()
    )
    e.add_field(name="User", value=f"<@{discord_id}> (`{discord_id}`)", inline=False)
    e.add_field(name="Product", value=f"`{product}`", inline=True)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    e.add_field(name="HWID", value=f"`{hwid_hash[:16]}...`", inline=True)
    e.add_field(name="Expires", value=fmt_dt(expires_at), inline=True)
    e.add_field(name="Session #", value=str(total_ok), inline=True)
    e.add_field(name="Failed Attempts", value=str(failed), inline=True)
    if ip_changed:
        e.add_field(name="IP Change", value=f"`{prev_ip}` -> `{ip}`", inline=False)
    e.set_footer(text=ts())
    await _loader_log(e)


async def _send_hwid_mismatch_log(discord_id: str, ip: str, stored_hash: str, attempt_hash: str, product: str):
    """Log a HWID mismatch attempt - someone trying to auth from a different machine."""
    attempts = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status='hwid_mismatch'", (discord_id,)
    ).fetchone()[0]

    e = discord.Embed(
        title="HWID Mismatch",
        description="Auth blocked - hardware ID does not match the registered device.",
        color=discord.Color.red()
    )
    e.add_field(name="User", value=f"<@{discord_id}> (`{discord_id}`)", inline=False)
    e.add_field(name="Product", value=f"`{product}`", inline=True)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    e.add_field(name="Mismatch Attempts", value=str(attempts + 1), inline=True)
    e.add_field(name="Registered HWID", value=f"`{stored_hash[:16]}...`", inline=True)
    e.add_field(name="Attempted HWID", value=f"`{attempt_hash[:16]}...`", inline=True)
    e.set_footer(text=ts())
    await _loader_log(e)


async def _send_hwid_banned_log(discord_id: str, ip: str, hwid_hash: str):
    """Log a banned HWID hitting the loader."""
    e = discord.Embed(
        title="Banned HWID",
        description="Auth blocked - this hardware ID is on the ban list.",
        color=discord.Color.dark_red()
    )
    e.add_field(name="Discord ID", value=f"`{discord_id}`", inline=True)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    e.add_field(name="HWID", value=f"`{hwid_hash[:16]}...`", inline=True)
    e.set_footer(text=ts())
    await _loader_log(e)


async def _send_ip_banned_log(discord_id: str, ip: str):
    """Log a banned IP hitting the loader."""
    e = discord.Embed(
        title="Banned IP",
        description="Auth blocked - this IP address is on the ban list.",
        color=discord.Color.dark_red()
    )
    e.add_field(name="Discord ID", value=f"`{discord_id}`", inline=True)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    e.set_footer(text=ts())
    await _loader_log(e)


async def _send_status_blocked_log(discord_id: str, ip: str, hwid_hash: str, status: str, product: str):
    """Log a banned/revoked/expired account trying to open the loader."""
    color_map = {"banned": discord.Color.red(), "revoked": discord.Color.orange(), "expired": discord.Color.greyple()}
    e = discord.Embed(
        title=f"Account {status.upper()}",
        description=f"Auth blocked - account is {status} and cannot use the loader.",
        color=color_map.get(status, discord.Color.red())
    )
    e.add_field(name="User", value=f"<@{discord_id}> (`{discord_id}`)", inline=False)
    e.add_field(name="Status", value=f"`{status}`", inline=True)
    e.add_field(name="Product", value=f"`{product}`", inline=True)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    e.add_field(name="HWID", value=f"`{hwid_hash[:16]}...`", inline=True)
    e.set_footer(text=ts())
    await _loader_log(e)


async def _send_macro_event_log(event_type: str, discord_id: str, ip: str, product: str, detail: str = None):
    """Log macro-side events reported by the loader - destructs, injection failures, etc."""
    color_map = {
        "DESTRUCT":    discord.Color.dark_red(),
        "INJECT_FAIL": discord.Color.red(),
        "CRASH":       discord.Color.orange(),
        "CHEAT_START": discord.Color.green(),
        "CHEAT_STOP":  discord.Color.greyple(),
    }
    emoji_map = {
        "DESTRUCT":    "💣",
        "INJECT_FAIL": "❌",
        "CRASH":       "⚠️",
        "CHEAT_START": "▶️",
        "CHEAT_STOP":  "⏹️",
    }
    color = color_map.get(event_type, discord.Color.blurple())
    emoji = emoji_map.get(event_type, "📋")
    desc_map = {
        "DESTRUCT":    "Kill-switch triggered - macro self-destructed.",
        "INJECT_FAIL": "Macro failed to inject into the target process.",
        "CRASH":       "Macro reported an unexpected crash.",
        "CHEAT_START": "Macro started successfully.",
        "CHEAT_STOP":  "Macro stopped cleanly.",
    }
    e = discord.Embed(
        title=f"{emoji} {event_type}",
        description=desc_map.get(event_type, f"Macro event: {event_type}"),
        color=color
    )
    e.add_field(name="User", value=f"<@{discord_id}> (`{discord_id}`)", inline=False)
    e.add_field(name="Product", value=f"`{product}`", inline=True)
    e.add_field(name="IP", value=f"`{ip}`", inline=True)
    if detail:
        e.add_field(name="Detail", value=detail, inline=False)
    e.set_footer(text=ts())
    await _loader_log(e)


# ─── VERIFY API ───────────────────────────────────────────────────────────────

class VerifyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("API " + fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._out(200, {"status": "ok"})
            return

        if parsed.path == "/macro_event":
            self._handle_macro_event(parsed)
            return

        if parsed.path != "/verify":
            self._out(404, {"status": "not_found"})
            return

        q   = parse_qs(parsed.query)
        did = q.get("discord_id", [None])[0]
        raw = q.get("hwid",       [None])[0]
        ip  = self.client_address[0]

        if not did or not raw:
            self._out(400, {"status": "error", "message": "Missing discord_id or hwid"})
            return

        hashed = hash_hwid(raw)

        # Check IP ban first
        ip_ban_key = f"IP:{ip}"
        if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (ip_ban_key,)).fetchone():
            audit("API_VERIFY_IP_BANNED", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), None, "ip_banned"))
            DB.commit()
            asyncio.run_coroutine_threadsafe(_send_ip_banned_log(did, ip), BOT.loop)
            self._out(403, {"status": "ip_banned", "message": "IP address banned"})
            return

        # Check HWID ban
        if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
            audit("API_VERIFY_HWID_BANNED", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), None, "hwid_banned"))
            DB.commit()
            asyncio.run_coroutine_threadsafe(_send_hwid_banned_log(did, ip, hashed), BOT.loop)
            self._out(403, {"status": "hwid_banned", "message": "HWID banned"})
            return

        row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
        if not row:
            audit("API_VERIFY_NO_USER", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), None, "not_registered"))
            DB.commit()
            self._out(401, {"status": "not_registered", "message": "Discord account not registered"})
            return

        s = effective_status(row)
        if s in ("banned", "revoked", "expired"):
            audit(f"API_VERIFY_{s.upper()}", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), row["product"], s))
            DB.commit()
            asyncio.run_coroutine_threadsafe(
                _send_status_blocked_log(did, ip, hashed, s, row["product"]), BOT.loop
            )
            self._out(403, {"status": s, "message": f"Account {s}"})
            return

        if row["hwid"] and row["hwid"] != hashed:
            audit("API_VERIFY_HWID_MISMATCH", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), row["product"], "hwid_mismatch"))
            DB.commit()
            asyncio.run_coroutine_threadsafe(
                _send_hwid_mismatch_log(did, ip, row["hwid"], hashed, row["product"]), BOT.loop
            )
            self._out(403, {"status": "hwid_mismatch", "message": "HWID does not match registered machine"})
            return

        if not row["hwid"]:
            DB.execute("UPDATE users SET hwid=? WHERE discord_id=?", (hashed, did))

        now = now_iso()
        DB.execute("UPDATE users SET last_seen=?, ip_last=? WHERE discord_id=?", (now, ip, did))
        DB.execute(
            "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
            (did, hashed, ip, now, row["product"], "ok")
        )
        DB.commit()
        audit("API_VERIFY_OK", target_id=did, ip=ip, detail=f"product={row['product']}")

        asyncio.run_coroutine_threadsafe(
            _send_login_log(did, ip, hashed, row["product"], row["expires_at"]),
            BOT.loop
        )

        self._out(200, {
            "status":     "ok",
            "discord_id": row["discord_id"],
            "product":    row["product"],
            "expires_at": row["expires_at"],
        })

    def _handle_macro_event(self, parsed):
        """POST-style GET endpoint: loader reports macro events like destructs, crashes, starts."""
        q       = parse_qs(parsed.query)
        did     = q.get("discord_id", [None])[0]
        event   = q.get("event",      [None])[0]  # DESTRUCT, INJECT_FAIL, CRASH, CHEAT_START, CHEAT_STOP
        product = q.get("product",    ["unknown"])[0]
        detail  = q.get("detail",     [None])[0]
        ip      = self.client_address[0]

        if not did or not event:
            self._out(400, {"status": "error", "message": "Missing discord_id or event"})
            return

        event = event.upper()
        valid_events = {"DESTRUCT", "INJECT_FAIL", "CRASH", "CHEAT_START", "CHEAT_STOP"}
        if event not in valid_events:
            self._out(400, {"status": "error", "message": f"Unknown event. Valid: {', '.join(valid_events)}"})
            return

        audit(f"MACRO_{event}", target_id=did, ip=ip, detail=detail)
        asyncio.run_coroutine_threadsafe(
            _send_macro_event_log(event, did, ip, product, detail),
            BOT.loop
        )
        self._out(200, {"status": "ok"})

    def _out(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_api(port: int):
    server = HTTPServer(("0.0.0.0", port), VerifyHandler)
    log.info("API listening on :%d", port)
    server.serve_forever()


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

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
                   user: discord.Member,
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

    # ── Fire the correct log and write DB records ──────────────────────────────
    if event == "LOGIN":
        DB.execute(
            "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
            (did, real_hwid_hash, ip, now_iso(), row["product"], "ok")
        )
        DB.execute("UPDATE users SET last_seen=?, ip_last=? WHERE discord_id=?", (now_iso(), ip, did))
        DB.commit()
        await _send_login_log(did, ip, real_hwid_hash, row["product"], row["expires_at"])
        fired.append("Login log posted")
        fired.append("login_log entry written")
        fired.append("last_seen + ip_last updated")

    elif event == "HWID_MISMATCH":
        mismatch_hash = hash_hwid(fake_hwid or ("MISMATCH_TEST_" + did))
        DB.execute(
            "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
            (did, mismatch_hash, ip, now_iso(), row["product"], "hwid_mismatch")
        )
        DB.commit()
        await _send_hwid_mismatch_log(did, ip, real_hwid_hash, mismatch_hash, row["product"])
        fired.append("HWID mismatch log posted")
        fired.append("Stored hash vs attempt hash shown in log channel")

    elif event == "HWID_BANNED":
        await _send_hwid_banned_log(did, ip, test_hwid_hash)
        fired.append("HWID banned log posted (no DB change)")

    elif event == "IP_BANNED":
        await _send_ip_banned_log(did, ip)
        fired.append("IP banned log posted (no DB change)")

    elif event == "STATUS_BLOCKED":
        status = row["status"]
        await _send_status_blocked_log(did, ip, real_hwid_hash, status, row["product"])
        fired.append(f"Status blocked log posted (status={status})")

    else:
        # Macro events: DESTRUCT, INJECT_FAIL, CRASH, CHEAT_START, CHEAT_STOP
        macro_detail = detail or f"Simulated by {i.user}"
        await _send_macro_event_log(event, did, ip, row["product"], macro_detail)
        fired.append(f"{event} macro event log posted")

    audit(f"TEST_{event}", actor_id=str(i.user.id), target_id=did, detail=f"ip={ip}")

    # ── Re-fetch user row (may have changed) and build full state summary ──────
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

    # ── Embed 1: Test result ───────────────────────────────────────────────────
    e1 = discord.Embed(
        title=f"Simulated: {event}",
        description="Event fired. Check your loader log channel for the resulting embed.",
        color=discord.Color.blurple()
    )
    e1.add_field(name="User", value=f"<@{did}> (`{did}`)", inline=False)
    e1.add_field(name="Simulated IP", value=f"`{ip}`", inline=True)
    e1.add_field(name="HWID", value=f"`{real_hwid_hash[:16]}...`", inline=True)
    e1.add_field(name="​", value="​", inline=True)
    e1.add_field(name="Actions Taken", value="\n".join(f"- {f}" for f in fired), inline=False)
    e1.set_footer(text=ts())

    # ── Embed 2: Live user state ───────────────────────────────────────────────
    prod_icon = PRODUCT_ICONS.get(row["product"], "🔑")
    fac_status = "Authorized" if row["fac_reset_auth"] else "Not Authorized"
    e2 = discord.Embed(
        title="Live User State",
        description="Current DB state after the simulated event.",
        color=status_color(s)
    )
    e2.add_field(name="Status", value=f"{status_emoji(s)} {s.upper()}", inline=True)
    e2.add_field(name="Product", value=f"{prod_icon} {row['product']}", inline=True)
    e2.add_field(name="Expires", value=fmt_dt(row["expires_at"]), inline=True)
    e2.add_field(name="Last Seen", value=fmt_ts(row["last_seen"]), inline=True)
    e2.add_field(name="Last IP", value=f"`{row['ip_last']}`" if row["ip_last"] else "N/A", inline=True)
    e2.add_field(name="FAC Auth", value=f"{'✅' if row['fac_reset_auth'] else '❌'} {fac_status}", inline=True)
    e2.add_field(name="Sessions (ok)", value=str(total_ok), inline=True)
    e2.add_field(name="Failed Attempts", value=str(failed), inline=True)
    e2.add_field(name="​", value="​", inline=True)
    e2.add_field(name="HWID Banned", value="Yes" if hwid_banned else "No", inline=True)
    e2.add_field(name="IP Banned", value="Yes" if ip_banned else "No", inline=True)
    if row["ban_reason"]:
        e2.add_field(name="Ban Reason", value=row["ban_reason"], inline=False)
    e2.set_footer(text=ts())

    # ── Embed 3: Last 5 login_log entries ─────────────────────────────────────
    if recent_logs:
        log_lines = []
        for r in recent_logs:
            stamp = r["timestamp"][:16].replace("T", " ")
            log_lines.append(f"[{stamp}] {r['status']:20s} {r['ip']}")
        e3 = discord.Embed(
            title="Recent Login Log",
            description="```\n" + "\n".join(log_lines) + "\n```",
            color=discord.Color.dark_gray()
        )
    else:
        e3 = discord.Embed(
            title="Recent Login Log",
            description="No login entries recorded yet.",
            color=discord.Color.dark_gray()
        )
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
                   user: discord.Member,
                   product: str = "private",
                   duration: str = "lifetime",
                   fake_hwid: Optional[str] = None,
                   fake_ip: Optional[str] = "127.0.0.1"):
    await i.response.defer(ephemeral=True)
    did = str(user.id)

    # Already registered?
    existing = DB.execute("SELECT key FROM users WHERE discord_id=?", (did,)).fetchone()
    if existing:
        await i.followup.send(embed=warn_embed(
            "Already Registered",
            f"<@{did}> already has a license (`{existing['key']}`).\nUse `/lookup` or `/profile` to view, or `/wipeuser` to reset first."
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

    # Generate a key and insert directly into key_pool as claimed
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
    # Seed a login_log entry so lookups have history
    DB.execute(
        "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
        (did, hwid_hash, ip, now_iso(), prod, "ok")
    )
    DB.commit()

    # Grant verified role
    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr:
            await user.add_roles(vr, reason="KeyLock seed")
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
    e.add_field(name="Product", value=f"{prod_icon} `{prod}`", inline=True)
    e.add_field(name="Expires", value=f"`{expires_label}`", inline=True)
    e.add_field(name="Seeded By", value=str(i.user), inline=True)
    e.add_field(name="License Key", value=f"`{k}`", inline=False)
    e.add_field(name="HWID Bound", value=f"`{hwid_raw}`", inline=True)
    e.add_field(name="Seeded IP", value=f"`{ip}`", inline=True)
    e.add_field(name="FAC Auth Key", value=f"`{fac_key}`", inline=True)
    e.set_footer(text=ts())
    await i.followup.send(embed=e, ephemeral=True)
    await BOT.log_embed(e)


ALL_COMMANDS = [
    cmd_register, cmd_mystatus,
    cmd_keygen, cmd_lookup, cmd_ban, cmd_unban, cmd_revoke,
    cmd_addnote, cmd_resethwid, cmd_hwid,
    cmd_extend, cmd_setproduct, cmd_grantresets,
    cmd_fac,
    cmd_listusers, cmd_listkeys, cmd_deletekey,
    cmd_auditlog, cmd_stats, cmd_announce,
    cmd_purgeexpired, cmd_wipeuser, cmd_invite,
    cmd_test, cmd_seed,
]

async def main():
    global DB, BOT
    DB  = init_db(CONFIG["db_path"])
    BOT = KeyLock()
    for cmd in ALL_COMMANDS:
        BOT.tree.add_command(cmd)
    threading.Thread(target=start_api, args=(CONFIG["api_port"],), daemon=True).start()
    async with BOT:
        await BOT.start(CONFIG["token"])

if __name__ == "__main__":
    asyncio.run(main())
