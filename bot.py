#!/usr/bin/env python3
"""
KeyLock v3 - Production Grade + Components V2
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
    "token":            env("DISCORD_TOKEN",        "YOUR_BOT_TOKEN"),
    "guild_id":         env_int("GUILD_ID"),
    "admin_role_id":    env_int("ADMIN_ROLE_ID"),
    "log_channel_id":   env_int("LOG_CHANNEL_ID"),
    "verified_role_id": env_int("VERIFIED_ROLE_ID"),
    "banned_role_id":   env_int("BANNED_ROLE_ID"),
    "db_path":          env("DB_PATH",              "/data/keylock.db"),
    "max_hwid_resets":  env_int("MAX_HWID_RESETS",  1),
    "key_prefix":       env("KEY_PREFIX",           "KL"),
    "api_port":         env_int("PORT",             8080),
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
            ban_reason      TEXT
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

def simple_embed(color: discord.Color, *lines: str) -> discord.Embed:
    """One-liner alert embed."""
    e = discord.Embed(color=color, description="\n".join(lines))
    return e

def status_embed(color: discord.Color, title: str,
                 fields: list[tuple[str, str]], footer: str = None) -> discord.Embed:
    """Rich field embed."""
    e = discord.Embed(color=color, title=title)
    for label, value in fields:
        e.add_field(name=label, value=value, inline=False)
    if footer:
        e.set_footer(text=footer)
    return e

def list_embed(title: str, lines: list[str], color=discord.Color.blurple()) -> discord.Embed:
    """Code-block list embed."""
    chunk = "\n".join(lines)
    e = discord.Embed(color=color, title=title, description=f"```\n{chunk}\n```")
    return e

# Compat shims so every call site works unchanged
def cv2_send(embed: discord.Embed) -> dict:
    return {"embed": embed}

def SimpleView(color, *lines, **kw):
    return simple_embed(color, *lines)

def StatusView(color, title, fields, footer=None, **kw):
    return status_embed(color, title, fields, footer)

def KeyListView(title, lines, color=discord.Color.blurple(), **kw):
    return list_embed(title, lines, color)

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
        err_view = SimpleView(discord.Color.red(), "**Internal Error**",
                              "Something went wrong. Please try again.")
        try:
            if interaction.response.is_done():
                await interaction.followup.send(**cv2_send(err_view), ephemeral=True)
            else:
                await interaction.response.send_message(**cv2_send(err_view), ephemeral=True)
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
        no_perm_view = SimpleView(
            discord.Color.red(),
            "**Access Denied**",
            "You don't have permission to use that command.",
        )
        try:
            if not i.response.is_done():
                await i.response.send_message(**cv2_send(no_perm_view), ephemeral=True)
            else:
                await i.followup.send(**cv2_send(no_perm_view), ephemeral=True)
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
        view = SimpleView(
            discord.Color.orange(),
            "**Already Registered**",
            "Your Discord account already has an active license.",
            "Use `/mystatus` to check it."
        )
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    pool = DB.execute("SELECT * FROM key_pool WHERE key=? AND claimed=0", (key.strip().upper(),)).fetchone()
    if not pool:
        audit("REGISTER_FAIL_BAD_KEY", actor_id=did, detail=f"key={key[:20]}")
        view = SimpleView(
            discord.Color.red(),
            "**Invalid Key**",
            "That key doesn't exist or has already been used.",
            "Contact support if you think this is a mistake."
        )
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    if DB.execute("SELECT 1 FROM users WHERE key=?", (key.strip().upper(),)).fetchone():
        audit("REGISTER_FAIL_KEY_TAKEN", actor_id=did)
        view = SimpleView(discord.Color.red(), "**Key Taken**", "That key is already registered to another account.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    hashed = hash_hwid(hwid)
    if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
        audit("REGISTER_FAIL_HWID_BANNED", actor_id=did)
        view = SimpleView(discord.Color.red(), "**Hardware Banned**", "Your hardware ID is banned. Contact support.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    if pool["expires_at"]:
        try:
            if datetime.now(timezone.utc) > datetime.fromisoformat(pool["expires_at"]):
                view = SimpleView(discord.Color.orange(), "**Key Expired**", "That key has expired. Contact support.")
                await i.followup.send(**cv2_send(view), ephemeral=True)
                return
        except Exception:
            pass

    DB.execute(
        "INSERT INTO users (discord_id,key,hwid,product,status,registered_at,expires_at) VALUES (?,?,?,?,?,?,?)",
        (did, key.strip().upper(), hashed, pool["product"], "active", now_iso(), pool["expires_at"])
    )
    DB.execute("UPDATE key_pool SET claimed=1 WHERE key=?", (key.strip().upper(),))
    DB.commit()

    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr:
            await i.user.add_roles(vr, reason="KeyLock: registered")
    except Exception as e:
        log.warning("Role grant failed: %s", e)

    audit("REGISTER_SUCCESS", actor_id=did, detail=f"key={key[:20]} product={pool['product']}")

    max_r = CONFIG["max_hwid_resets"]
    view = StatusView(
        discord.Color.green(),
        "License Activated",
        [
            ("Product", pool["product"]),
            ("Expires", fmt_dt(pool["expires_at"])),
            ("HWID Resets", str(max_r)),
            ("Auth Method", "Your **Discord ID** is now your license.\nKeep your account secure."),
        ],
        footer=f"{i.user} - {i.user.id}"
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)

    log_view = StatusView(
        discord.Color.green(),
        "New Registration",
        [
            ("User", f"<@{did}> ({did})"),
            ("Product", pool["product"]),
            ("Expires", fmt_dt(pool["expires_at"])),
        ]
    )
    await BOT.log_embed(log_view)


@app_commands.command(name="mystatus", description="Check your license status.")
async def cmd_mystatus(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (str(i.user.id),)).fetchone()
    if not row:
        view = SimpleView(
            discord.Color.red(),
            "**Not Registered**",
            "You don't have a license yet.",
            "Use `/register <key> <hwid>` to get started."
        )
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    s = effective_status(row)
    resets_left = max(0, CONFIG["max_hwid_resets"] - row["hwid_resets"])
    fields = [
        ("Status", f"{status_emoji(s)} {s.upper()}"),
        ("Product", row["product"]),
        ("Expires", fmt_dt(row["expires_at"])),
        ("Registered", fmt_dt(row["registered_at"])),
        ("Last Seen", fmt_ts(row["last_seen"])),
        ("HWID Resets Left", str(resets_left)),
    ]
    if row["ban_reason"]:
        fields.append(("Reason", row["ban_reason"]))

    view = StatusView(status_color(s), "Your License", fields, footer=f"ID: {i.user.id}")
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="resetmyhwid",
    description="Swap your HWID to a new machine (limited uses).")
@app_commands.describe(new_hwid="Your new Hardware ID from the launcher")
async def cmd_resetmyhwid(i: discord.Interaction, new_hwid: str):
    await i.response.defer(ephemeral=True)
    did = str(i.user.id)
    max_r = CONFIG["max_hwid_resets"]
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()

    if not row:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**", "You don't have a license.")), ephemeral=True)
        return

    s = effective_status(row)
    if s in ("banned", "revoked", "expired"):
        view = SimpleView(discord.Color.red(), f"**Account {s.upper()}**", "Contact an admin for help.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    if row["hwid_resets"] >= max_r:
        audit("HWID_RESET_DENIED", actor_id=did, detail=f"at max {max_r}")
        view = SimpleView(
            discord.Color.red(),
            "**No Resets Left**",
            f"You have used all `{max_r}` HWID reset(s).",
            "Contact an admin for a manual reset."
        )
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    hashed = hash_hwid(new_hwid)
    if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
        view = SimpleView(discord.Color.red(), "**Hardware Banned**", "That hardware ID is banned.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    DB.execute("UPDATE users SET hwid=?, hwid_resets=hwid_resets+1 WHERE discord_id=?", (hashed, did))
    DB.commit()
    audit("HWID_RESET_USER", actor_id=did, detail=f"reset #{row['hwid_resets']+1}")

    remaining = max_r - row["hwid_resets"] - 1
    view = StatusView(
        discord.Color.orange(),
        "HWID Updated",
        [
            ("New Machine", "Bound successfully"),
            ("Resets Remaining", str(remaining)),
            ("Next Step", "Launch the software on your new machine."),
        ]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)

    log_view = StatusView(
        discord.Color.orange(), "HWID Reset (User)",
        [("User", f"<@{did}> ({did})"), ("Resets Left", str(remaining))]
    )
    await BOT.log_embed(log_view)


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
        view = SimpleView(discord.Color.red(), "**Bad Duration**", f"Choose one: {opts}")
        await i.followup.send(**cv2_send(view), ephemeral=True)
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
    dm_status = None
    if deliver_to:
        dm_view = StatusView(
            discord.Color.green(),
            "Your License Key",
            [
                ("Key", f"```{k}```"),
                ("Product", prod),
                ("Duration", expires_label),
                ("How to activate", "Use `/register <key> <hwid>` in the server to activate your license."),
            ],
            footer="Keep this key private - do not share it."
        )
        try:
            await deliver_to.send(**cv2_send(dm_view))
            dm_status = f"DM sent to {deliver_to.mention}"
            audit("KEY_DELIVERED", actor_id=str(i.user.id), target_id=str(deliver_to.id),
                  detail=f"key={k[:20]} product={prod}")
        except discord.Forbidden:
            dm_status = f"DM FAILED - {deliver_to.mention} has DMs closed"
        except Exception as e:
            dm_status = f"DM FAILED - {e}"

    # ── Polished result card ────────────────────────────────────────────────
    prod_emoji = "🌐" if prod == "public" else "🔒"

    result_embed = discord.Embed(
        title="Key Generated",
        color=discord.Color.green(),
    )
    result_embed.add_field(name="Product", value=f"{prod_emoji} `{prod}`", inline=True)
    result_embed.add_field(name="Duration", value=f"`{expires_label}`", inline=True)
    result_embed.add_field(name="License Key", value=f"```\n{k}\n```", inline=False)
    if dm_status:
        result_embed.add_field(name="Delivery", value=dm_status, inline=False)
    if notes:
        result_embed.add_field(name="Notes", value=notes, inline=False)
    result_embed.set_footer(text=f"Generated by {i.user} - {now_iso()[:16].replace('T', ' ')} UTC")

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
        view = SimpleView(discord.Color.red(), "**Not Found**", "No user matched that query.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    s = effective_status(row)
    try:
        member = await i.guild.fetch_member(int(row["discord_id"]))
        user_str = f"<@{row['discord_id']}> (`{member}` / {row['discord_id']})"
    except Exception:
        user_str = f"`{row['discord_id']}`"

    fields = [
        ("Discord", user_str),
        ("Key", f"`{row['key']}`"),
        ("Status", f"{status_emoji(s)} {s.upper()}"),
        ("Product", row["product"]),
        ("Expires", fmt_dt(row["expires_at"])),
        ("Registered", fmt_dt(row["registered_at"])),
        ("Last Seen", fmt_ts(row["last_seen"])),
        ("Last IP", row["ip_last"] or "N/A"),
        ("HWID Bound", "Yes" if row["hwid"] else "No"),
        ("HWID Resets Used", str(row["hwid_resets"])),
    ]
    if row["ban_reason"]:
        fields.append(("Ban Reason", row["ban_reason"]))
    if row["notes"]:
        fields.append(("Notes", row["notes"][-300:]))

    view = StatusView(status_color(s), "User Lookup", fields)
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="ban", description="[ADMIN] Ban a user's license.")
@app_commands.describe(user="Target user", reason="Ban reason")
@admin_only()
async def cmd_ban(i: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**", "User has no license.")), ephemeral=True)
        return
    DB.execute("UPDATE users SET status='banned', ban_reason=? WHERE discord_id=?", (reason or "No reason given", did))
    DB.commit()
    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        br = i.guild.get_role(CONFIG["banned_role_id"])
        if vr and vr in user.roles:
            await user.remove_roles(vr, reason="KeyLock ban")
        if br:
            await user.add_roles(br, reason="KeyLock ban")
    except Exception:
        pass
    audit("BAN", actor_id=str(i.user.id), target_id=did, detail=reason or "No reason")
    view = StatusView(
        discord.Color.red(), "User Banned",
        [("User", f"<@{did}> ({did})"), ("Reason", reason or "None"), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)
    await BOT.log_embed(view)


@app_commands.command(name="unban", description="[ADMIN] Unban a user's license.")
@app_commands.describe(user="Target user")
@admin_only()
async def cmd_unban(i: discord.Interaction, user: discord.Member):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**", "User has no license.")), ephemeral=True)
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
    view = StatusView(
        discord.Color.green(), "User Unbanned",
        [("User", f"<@{did}> ({did})"), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)
    await BOT.log_embed(view)


@app_commands.command(name="revoke", description="[ADMIN] Permanently revoke a license.")
@app_commands.describe(user="Target user", reason="Reason")
@admin_only()
async def cmd_revoke(i: discord.Interaction, user: discord.Member, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**", "User has no license.")), ephemeral=True)
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
    view = StatusView(
        discord.Color.dark_gray(), "License Revoked",
        [("User", f"<@{did}> ({did})"), ("Reason", reason or "None"), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)
    await BOT.log_embed(view)


@app_commands.command(name="addnote", description="[ADMIN] Append an admin note to a user.")
@app_commands.describe(user="Target user", note="Note text")
@admin_only()
async def cmd_addnote(i: discord.Interaction, user: discord.Member, note: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT notes FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**")), ephemeral=True)
        return
    stamp = f"[{now_iso()[:10]} - {i.user}] {note}"
    existing = row["notes"] or ""
    DB.execute("UPDATE users SET notes=? WHERE discord_id=?", ((existing + "\n" + stamp).strip(), did))
    DB.commit()
    audit("ADD_NOTE", actor_id=str(i.user.id), target_id=did, detail=note[:100])
    view = SimpleView(discord.Color.blurple(), "**Note Added**", f"Added note to <@{did}>.", f"```{note[:200]}```")
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="resethwid", description="[ADMIN] Force-reset or rebind a user's HWID.")
@app_commands.describe(user="Target user", new_hwid="New HWID to bind (blank = clear)")
@admin_only()
async def cmd_resethwid(i: discord.Interaction, user: discord.Member, new_hwid: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**")), ephemeral=True)
        return
    hashed = hash_hwid(new_hwid) if new_hwid else None
    DB.execute("UPDATE users SET hwid=?, hwid_resets=hwid_resets+1 WHERE discord_id=?", (hashed, did))
    DB.commit()
    audit("HWID_RESET_ADMIN", actor_id=str(i.user.id), target_id=did, detail="set" if hashed else "cleared")
    action = "updated" if hashed else "cleared"
    view = SimpleView(discord.Color.orange(), f"**HWID {action.title()}**", f"HWID {action} for <@{did}>.")
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="banhwid", description="[ADMIN] Globally ban an HWID.")
@app_commands.describe(raw_hwid="Raw HWID to ban", reason="Reason")
@admin_only()
async def cmd_banhwid(i: discord.Interaction, raw_hwid: str, reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    hashed = hash_hwid(raw_hwid)
    try:
        DB.execute("INSERT INTO hwid_bans (hwid,reason,banned_at,banned_by) VALUES (?,?,?,?)",
                   (hashed, reason or "No reason", now_iso(), str(i.user.id)))
        DB.commit()
    except sqlite3.IntegrityError:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.orange(), "**Already Banned**", "That HWID is already banned.")), ephemeral=True)
        return
    audit("HWID_BAN", actor_id=str(i.user.id), detail=hashed[:16])
    view = StatusView(
        discord.Color.red(), "HWID Banned",
        [("Hash", f"`{hashed[:24]}...`"), ("Reason", reason or "None"), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)
    await BOT.log_embed(view)


@app_commands.command(name="unbanhwid", description="[ADMIN] Remove an HWID ban.")
@app_commands.describe(raw_hwid="Raw HWID to unban")
@admin_only()
async def cmd_unbanhwid(i: discord.Interaction, raw_hwid: str):
    await i.response.defer(ephemeral=True)
    hashed = hash_hwid(raw_hwid)
    cur = DB.execute("DELETE FROM hwid_bans WHERE hwid=?", (hashed,))
    DB.commit()
    if cur.rowcount == 0:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Found**", "That HWID is not banned.")), ephemeral=True)
        return
    audit("HWID_UNBAN", actor_id=str(i.user.id), detail=hashed[:16])
    view = SimpleView(discord.Color.green(), "**HWID Unbanned**", "Hardware ID removed from ban list.")
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="extend", description="[ADMIN] Set or extend a user's expiry date.")
@app_commands.describe(user="Target user", expires="New expiry YYYY-MM-DD")
@admin_only()
async def cmd_extend(i: discord.Interaction, user: discord.Member, expires: str):
    await i.response.defer(ephemeral=True)
    exp_iso = parse_date(expires)
    if not exp_iso:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Bad Date**", "Use format: `YYYY-MM-DD`")), ephemeral=True)
        return
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**")), ephemeral=True)
        return
    DB.execute("UPDATE users SET expires_at=?, status='active', ban_reason=NULL WHERE discord_id=?", (exp_iso, did))
    DB.commit()
    audit("EXTEND", actor_id=str(i.user.id), target_id=did, detail=f"new_expiry={expires}")
    view = StatusView(
        discord.Color.green(), "Expiry Updated",
        [("User", f"<@{did}>"), ("New Expiry", expires), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="setproduct", description="[ADMIN] Change a user's product tier.")
@app_commands.describe(user="Target user", product="New product name")
@admin_only()
async def cmd_setproduct(i: discord.Interaction, user: discord.Member, product: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**")), ephemeral=True)
        return
    DB.execute("UPDATE users SET product=? WHERE discord_id=?", (product, did))
    DB.commit()
    audit("SET_PRODUCT", actor_id=str(i.user.id), target_id=did, detail=f"product={product}")
    view = StatusView(
        discord.Color.blurple(), "Product Updated",
        [("User", f"<@{did}>"), ("New Product", product), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="grantresets", description="[ADMIN] Give a user extra HWID reset uses.")
@app_commands.describe(user="Target user", count="Adjust reset counter by this amount (negative = grant more)")
@admin_only()
async def cmd_grantresets(i: discord.Interaction, user: discord.Member, count: int = -1):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT hwid_resets FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**")), ephemeral=True)
        return
    new_val = max(0, row["hwid_resets"] + count)
    DB.execute("UPDATE users SET hwid_resets=? WHERE discord_id=?", (new_val, did))
    DB.commit()
    audit("GRANT_RESETS", actor_id=str(i.user.id), target_id=did, detail=f"delta={count} new_val={new_val}")
    view = StatusView(
        discord.Color.blurple(), "Resets Updated",
        [("User", f"<@{did}>"), ("Reset Counter", str(new_val)), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)


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
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**No Users Found**")), ephemeral=True)
        return
    lines = []
    for r in rows:
        s = effective_status(r)
        lines.append(f"{status_emoji(s)} {r['discord_id']} - {r['product']} - expires {fmt_dt(r['expires_at'])}")
    view = KeyListView(f"Users ({len(rows)} shown)", lines)
    await i.followup.send(**cv2_send(view), ephemeral=True)


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
        await i.followup.send(**cv2_send(SimpleView(discord.Color.orange(), "**No Unclaimed Keys**")), ephemeral=True)
        return
    lines = []
    for r in rows:
        vis_icon = "🌐" if r["visibility"] == "public" else "🔒"
        lines.append(f"{vis_icon} {r['key']} - {r['product']} - {fmt_dt(r['expires_at'])}")
    view = KeyListView(f"Unclaimed Keys ({len(rows)})", lines)
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="deletekey", description="[ADMIN] Delete an unclaimed key from the pool.")
@app_commands.describe(key="The key to delete")
@admin_only()
async def cmd_deletekey(i: discord.Interaction, key: str):
    await i.response.defer(ephemeral=True)
    cur = DB.execute("DELETE FROM key_pool WHERE key=? AND claimed=0", (key.strip().upper(),))
    DB.commit()
    if cur.rowcount == 0:
        view = SimpleView(discord.Color.red(), "**Not Found**", "Key not found or already claimed.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return
    audit("DELETE_KEY", actor_id=str(i.user.id), detail=f"key={key[:20]}")
    view = SimpleView(discord.Color.green(), "**Key Deleted**", f"`{key}` removed from pool.")
    await i.followup.send(**cv2_send(view), ephemeral=True)


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
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**No Entries Found**")), ephemeral=True)
        return
    lines = []
    for r in rows:
        ts = r["timestamp"][:16].replace("T", " ")
        actor = r["actor_id"] or "-"
        detail = f" | {r['detail'][:50]}" if r["detail"] else ""
        lines.append(f"[{ts}] {r['action']} | {actor}{detail}")
    view = KeyListView(f"Audit Log ({len(rows)})", lines)
    await i.followup.send(**cv2_send(view), ephemeral=True)


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
    view = StatusView(
        discord.Color.blurple(), "KeyLock Stats",
        [
            ("Users", f"Total: **{total}** | Active: **{active}** | Banned: **{banned}** | Revoked: **{revoked}**"),
            ("Keys", f"Unclaimed: **{unclaim}** | Claimed: **{claimed}**"),
            ("Security", f"HWID Bans: **{hwbans}** | Audit Entries: **{logs}**"),
            ("Today", f"Logins: **{logins_today}** | Registrations: **{regs_today}**"),
        ]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="announce",
    description="[ADMIN] Send a styled CV2 announcement to any channel.")
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
    view = SimpleView(discord.Color.green(), "**Announcement Sent**", f"Posted to {channel.mention}.")
    await i.followup.send(**cv2_send(view), ephemeral=True)


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
    view = StatusView(
        discord.Color.orange(), "Purge Complete",
        [("Licenses Revoked", str(count)), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)


@app_commands.command(name="wipeuser",
    description="[ADMIN] Completely wipe a user's registration (frees their key).")
@app_commands.describe(user="Target user", confirm="Type CONFIRM to proceed")
@admin_only()
async def cmd_wipeuser(i: discord.Interaction, user: discord.Member, confirm: str = ""):
    await i.response.defer(ephemeral=True)
    if confirm != "CONFIRM":
        view = SimpleView(
            discord.Color.red(),
            "**Confirmation Required**",
            "Pass `confirm: CONFIRM` to wipe a user.",
            "This cannot be undone."
        )
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return
    did = str(user.id)
    row = DB.execute("SELECT key FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send(**cv2_send(SimpleView(discord.Color.red(), "**Not Registered**")), ephemeral=True)
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
    view = StatusView(
        discord.Color.dark_red(), "User Wiped",
        [("User", f"{user} ({did})"), ("Key", "Returned to pool"), ("By", str(i.user))]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)
    await BOT.log_embed(view)


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
    view = StatusView(
        discord.Color.blurple(), "Bot Invite URL",
        [("Link", url), ("Permissions", "Send Messages, Manage Roles, Read Messages, Slash Commands")]
    )
    await i.followup.send(**cv2_send(view), ephemeral=True)


async def _send_login_log(discord_id: str, ip: str, product: str, expires_at: str):
    """Called from the API thread via run_coroutine_threadsafe."""
    ch = BOT.get_channel(CONFIG["log_channel_id"])
    if not ch:
        return
    # Count total logins for this user
    total = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status='ok'", (discord_id,)
    ).fetchone()[0]
    view = StatusView(
        discord.Color.green(), "Login Detected",
        [
            ("User", f"<@{discord_id}> (`{discord_id}`)"),
            ("Product", product),
            ("IP", f"`{ip}`"),
            ("Expires", fmt_dt(expires_at)),
            ("Total Logins", str(total)),
        ],
        footer=fmt_ts(now_iso())
    )
    try:
        await ch.send(embed=view)
    except Exception as e:
        log.warning("Login log send failed: %s", e)


@app_commands.command(name="profile",
    description="[ADMIN] Full profile for a user - HWID, IPs, login history, alt detection.")
@app_commands.describe(query="@mention, Discord ID, or license key")
@admin_only()
async def cmd_profile(i: discord.Interaction, query: str):
    await i.response.defer(ephemeral=True)
    clean = query.strip().lstrip("<@!").rstrip(">")
    row = (
        DB.execute("SELECT * FROM users WHERE discord_id=?", (clean,)).fetchone() or
        DB.execute("SELECT * FROM users WHERE key=?", (query.strip().upper(),)).fetchone()
    )
    if not row:
        view = SimpleView(discord.Color.red(), "**Not Found**", "No user matched that query.")
        await i.followup.send(**cv2_send(view), ephemeral=True)
        return

    did = row["discord_id"]
    s   = effective_status(row)

    # Login history (last 10)
    logins = DB.execute(
        "SELECT * FROM login_log WHERE discord_id=? ORDER BY id DESC LIMIT 10", (did,)
    ).fetchall()

    # All unique IPs this user has logged in from
    all_ips = DB.execute(
        "SELECT DISTINCT ip FROM login_log WHERE discord_id=? AND ip IS NOT NULL", (did,)
    ).fetchall()
    ip_list = [r["ip"] for r in all_ips]

    # Alt detection - find other accounts sharing any of those IPs
    alts = []
    if ip_list:
        placeholders = ",".join("?" * len(ip_list))
        alt_rows = DB.execute(
            f"SELECT DISTINCT discord_id FROM login_log WHERE ip IN ({placeholders}) AND discord_id != ?",
            ip_list + [did]
        ).fetchall()
        alts = [r["discord_id"] for r in alt_rows]

    # HWID sharing - find other accounts with same HWID hash
    hwid_alts = []
    if row["hwid"]:
        hwid_rows = DB.execute(
            "SELECT discord_id FROM users WHERE hwid=? AND discord_id != ?",
            (row["hwid"], did)
        ).fetchall()
        hwid_alts = [r["discord_id"] for r in hwid_rows]

    # Total login count
    total_logins = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=?", (did,)
    ).fetchone()[0]
    failed_logins = DB.execute(
        "SELECT COUNT(*) FROM login_log WHERE discord_id=? AND status != 'ok'", (did,)
    ).fetchone()[0]

    # Notes
    notes_preview = (row["notes"] or "None")[:300]

    # Audit entries for this user
    audit_rows = DB.execute(
        "SELECT action, timestamp FROM audit_log WHERE target_id=? ORDER BY id DESC LIMIT 5", (did,)
    ).fetchall()
    audit_lines = [f"`{r['action']}` - {r['timestamp'][:10]}" for r in audit_rows] or ["None"]

    # Build login history lines
    login_lines = []
    for l in logins:
        status_icon = "OK" if l["status"] == "ok" else l["status"].upper()
        login_lines.append(f"[{l['timestamp'][:16].replace('T',' ')}] {status_icon} - {l['ip'] or 'N/A'}")

    # ── Embed 1 - Identity ─────────────────────────────────────────────────
    e1 = discord.Embed(
        title=f"Profile - {did}",
        color=status_color(s)
    )
    e1.add_field(name="Status", value=f"{status_emoji(s)} {s.upper()}", inline=True)
    e1.add_field(name="Product", value=row["product"], inline=True)
    e1.add_field(name="Key", value=f"`{row['key']}`", inline=False)
    e1.add_field(name="Registered", value=fmt_dt(row["registered_at"]), inline=True)
    e1.add_field(name="Expires", value=fmt_dt(row["expires_at"]), inline=True)
    e1.add_field(name="Last Seen", value=fmt_ts(row["last_seen"]), inline=True)
    e1.add_field(name="Last IP", value=f"`{row['ip_last'] or 'N/A'}`", inline=True)
    e1.add_field(name="HWID Bound", value="Yes" if row["hwid"] else "No", inline=True)
    e1.add_field(name="HWID Resets", value=str(row["hwid_resets"]), inline=True)
    if row["ban_reason"]:
        e1.add_field(name="Ban Reason", value=row["ban_reason"], inline=False)

    # ── Embed 2 - Network / Alts ───────────────────────────────────────────
    alt_color = discord.Color.orange() if alts or hwid_alts else discord.Color.blurple()
    e2 = discord.Embed(title="Network & Alts", color=alt_color)
    ip_str = " - ".join(f"`{ip}`" for ip in ip_list) if ip_list else "None"
    e2.add_field(name=f"Known IPs ({len(ip_list)})", value=ip_str, inline=False)
    alt_str = " - ".join(f"<@{a}>" for a in alts[:10]) if alts else "None detected"
    e2.add_field(name=f"IP-Shared Accounts ({len(alts)})", value=alt_str, inline=False)
    h_str = " - ".join(f"<@{a}>" for a in hwid_alts[:10]) if hwid_alts else "None detected"
    e2.add_field(name=f"HWID-Shared Accounts ({len(hwid_alts)})", value=h_str, inline=False)

    # ── Embed 3 - Login history + notes ───────────────────────────────────
    e3 = discord.Embed(
        title=f"Login History - {total_logins} total ({failed_logins} failed)",
        color=discord.Color.dark_gray(),
        description="```\n" + "\n".join(login_lines or ["No logins recorded"]) + "\n```"
    )
    e3.add_field(name="Admin Notes", value=f"```{notes_preview}```", inline=False)
    e3.add_field(name="Recent Actions", value="\n".join(audit_lines), inline=False)

    await i.followup.send(embeds=[e1, e2, e3], ephemeral=True)


# ─── VERIFY API ───────────────────────────────────────────────────────────────

class VerifyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.info("API " + fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._out(200, {"status": "ok"})
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

        if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
            audit("API_VERIFY_HWID_BANNED", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), None, "hwid_banned"))
            DB.commit()
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
            self._out(403, {"status": s, "message": f"Account {s}"})
            return

        if row["hwid"] and row["hwid"] != hashed:
            audit("API_VERIFY_HWID_MISMATCH", target_id=did, ip=ip)
            DB.execute("INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
                       (did, hashed, ip, now_iso(), row["product"], "hwid_mismatch"))
            DB.commit()
            self._out(403, {"status": "hwid_mismatch", "message": "HWID does not match registered machine"})
            return

        if not row["hwid"]:
            DB.execute("UPDATE users SET hwid=? WHERE discord_id=?", (hashed, did))

        ts = now_iso()
        DB.execute("UPDATE users SET last_seen=?, ip_last=? WHERE discord_id=?", (ts, ip, did))
        DB.execute(
            "INSERT INTO login_log (discord_id,hwid,ip,timestamp,product,status) VALUES (?,?,?,?,?,?)",
            (did, hashed, ip, ts, row["product"], "ok")
        )
        DB.commit()
        audit("API_VERIFY_OK", target_id=did, ip=ip, detail=f"product={row['product']}")

        # Fire login log to Discord channel (non-blocking)
        asyncio.run_coroutine_threadsafe(
            _send_login_log(did, ip, row["product"], row["expires_at"]),
            BOT.loop
        )

        self._out(200, {
            "status":     "ok",
            "discord_id": row["discord_id"],
            "product":    row["product"],
            "expires_at": row["expires_at"],
        })

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

ALL_COMMANDS = [
    cmd_register, cmd_mystatus, cmd_resetmyhwid,
    cmd_keygen, cmd_lookup, cmd_profile, cmd_ban, cmd_unban, cmd_revoke,
    cmd_addnote, cmd_resethwid, cmd_banhwid, cmd_unbanhwid,
    cmd_extend, cmd_setproduct, cmd_grantresets,
    cmd_listusers, cmd_listkeys, cmd_deletekey,
    cmd_auditlog, cmd_stats, cmd_announce,
    cmd_purgeexpired, cmd_wipeuser, cmd_invite,
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
