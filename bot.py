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
import argparse
from datetime import datetime, timezone, timedelta
from typing import Optional
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# ─── ENV / CONFIG ─────────────────────────────────────────────────────────────

def env(key: str, default=None):
    return os.environ.get(key, default)

CONFIG = {
    "token":              env("DISCORD_TOKEN",        "YOUR_BOT_TOKEN"),
    "guild_id":           int(env("GUILD_ID",         "0")),
    "admin_role_id":      int(env("ADMIN_ROLE_ID",    "0")),
    "log_channel_id":     int(env("LOG_CHANNEL_ID",   "0")),
    "verified_role_id":   int(env("VERIFIED_ROLE_ID", "0")),
    "banned_role_id":     int(env("BANNED_ROLE_ID",   "0")),
    "db_path":            env("DB_PATH",              "/data/keylock.db"),
    "max_hwid_resets":    int(env("MAX_HWID_RESETS",  "1")),
    "key_prefix":         env("KEY_PREFIX",           "KL"),
    "api_port":           int(env("PORT",             "8080")),
}

# ─── LOGGING ──────────────────────────────────────────────────────────────────

os.makedirs(os.path.dirname(CONFIG["db_path"]), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("keylock.log"),
        logging.StreamHandler(),
    ]
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
            created_at  TEXT NOT NULL,
            expires_at  TEXT,
            claimed     INTEGER NOT NULL DEFAULT 0,
            created_by  TEXT,
            notes       TEXT
        );

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
    """)
    conn.commit()
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
    parts = [
        "".join(secrets.choice(charset) for _ in range(seg_len))
        for _ in range(segments)
    ]
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

def status_color(s: str) -> int:
    return {
        "active":  0x00ff88,
        "banned":  0xff4444,
        "revoked": 0x888888,
        "expired": 0xff8800,
    }.get(s, 0x5865f2)

def audit(action: str, actor_id: str = None, target_id: str = None,
          ip: str = None, detail: str = None):
    DB.execute(
        "INSERT INTO audit_log (timestamp,action,actor_id,target_id,ip,detail) "
        "VALUES (?,?,?,?,?,?)",
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

# ─── BOT ──────────────────────────────────────────────────────────────────────

class KeyLock(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        super().__init__(command_prefix="kl!", intents=intents)

    async def setup_hook(self):
        g = discord.Object(id=CONFIG["guild_id"])
        self.tree.copy_global_to(guild=g)
        await self.tree.sync(guild=g)
        expire_checker.start()
        log.info("Commands synced to guild %d", CONFIG["guild_id"])

    async def on_ready(self):
        log.info("KeyLock online: %s (%d)", self.user, self.user.id)
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="the vault"
            )
        )

    async def log_embed(self, embed: discord.Embed):
        ch = self.get_channel(CONFIG["log_channel_id"])
        if ch:
            try:
                await ch.send(embed=embed)
            except Exception as e:
                log.warning("Log send failed: %s", e)

BOT: KeyLock = None

# ─── ADMIN CHECK ──────────────────────────────────────────────────────────────

def admin_only():
    async def predicate(i: discord.Interaction) -> bool:
        rid = CONFIG["admin_role_id"]
        if not rid:
            return i.user.guild_permissions.administrator
        role = i.guild.get_role(rid)
        if role and role in i.user.roles:
            return True
        await i.response.send_message("No permission.", ephemeral=True)
        return False
    return app_commands.check(predicate)

# ─── BACKGROUND TASK ──────────────────────────────────────────────────────────

@tasks.loop(hours=1)
async def expire_checker():
    """Auto-revoke expired licenses and strip roles every hour."""
    rows = DB.execute(
        "SELECT * FROM users WHERE status='active' AND expires_at IS NOT NULL"
    ).fetchall()
    guild = BOT.get_guild(CONFIG["guild_id"])
    if not guild:
        return
    for row in rows:
        if is_expired(row):
            DB.execute(
                "UPDATE users SET status='revoked', ban_reason='Auto: expired' "
                "WHERE discord_id=?", (row["discord_id"],)
            )
            DB.commit()
            audit("AUTO_EXPIRE", target_id=row["discord_id"],
                  detail=f"expired at {row['expires_at']}")
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
    db  = DB

    if db.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        em = discord.Embed(
            title="Already Registered",
            description="Your Discord account already has an active license.\n"
                        "Use `/mystatus` to check it.",
            color=0xffa500
        )
        await i.followup.send(embed=em, ephemeral=True)
        return

    pool = db.execute(
        "SELECT * FROM key_pool WHERE key=? AND claimed=0", (key.strip().upper(),)
    ).fetchone()
    if not pool:
        audit("REGISTER_FAIL_BAD_KEY", actor_id=did, detail=f"key={key[:20]}")
        await i.followup.send(
            embed=discord.Embed(
                title="Invalid Key",
                description="That key doesn't exist or has already been used.",
                color=0xff4444
            ),
            ephemeral=True
        )
        return

    if db.execute("SELECT 1 FROM users WHERE key=?", (key.strip().upper(),)).fetchone():
        audit("REGISTER_FAIL_KEY_TAKEN", actor_id=did)
        await i.followup.send(
            embed=discord.Embed(
                title="Key Taken",
                description="That key is already registered to another account.",
                color=0xff4444
            ),
            ephemeral=True
        )
        return

    hashed = hash_hwid(hwid)
    if db.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
        audit("REGISTER_FAIL_HWID_BANNED", actor_id=did, detail=hashed[:16])
        await i.followup.send(
            embed=discord.Embed(
                title="Banned",
                description="Your hardware ID is banned. Contact support.",
                color=0xff4444
            ),
            ephemeral=True
        )
        return

    if pool["expires_at"]:
        try:
            if datetime.now(timezone.utc) > datetime.fromisoformat(pool["expires_at"]):
                await i.followup.send(
                    embed=discord.Embed(
                        title="Key Expired",
                        description="That key has expired. Contact support.",
                        color=0xff8800
                    ),
                    ephemeral=True
                )
                return
        except Exception:
            pass

    db.execute(
        "INSERT INTO users (discord_id,key,hwid,product,status,registered_at,expires_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (did, key.strip().upper(), hashed, pool["product"],
         "active", now_iso(), pool["expires_at"])
    )
    db.execute("UPDATE key_pool SET claimed=1 WHERE key=?", (key.strip().upper(),))
    db.commit()

    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr:
            await i.user.add_roles(vr, reason="KeyLock: registered")
    except Exception as e:
        log.warning("Role grant failed: %s", e)

    audit("REGISTER_SUCCESS", actor_id=did,
          detail=f"key={key[:20]} product={pool['product']}")

    em = discord.Embed(
        title="Registered",
        description=(
            "Your license has been activated and your hardware is now bound.\n\n"
            "**From this point your Discord account IS your license.**\n"
            "The launcher uses your Discord ID - keep your account secure."
        ),
        color=0x00ff88,
        timestamp=datetime.now(timezone.utc)
    )
    em.add_field(name="Product", value=pool["product"], inline=True)
    em.add_field(name="Expires", value=fmt_dt(pool["expires_at"]), inline=True)
    em.add_field(name="HWID Resets", value=str(CONFIG["max_hwid_resets"]), inline=True)
    em.set_footer(text=f"{i.user} - {i.user.id}")
    await i.followup.send(embed=em, ephemeral=True)

    log_em = discord.Embed(
        title="New Registration",
        color=0x00ff88,
        timestamp=datetime.now(timezone.utc)
    )
    log_em.add_field(name="User", value=f"{i.user.mention} ({did})", inline=False)
    log_em.add_field(name="Product", value=pool["product"], inline=True)
    log_em.add_field(name="Expires", value=fmt_dt(pool["expires_at"]), inline=True)
    await BOT.log_embed(log_em)


@app_commands.command(name="mystatus", description="Check your license status.")
async def cmd_mystatus(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    row = DB.execute("SELECT * FROM users WHERE discord_id=?",
                     (str(i.user.id),)).fetchone()
    if not row:
        await i.followup.send(
            embed=discord.Embed(
                title="Not Registered",
                description="You don't have a license yet.\n"
                            "Use `/register <key> <hwid>` to get started.",
                color=0xff4444
            ),
            ephemeral=True
        )
        return

    s = effective_status(row)
    em = discord.Embed(title="Your License", color=status_color(s),
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="Status",   value=s.upper(),                      inline=True)
    em.add_field(name="Product",  value=row["product"],                  inline=True)
    em.add_field(name="Expires",  value=fmt_dt(row["expires_at"]),       inline=True)
    em.add_field(name="Registered", value=fmt_dt(row["registered_at"]), inline=True)
    em.add_field(name="Last Seen",  value=fmt_ts(row["last_seen"]),      inline=True)
    em.add_field(
        name="HWID Resets Left",
        value=str(max(0, CONFIG["max_hwid_resets"] - row["hwid_resets"])),
        inline=True
    )
    if row["ban_reason"]:
        em.add_field(name="Reason", value=row["ban_reason"], inline=False)
    em.set_footer(text=f"ID: {i.user.id}")
    await i.followup.send(embed=em, ephemeral=True)


@app_commands.command(name="resetmyhwid",
    description="Swap your HWID to a new machine (limited uses).")
@app_commands.describe(new_hwid="Your new Hardware ID from the launcher")
async def cmd_resetmyhwid(i: discord.Interaction, new_hwid: str):
    await i.response.defer(ephemeral=True)
    did = str(i.user.id)
    max_r = CONFIG["max_hwid_resets"]
    row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()

    if not row:
        await i.followup.send("You are not registered.", ephemeral=True)
        return

    s = effective_status(row)
    if s in ("banned", "revoked", "expired"):
        await i.followup.send(
            f"Your account is `{s.upper()}`. Contact an admin.", ephemeral=True
        )
        return

    if row["hwid_resets"] >= max_r:
        audit("HWID_RESET_DENIED", actor_id=did, detail=f"at max {max_r}")
        await i.followup.send(
            embed=discord.Embed(
                title="No Resets Left",
                description=f"You have used all `{max_r}` HWID reset(s).\n"
                            "Contact an admin for a manual reset.",
                color=0xff4444
            ),
            ephemeral=True
        )
        return

    hashed = hash_hwid(new_hwid)
    if DB.execute("SELECT 1 FROM hwid_bans WHERE hwid=?", (hashed,)).fetchone():
        await i.followup.send("That hardware ID is banned.", ephemeral=True)
        return

    DB.execute(
        "UPDATE users SET hwid=?, hwid_resets=hwid_resets+1 WHERE discord_id=?",
        (hashed, did)
    )
    DB.commit()
    audit("HWID_RESET_USER", actor_id=did, detail=f"reset #{row['hwid_resets']+1}")

    remaining = max_r - row["hwid_resets"] - 1
    em = discord.Embed(
        title="HWID Updated",
        description=(
            f"Your new hardware ID is now bound.\n\n"
            f"Resets remaining: **{remaining}**\n"
            "The launcher will accept your new machine on next launch."
        ),
        color=0xffa500,
        timestamp=datetime.now(timezone.utc)
    )
    await i.followup.send(embed=em, ephemeral=True)

    log_em = discord.Embed(title="HWID Reset (User)", color=0xffa500,
                           timestamp=datetime.now(timezone.utc))
    log_em.add_field(name="User", value=f"{i.user.mention} ({did})")
    log_em.add_field(name="Resets Left", value=str(remaining))
    await BOT.log_embed(log_em)


# ─── ADMIN COMMANDS ───────────────────────────────────────────────────────────

@app_commands.command(name="keygen", description="[ADMIN] Generate keys into the pool.")
@app_commands.describe(
    count="Number of keys to generate (1-100)",
    product="Product name/tier",
    expires="Expiry date YYYY-MM-DD (blank = never)",
    notes="Admin notes attached to these keys"
)
@admin_only()
async def cmd_keygen(i: discord.Interaction,
                     count: app_commands.Range[int, 1, 100] = 1,
                     product: str = "default",
                     expires: Optional[str] = None,
                     notes: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    exp_iso = None
    if expires:
        exp_iso = parse_date(expires)
        if not exp_iso:
            await i.followup.send("Bad date. Use YYYY-MM-DD.", ephemeral=True)
            return

    keys = []
    for _ in range(count):
        k = gen_key(CONFIG["key_prefix"])
        DB.execute(
            "INSERT OR IGNORE INTO key_pool "
            "(key,product,created_at,expires_at,created_by,notes) VALUES (?,?,?,?,?,?)",
            (k, product, now_iso(), exp_iso, str(i.user.id), notes)
        )
        keys.append(k)
    DB.commit()
    audit("KEYGEN", actor_id=str(i.user.id),
          detail=f"{count}x product={product} expires={expires or 'never'}")

    block = "\n".join(keys)
    em = discord.Embed(
        title=f"Generated {count} Key(s)",
        description=f"**Product:** `{product}`\n**Expires:** `{expires or 'Never'}`\n\n```\n{block}\n```",
        color=0x00ff88,
        timestamp=datetime.now(timezone.utc)
    )
    em.set_footer(text=f"By {i.user}")
    await i.followup.send(embed=em, ephemeral=True)
    await BOT.log_embed(em)


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
        await i.followup.send("No user found.", ephemeral=True)
        return

    s = effective_status(row)
    try:
        member = await i.guild.fetch_member(int(row["discord_id"]))
        user_str = f"{member.mention}\n`{member}` ({row['discord_id']})"
    except Exception:
        user_str = f"`{row['discord_id']}`"

    em = discord.Embed(title="User Lookup", color=status_color(s),
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="Discord",      value=user_str,                    inline=False)
    em.add_field(name="Key",          value=f"`{row['key']}`",            inline=False)
    em.add_field(name="Status",       value=s.upper(),                   inline=True)
    em.add_field(name="Product",      value=row["product"],               inline=True)
    em.add_field(name="Expires",      value=fmt_dt(row["expires_at"]),    inline=True)
    em.add_field(name="Registered",   value=fmt_dt(row["registered_at"]), inline=True)
    em.add_field(name="Last Seen",    value=fmt_ts(row["last_seen"]),     inline=True)
    em.add_field(name="Last IP",      value=row["ip_last"] or "N/A",      inline=True)
    em.add_field(name="HWID Bound",   value="Yes" if row["hwid"] else "No", inline=True)
    em.add_field(name="HWID Resets",  value=str(row["hwid_resets"]),      inline=True)
    if row["ban_reason"]:
        em.add_field(name="Ban/Revoke Reason", value=row["ban_reason"], inline=False)
    if row["notes"]:
        em.add_field(name="Notes", value=row["notes"][-500:], inline=False)
    await i.followup.send(embed=em, ephemeral=True)


@app_commands.command(name="ban", description="[ADMIN] Ban a user's license.")
@app_commands.describe(user="Target user", reason="Ban reason")
@admin_only()
async def cmd_ban(i: discord.Interaction, user: discord.Member,
                  reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    DB.execute(
        "UPDATE users SET status='banned', ban_reason=? WHERE discord_id=?",
        (reason or "No reason given", did)
    )
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
    em = discord.Embed(title="User Banned", color=0xff4444,
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="User",   value=f"{user.mention} ({did})", inline=False)
    em.add_field(name="Reason", value=reason or "None",          inline=False)
    em.set_footer(text=f"By {i.user}")
    await i.followup.send(embed=em, ephemeral=True)
    await BOT.log_embed(em)


@app_commands.command(name="unban", description="[ADMIN] Unban a user's license.")
@app_commands.describe(user="Target user")
@admin_only()
async def cmd_unban(i: discord.Interaction, user: discord.Member):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    DB.execute(
        "UPDATE users SET status='active', ban_reason=NULL WHERE discord_id=?", (did,)
    )
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
    em = discord.Embed(title="User Unbanned", color=0x00ff88,
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="User", value=f"{user.mention} ({did})")
    em.set_footer(text=f"By {i.user}")
    await i.followup.send(embed=em, ephemeral=True)
    await BOT.log_embed(em)


@app_commands.command(name="revoke", description="[ADMIN] Permanently revoke a license.")
@app_commands.describe(user="Target user", reason="Reason")
@admin_only()
async def cmd_revoke(i: discord.Interaction, user: discord.Member,
                     reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    DB.execute(
        "UPDATE users SET status='revoked', ban_reason=? WHERE discord_id=?",
        (reason or "Revoked", did)
    )
    DB.commit()
    try:
        vr = i.guild.get_role(CONFIG["verified_role_id"])
        if vr and vr in user.roles:
            await user.remove_roles(vr, reason="KeyLock revoke")
    except Exception:
        pass
    audit("REVOKE", actor_id=str(i.user.id), target_id=did, detail=reason)
    em = discord.Embed(title="License Revoked", color=0x888888,
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="User",   value=f"{user.mention} ({did})", inline=False)
    em.add_field(name="Reason", value=reason or "None",          inline=False)
    em.set_footer(text=f"By {i.user}")
    await i.followup.send(embed=em, ephemeral=True)
    await BOT.log_embed(em)


@app_commands.command(name="addnote", description="[ADMIN] Append an admin note to a user.")
@app_commands.describe(user="Target user", note="Note text")
@admin_only()
async def cmd_addnote(i: discord.Interaction, user: discord.Member, note: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT notes FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    stamp = f"[{now_iso()[:10]} - {i.user}] {note}"
    existing = row["notes"] or ""
    DB.execute("UPDATE users SET notes=? WHERE discord_id=?",
               ((existing + "\n" + stamp).strip(), did))
    DB.commit()
    audit("ADD_NOTE", actor_id=str(i.user.id), target_id=did, detail=note[:100])
    await i.followup.send(f"Note added to {user.mention}.", ephemeral=True)


@app_commands.command(name="resethwid",
    description="[ADMIN] Force-reset or rebind a user's HWID.")
@app_commands.describe(user="Target user",
                       new_hwid="New HWID to bind (leave blank to just clear)")
@admin_only()
async def cmd_resethwid(i: discord.Interaction, user: discord.Member,
                        new_hwid: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    hashed = hash_hwid(new_hwid) if new_hwid else None
    DB.execute(
        "UPDATE users SET hwid=?, hwid_resets=hwid_resets+1 WHERE discord_id=?",
        (hashed, did)
    )
    DB.commit()
    audit("HWID_RESET_ADMIN", actor_id=str(i.user.id), target_id=did,
          detail="set" if hashed else "cleared")
    await i.followup.send(
        f"HWID {'updated' if hashed else 'cleared'} for {user.mention}.", ephemeral=True
    )


@app_commands.command(name="banhwid", description="[ADMIN] Globally ban an HWID.")
@app_commands.describe(raw_hwid="Raw HWID to ban", reason="Reason")
@admin_only()
async def cmd_banhwid(i: discord.Interaction, raw_hwid: str,
                      reason: Optional[str] = None):
    await i.response.defer(ephemeral=True)
    hashed = hash_hwid(raw_hwid)
    try:
        DB.execute(
            "INSERT INTO hwid_bans (hwid,reason,banned_at,banned_by) VALUES (?,?,?,?)",
            (hashed, reason or "No reason", now_iso(), str(i.user.id))
        )
        DB.commit()
    except sqlite3.IntegrityError:
        await i.followup.send("HWID is already banned.", ephemeral=True)
        return
    audit("HWID_BAN", actor_id=str(i.user.id), detail=hashed[:16])
    em = discord.Embed(title="HWID Banned", color=0xff0000,
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="HWID Hash", value=f"`{hashed[:24]}...`")
    em.add_field(name="Reason",    value=reason or "None")
    em.set_footer(text=f"By {i.user}")
    await i.followup.send(embed=em, ephemeral=True)
    await BOT.log_embed(em)


@app_commands.command(name="unbanhwid", description="[ADMIN] Remove an HWID ban.")
@app_commands.describe(raw_hwid="Raw HWID to unban")
@admin_only()
async def cmd_unbanhwid(i: discord.Interaction, raw_hwid: str):
    await i.response.defer(ephemeral=True)
    hashed = hash_hwid(raw_hwid)
    cur = DB.execute("DELETE FROM hwid_bans WHERE hwid=?", (hashed,))
    DB.commit()
    if cur.rowcount == 0:
        await i.followup.send("That HWID is not banned.", ephemeral=True)
        return
    audit("HWID_UNBAN", actor_id=str(i.user.id), detail=hashed[:16])
    await i.followup.send("HWID unbanned successfully.", ephemeral=True)


@app_commands.command(name="extend",
    description="[ADMIN] Set or extend a user's expiry date.")
@app_commands.describe(user="Target user", expires="New expiry YYYY-MM-DD")
@admin_only()
async def cmd_extend(i: discord.Interaction, user: discord.Member, expires: str):
    await i.response.defer(ephemeral=True)
    exp_iso = parse_date(expires)
    if not exp_iso:
        await i.followup.send("Bad date format. Use YYYY-MM-DD.", ephemeral=True)
        return
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    DB.execute("UPDATE users SET expires_at=?, status='active', ban_reason=NULL "
               "WHERE discord_id=?", (exp_iso, did))
    DB.commit()
    audit("EXTEND", actor_id=str(i.user.id), target_id=did,
          detail=f"new_expiry={expires}")
    await i.followup.send(
        f"Expiry set to `{expires}` for {user.mention}.", ephemeral=True
    )


@app_commands.command(name="setproduct",
    description="[ADMIN] Change a user's product tier.")
@app_commands.describe(user="Target user", product="New product name")
@admin_only()
async def cmd_setproduct(i: discord.Interaction, user: discord.Member, product: str):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    if not DB.execute("SELECT 1 FROM users WHERE discord_id=?", (did,)).fetchone():
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    DB.execute("UPDATE users SET product=? WHERE discord_id=?", (product, did))
    DB.commit()
    audit("SET_PRODUCT", actor_id=str(i.user.id), target_id=did,
          detail=f"product={product}")
    await i.followup.send(
        f"Product updated to `{product}` for {user.mention}.", ephemeral=True
    )


@app_commands.command(name="grantresets",
    description="[ADMIN] Give a user extra HWID reset uses.")
@app_commands.describe(user="Target user",
                       count="Amount to adjust resets by (negative = grant more)")
@admin_only()
async def cmd_grantresets(i: discord.Interaction, user: discord.Member,
                          count: int = -1):
    await i.response.defer(ephemeral=True)
    did = str(user.id)
    row = DB.execute("SELECT hwid_resets FROM users WHERE discord_id=?",
                     (did,)).fetchone()
    if not row:
        await i.followup.send("User is not registered.", ephemeral=True)
        return
    new_val = max(0, row["hwid_resets"] + count)
    DB.execute("UPDATE users SET hwid_resets=? WHERE discord_id=?", (new_val, did))
    DB.commit()
    audit("GRANT_RESETS", actor_id=str(i.user.id), target_id=did,
          detail=f"delta={count} new_val={new_val}")
    await i.followup.send(
        f"HWID reset counter set to `{new_val}` for {user.mention}.", ephemeral=True
    )


@app_commands.command(name="listusers", description="[ADMIN] Browse registered users.")
@app_commands.describe(
    status="Filter: active, banned, revoked",
    product="Filter by product",
    limit="Results to show (max 25)"
)
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
    q += " ORDER BY registered_at DESC LIMIT ?"
    p.append(limit)
    rows = DB.execute(q, p).fetchall()
    if not rows:
        await i.followup.send("No users found.", ephemeral=True)
        return
    lines = []
    for r in rows:
        s = effective_status(r)
        icon = {"active": "GREEN", "banned": "RED",
                "revoked": "GREY", "expired": "ORANGE"}.get(s, s.upper())
        lines.append(
            f"`{r['discord_id']}` - **{icon}** - `{r['product']}` - "
            f"expires `{fmt_dt(r['expires_at'])}`"
        )
    em = discord.Embed(
        title=f"Users ({len(rows)} shown)",
        description="\n".join(lines),
        color=0x5865f2,
        timestamp=datetime.now(timezone.utc)
    )
    await i.followup.send(embed=em, ephemeral=True)


@app_commands.command(name="listkeys",
    description="[ADMIN] Browse unclaimed keys in the pool.")
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
    q += " ORDER BY created_at DESC LIMIT ?"
    p.append(limit)
    rows = DB.execute(q, p).fetchall()
    if not rows:
        await i.followup.send("No unclaimed keys.", ephemeral=True)
        return
    lines = [
        f"`{r['key']}` - `{r['product']}` - expires `{fmt_dt(r['expires_at'])}`"
        for r in rows
    ]
    em = discord.Embed(
        title=f"Unclaimed Keys ({len(rows)})",
        description="\n".join(lines),
        color=0x5865f2,
        timestamp=datetime.now(timezone.utc)
    )
    await i.followup.send(embed=em, ephemeral=True)


@app_commands.command(name="deletekey",
    description="[ADMIN] Delete an unclaimed key from the pool.")
@app_commands.describe(key="The key to delete")
@admin_only()
async def cmd_deletekey(i: discord.Interaction, key: str):
    await i.response.defer(ephemeral=True)
    cur = DB.execute("DELETE FROM key_pool WHERE key=? AND claimed=0",
                     (key.strip().upper(),))
    DB.commit()
    if cur.rowcount == 0:
        await i.followup.send(
            "Key not found or already claimed (claimed keys cannot be deleted).", ephemeral=True
        )
        return
    audit("DELETE_KEY", actor_id=str(i.user.id), detail=f"key={key[:20]}")
    await i.followup.send(f"Key `{key}` deleted from pool.", ephemeral=True)


@app_commands.command(name="auditlog",
    description="[ADMIN] View audit log with optional filters.")
@app_commands.describe(
    limit="Entries to show (max 25)",
    user="Filter by Discord mention or ID",
    action="Filter by action keyword e.g. BAN, REGISTER"
)
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
        await i.followup.send("No entries found.", ephemeral=True)
        return
    lines = []
    for r in rows:
        ts = r["timestamp"][:16].replace("T", " ")
        actor = f"<@{r['actor_id']}>" if r["actor_id"] else "-"
        target = f"<@{r['target_id']}>" if r["target_id"] else "-"
        lines.append(
            f"`{ts}` **{r['action']}** | {actor}"
            + (f" -> {target}" if r["target_id"] else "")
            + (f" | {r['detail'][:60]}" if r["detail"] else "")
        )
    em = discord.Embed(
        title=f"Audit Log ({len(rows)} entries)",
        description="\n".join(lines),
        color=0x5865f2,
        timestamp=datetime.now(timezone.utc)
    )
    await i.followup.send(embed=em, ephemeral=True)


@app_commands.command(name="stats", description="[ADMIN] Full system stats.")
@admin_only()
async def cmd_stats(i: discord.Interaction):
    await i.response.defer(ephemeral=True)
    db = DB
    total    = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active   = db.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    banned   = db.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0]
    revoked  = db.execute("SELECT COUNT(*) FROM users WHERE status='revoked'").fetchone()[0]
    unclaim  = db.execute("SELECT COUNT(*) FROM key_pool WHERE claimed=0").fetchone()[0]
    claimed  = db.execute("SELECT COUNT(*) FROM key_pool WHERE claimed=1").fetchone()[0]
    hwbans   = db.execute("SELECT COUNT(*) FROM hwid_bans").fetchone()[0]
    logs     = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    today    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logins_today = db.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action='API_VERIFY_OK' AND timestamp LIKE ?",
        (today + "%",)
    ).fetchone()[0]
    regs_today = db.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action='REGISTER_SUCCESS' AND timestamp LIKE ?",
        (today + "%",)
    ).fetchone()[0]

    em = discord.Embed(title="KeyLock Stats", color=0x00ff88,
                       timestamp=datetime.now(timezone.utc))
    em.add_field(name="Total Users",         value=total,        inline=True)
    em.add_field(name="Active",              value=active,       inline=True)
    em.add_field(name="Banned",              value=banned,       inline=True)
    em.add_field(name="Revoked",             value=revoked,      inline=True)
    em.add_field(name="Unclaimed Keys",      value=unclaim,      inline=True)
    em.add_field(name="Claimed Keys",        value=claimed,      inline=True)
    em.add_field(name="HWID Bans",           value=hwbans,       inline=True)
    em.add_field(name="Audit Entries",       value=logs,         inline=True)
    em.add_field(name="Logins Today",        value=logins_today, inline=True)
    em.add_field(name="Registrations Today", value=regs_today,   inline=True)
    await i.followup.send(embed=em, ephemeral=True)


@app_commands.command(name="announce",
    description="[ADMIN] Send a styled embed announcement to any channel.")
@app_commands.describe(
    channel="Target channel",
    title="Embed title",
    message="Embed body (use \\n for new lines)",
    color="Hex color e.g. 00ff88"
)
@admin_only()
async def cmd_announce(i: discord.Interaction,
                       channel: discord.TextChannel,
                       title: str, message: str,
                       color: Optional[str] = "00ff88"):
    await i.response.defer(ephemeral=True)
    try:
        c = int(color.lstrip("#"), 16)
    except Exception:
        c = 0x00ff88
    em = discord.Embed(
        title=title,
        description=message.replace("\\n", "\n"),
        color=c,
        timestamp=datetime.now(timezone.utc)
    )
    em.set_footer(text=i.guild.name)
    await channel.send(embed=em)
    audit("ANNOUNCE", actor_id=str(i.user.id),
          detail=f"channel={channel.id} title={title[:50]}")
    await i.followup.send(f"Sent to {channel.mention}.", ephemeral=True)


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
            DB.execute(
                "UPDATE users SET status='revoked', ban_reason='Manual purge: expired' "
                "WHERE discord_id=?", (row["discord_id"],)
            )
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
    await i.followup.send(f"Purged `{count}` expired license(s).", ephemeral=True)


@app_commands.command(name="wipeuser",
    description="[ADMIN] Completely wipe a user's registration (frees their key).")
@app_commands.describe(user="Target user", confirm="Type CONFIRM to proceed")
@admin_only()
async def cmd_wipeuser(i: discord.Interaction, user: discord.Member,
                       confirm: str = ""):
    await i.response.defer(ephemeral=True)
    if confirm != "CONFIRM":
        await i.followup.send(
            "Pass `confirm: CONFIRM` to wipe a user. This cannot be undone.",
            ephemeral=True
        )
        return
    did = str(user.id)
    row = DB.execute("SELECT key FROM users WHERE discord_id=?", (did,)).fetchone()
    if not row:
        await i.followup.send("User is not registered.", ephemeral=True)
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
    await i.followup.send(
        f"User `{did}` wiped. Their key is back in the pool.", ephemeral=True
    )


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
            self._out(403, {"status": "banned", "message": "HWID banned"})
            return

        row = DB.execute("SELECT * FROM users WHERE discord_id=?", (did,)).fetchone()
        if not row:
            audit("API_VERIFY_NO_USER", target_id=did, ip=ip)
            self._out(401, {"status": "not_registered",
                            "message": "Discord account not registered"})
            return

        s = effective_status(row)
        if s in ("banned", "revoked", "expired"):
            audit(f"API_VERIFY_{s.upper()}", target_id=did, ip=ip)
            self._out(403, {"status": s, "message": f"Account {s}"})
            return

        if row["hwid"] and row["hwid"] != hashed:
            audit("API_VERIFY_HWID_MISMATCH", target_id=did, ip=ip)
            self._out(403, {"status": "hwid_mismatch",
                            "message": "HWID does not match registered machine"})
            return

        if not row["hwid"]:
            DB.execute("UPDATE users SET hwid=? WHERE discord_id=?", (hashed, did))

        DB.execute(
            "UPDATE users SET last_seen=?, ip_last=? WHERE discord_id=?",
            (now_iso(), ip, did)
        )
        DB.commit()
        audit("API_VERIFY_OK", target_id=did, ip=ip,
              detail=f"product={row['product']}")

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
    cmd_keygen, cmd_lookup, cmd_ban, cmd_unban, cmd_revoke,
    cmd_addnote, cmd_resethwid, cmd_banhwid, cmd_unbanhwid,
    cmd_extend, cmd_setproduct, cmd_grantresets,
    cmd_listusers, cmd_listkeys, cmd_deletekey,
    cmd_auditlog, cmd_stats, cmd_announce,
    cmd_purgeexpired, cmd_wipeuser,
]

async def main():
    global DB, BOT

    DB  = init_db(CONFIG["db_path"])
    BOT = KeyLock()

    for cmd in ALL_COMMANDS:
        BOT.tree.add_command(cmd)

    threading.Thread(
        target=start_api,
        args=(CONFIG["api_port"],),
        daemon=True
    ).start()

    async with BOT:
        await BOT.start(CONFIG["token"])


if __name__ == "__main__":
    asyncio.run(main())
