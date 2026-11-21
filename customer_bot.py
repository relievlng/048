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
    "token":                   env("DISCORD_TOKEN") or env("TOKEN"),
    "guild_id":                env_int("GUILD_ID"),
    "admin_role_id":           env_int("ADMIN_ROLE_ID"),
    "verified_role_id":        env_int("VERIFIED_ROLE_ID"),
    "setup_pings_role_id":     env_int("SETUP_PINGS_ROLE_ID"),
    "setup_alerts_channel_id": env_int("SETUP_ALERTS_CHANNEL_ID"),
    "ticket_category_id":      env_int("TICKET_CATEGORY_ID"),
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

# ─── WEBHOOK LOGGING (Components v2) ──────────────────────────────────────────

async def send_log(
    title: str,
    description: str,
    color: int = 0x5865F2,
    fields: list = None,
    webhook_key: str = "log_webhook_url",
):
    """Send a Components v2 container to the appropriate staff log channel."""
    url = CONFIG.get(webhook_key) or CONFIG.get("log_webhook_url")
    if not url:
        return

    parts = [f"### {title}", description]
    if fields:
        for field in fields:
            parts.append(f"\n**{field['name']}**\n{field['value']}")

    payload = {
        "flags": 1 << 15,  # IS_COMPONENTS_V2
        "components": [
            {
                "type": 17,       # Container
                "accent_color": color,
                "components": [
                    {
                        "type": 10,   # Text Display
                        "content": "\n".join(parts),
                    }
                ],
            }
        ],
    }
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(url, json=payload)
    except Exception as exc:
        log.warning(f"Webhook log failed: {exc}")

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

# ─── COMPONENTS v2 HELPERS ────────────────────────────────────────────────────

def _container(text: str, color: int = 0x2b2d31) -> discord.ui.Container:
    """Build a Components v2 Container with a single TextDisplay child."""
    return discord.ui.Container(
        discord.ui.TextDisplay(text),
        accent_colour=discord.Colour(color),
    )

async def _send_v2(
    channel: discord.TextChannel,
    text: str,
    color: int = 0x2b2d31,
    view: discord.ui.View = None,
):
    """Send a Components v2 message to a channel."""
    kwargs = {
        "components": [_container(text, color)],
    }
    if view:
        kwargs["view"] = view
    await channel.send(**kwargs)

async def _reply_v2(
    interaction: discord.Interaction,
    text: str,
    color: int = 0x2b2d31,
    ephemeral: bool = True,
):
    """Respond to an interaction with a Components v2 message."""
    await interaction.response.send_message(
        components=[_container(text, color)],
        ephemeral=ephemeral,
    )

# ─── TICKET VIEWS ─────────────────────────────────────────────────────────────

TICKET_CATEGORIES = {
    "support":  {"label": "Support",           "emoji": e("ticket"),   "desc": "Product support or general enquiries"},
    "setup":    {"label": "Setup",             "emoji": e("arrow"),    "desc": "First time setup and installation"},
    "billing":  {"label": "Billing",           "emoji": e("shield"),   "desc": "Purchases, renewals and refunds"},
    "key":      {"label": "Key / HWID Issues", "emoji": e("key"),      "desc": "Key problems and HWID resets"},
}

class TicketPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        for cat_id, cat in TICKET_CATEGORIES.items():
            btn = discord.ui.Button(
                label=cat["label"],
                emoji=None,
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
    guild = interaction.guild
    member = interaction.user
    cat_info = TICKET_CATEGORIES[cat_id]

    existing = discord.utils.get(
        guild.text_channels,
        name=f"ticket-{member.name.lower().replace(' ', '-')}"
    )
    if existing:
        await _reply_v2(
            interaction,
            f"You already have an open ticket: {existing.mention}\n\n-# Close your existing ticket before opening a new one.",
            color=0xFEE75C,
        )
        return

    admin_role = guild.get_role(CONFIG["admin_role_id"])
    ticket_category = guild.get_channel(CONFIG["ticket_category_id"])

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True
        ),
    }
    if admin_role:
        overwrites[admin_role] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True,
            read_message_history=True, manage_channels=True
        )

    channel = await guild.create_text_channel(
        name=f"ticket-{member.name.lower().replace(' ', '-')}",
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
        components=[_container(text, 0x2b2d31)],
        view=TicketControlView(),
    )

    await _reply_v2(
        interaction,
        f"{e('arrow')} Your ticket has been opened: {channel.mention}",
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


async def close_ticket(interaction: discord.Interaction):
    channel = interaction.channel
    admin_role = interaction.guild.get_role(CONFIG["admin_role_id"])
    is_admin = admin_role and admin_role in interaction.user.roles

    if not is_admin and not channel.name.startswith("ticket-"):
        await _reply_v2(interaction, f"{e('cross')} You cannot close this ticket.", color=0xED4245)
        return

    await interaction.response.send_message("Closing ticket in 5 seconds...")

    messages = []
    msg_count = 0
    async for msg in channel.history(limit=200, oldest_first=True):
        if not msg.author.bot:
            msg_count += 1
            content = msg.content or "[no content - enable Message Content Intent]"
            messages.append(f"[{msg.created_at.strftime('%H:%M')}] {msg.author}: {content}")
    transcript = "\n".join(messages) if messages else f"No messages recorded ({msg_count} total)."

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

    await asyncio.sleep(5)
    await channel.delete(reason=f"Ticket closed by {interaction.user}")

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
    bot.add_view(TicketPanelView())
    bot.add_view(TicketControlView())
    bot.add_view(VerifyView())
    bot.add_view(HWIDView())
    bot.add_view(SetupPingsView())
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
    cats = "\n".join(
        f"{e('dot')} **{cat['label']}** - {cat['desc']}"
        for cat in TICKET_CATEGORIES.values()
    )
    text = (
        f"## {e('ticket')} Open a Ticket\n\n"
        "Choose a category below. A private channel opens and staff meet you there.\n\n"
        f"{cats}"
    )
    await interaction.channel.send(
        components=[_container(text, 0x2b2d31)],
        view=TicketPanelView(),
    )
    await _reply_v2(interaction, f"{e('verify')} Ticket panel posted.", color=0x57F287)


@bot.tree.command(name="setup-verify", description="[Admin] Post the verification panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_verify(interaction: discord.Interaction):
    text = (
        f"## {e('verify')} Verification\n\n"
        "To access this server you need to verify your license key.\n\n"
        f"{e('arrow')} Click **Verify** below and enter your license key when prompted.\n"
        f"{e('key')} Your key is linked to your Discord account permanently.\n\n"
        "-# One key per Discord account."
    )
    await interaction.channel.send(
        components=[_container(text, 0x2b2d31)],
        view=VerifyView(),
    )
    await _reply_v2(interaction, f"{e('verify')} Verification panel posted.", color=0x57F287)


@bot.tree.command(name="setup-hwid", description="[Admin] Post the HWID reset panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_hwid(interaction: discord.Interaction):
    text = (
        f"## {e('chip')} HWID Reset\n\n"
        "Changed hardware or reinstalled Windows? Reset your HWID here.\n\n"
        f"{e('arrow')} Click **Reset HWID** below.\n"
        f"{e('warn')} You have a limited number of resets - use only when necessary.\n"
        f"{e('ticket')} Used all resets? Open a ticket in the Key / HWID category.\n\n"
        "-# HWID resets are logged and monitored."
    )
    await interaction.channel.send(
        components=[_container(text, 0x2b2d31)],
        view=HWIDView(),
    )
    await _reply_v2(interaction, f"{e('verify')} HWID panel posted.", color=0x57F287)


@bot.tree.command(name="setup-rules", description="[Admin] Post the rules in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_rules(interaction: discord.Interaction):
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
    rule_lines = "\n".join(
        f"{e('dot')} **{name}** - {value}"
        for name, value in rules
    )
    text = (
        f"## {e('rules')} Server Rules\n\n"
        "By being in this server you agree to the following rules.\n"
        "Violations may result in removal or key termination.\n\n"
        f"{rule_lines}\n\n"
        "-# Last updated by staff"
    )
    await interaction.channel.send(components=[_container(text, 0x2b2d31)])
    await _reply_v2(interaction, f"{e('verify')} Rules posted.", color=0x57F287)


@bot.tree.command(name="setup-info", description="[Admin] Post the setup instructions in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_info_cmd(interaction: discord.Interaction):
    guild = interaction.guild

    ticket_ch = guild.get_channel(CONFIG["ticket_channel_id"])
    ticket_ref = ticket_ch.mention if ticket_ch else "#open-a-ticket"

    alerts_ch = guild.get_channel(CONFIG["setup_alerts_channel_id"]) if CONFIG["setup_alerts_channel_id"] else None
    alerts_ref = alerts_ch.mention if alerts_ch else "#setup-alerts"

    text = (
        f"## {e('warn')} Awaiting Setup?\n\n"
        "Complete every step below, then wait for the Setup Team.\n\n"
        f"{e('dot')} **Get Setup Pings** - Click the button below to receive setup pings (click again to remove).\n\n"
        f"{e('dot')} **Open a Setup Ticket** - Open a setup ticket in {ticket_ref}. Your Invoice ID is in your DMs with this bot.\n\n"
        f"{e('dot')} **Wait for the Setup Team** - Check {alerts_ref} regularly. When a team member is available, ping them in your ticket **once** with your AnyDesk code and invoice ID.\n\n"
        f"{e('warn')} Do **NOT** ping staff unless they have announced they are available for setups.\n\n"
        "-# Failing to follow these steps may delay your setup."
    )
    await interaction.channel.send(
        components=[_container(text, 0x2b2d31)],
        view=SetupPingsView(),
    )
    await _reply_v2(interaction, f"{e('verify')} Setup info posted.", color=0x57F287)


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
