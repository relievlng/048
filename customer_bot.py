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
import os
import json
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
    "token":                  env("DISCORD_TOKEN") or env("TOKEN"),
    "guild_id":               env_int("GUILD_ID"),
    "admin_role_id":          env_int("ADMIN_ROLE_ID"),
    "verified_role_id":       env_int("VERIFIED_ROLE_ID"),
    "setup_pings_role_id":    env_int("SETUP_PINGS_ROLE_ID"),
    "setup_alerts_channel_id": env_int("SETUP_ALERTS_CHANNEL_ID"),
    "ticket_category_id":     env_int("TICKET_CATEGORY_ID"),
    "rules_channel_id":       env_int("RULES_CHANNEL_ID"),
    "verify_channel_id":      env_int("VERIFY_CHANNEL_ID"),
    "hwid_channel_id":        env_int("HWID_CHANNEL_ID"),
    "ticket_channel_id":      env_int("TICKET_CHANNEL_ID"),
    # Per-channel webhook URLs (from staff bot's auto-setup output)
    "wh_tickets_opened":      env("WEBHOOK_CUSTOMER_TICKETS_OPENED"),
    "wh_tickets_closed":      env("WEBHOOK_CUSTOMER_TICKETS_CLOSED"),
    "wh_ticket_transcripts":  env("WEBHOOK_CUSTOMER_TICKET_TRANSCRIPTS"),
    "wh_key_generated":       env("WEBHOOK_CUSTOMER_KEY_GENERATED"),
    "wh_bans":                env("WEBHOOK_CUSTOMER_BANS"),
    # Fallback: single webhook for any event type not explicitly wired
    "log_webhook_url":        env("LOG_WEBHOOK_URL"),
    "db_path":                env("DB_PATH", "/data/keylock.db"),
    "key_prefix":             env("KEY_PREFIX", "KL"),
    "api_port":               env_int("PORT", 8080),
}

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
            return False  # already claimed by someone else
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
            return False, f"You have used all {max_resets} HWID reset(s). Contact staff for further assistance."
        conn.execute(
            "UPDATE users SET hwid = NULL, hwid_resets = hwid_resets + 1 WHERE discord_id = ?",
            (str(discord_id),)
        )
        conn.commit()
        return True, f"HWID reset successful. You have {max_resets - row['hwid_resets'] - 1} reset(s) remaining."

# ─── WEBHOOK LOGGING ──────────────────────────────────────────────────────────

async def send_log(title: str, description: str, color: int = 0x5865F2, fields: list = None, webhook_key: str = "log_webhook_url"):
    """Send an embed to the appropriate staff log channel.
    webhook_key: CONFIG key for the specific channel webhook (falls back to log_webhook_url)."""
    url = CONFIG.get(webhook_key) or CONFIG.get("log_webhook_url")
    if not url:
        return
    embed = {
        "title": title,
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fields": fields or [],
    }
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(url, json={"embeds": [embed]})
    except Exception as e:
        log.warning(f"Webhook log failed: {e}")

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

# ─── TICKET VIEWS ─────────────────────────────────────────────────────────────

TICKET_CATEGORIES = {
    "support":  {"label": "Support",           "emoji": "✉️",  "desc": "Product support or general enquiries"},
    "setup":    {"label": "Setup",             "emoji": "🖱️",  "desc": "First time setup and installation"},
    "billing":  {"label": "Billing",           "emoji": "🛒",  "desc": "Purchases, renewals and refunds"},
    "key":      {"label": "Key / HWID Issues", "emoji": "🔑",  "desc": "Key problems and HWID resets"},
}

class TicketPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        for cat_id, cat in TICKET_CATEGORIES.items():
            btn = discord.ui.Button(
                label=cat["label"],
                emoji=cat["emoji"],
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

    @discord.ui.button(label="Close Ticket", emoji="🔒", style=discord.ButtonStyle.danger, custom_id="ticket_close")
    async def close_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await close_ticket(interaction)

    @discord.ui.button(label="Claim", emoji="👤", style=discord.ButtonStyle.secondary, custom_id="ticket_claim")
    async def claim_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message(
            f"**{interaction.user.mention}** has claimed this ticket.", ephemeral=False
        )

async def open_ticket(interaction: discord.Interaction, cat_id: str):
    guild = interaction.guild
    member = interaction.user
    cat_info = TICKET_CATEGORIES[cat_id]

    # Check for existing open ticket
    existing = discord.utils.get(
        guild.text_channels,
        name=f"ticket-{member.name.lower().replace(' ', '-')}"
    )
    if existing:
        await interaction.response.send_message(
            f"You already have an open ticket: {existing.mention}", ephemeral=True
        )
        return

    admin_role = guild.get_role(CONFIG["admin_role_id"])
    ticket_category = guild.get_channel(CONFIG["ticket_category_id"])

    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        member: discord.PermissionOverwrite(view_channel=True, send_messages=True, read_message_history=True),
    }
    if admin_role:
        overwrites[admin_role] = discord.PermissionOverwrite(
            view_channel=True, send_messages=True, read_message_history=True, manage_channels=True
        )

    channel = await guild.create_text_channel(
        name=f"ticket-{member.name.lower().replace(' ', '-')}",
        category=ticket_category,
        overwrites=overwrites,
        topic=f"{cat_info['label']} | {member} ({member.id})",
    )

    embed = discord.Embed(
        title=f"{cat_info['emoji']} {cat_info['label']} Ticket",
        description=(
            f"Hey {member.mention}, thanks for reaching out!\n\n"
            f"**Category:** {cat_info['desc']}\n\n"
            "Please describe your issue and a staff member will be with you shortly.\n"
            "Use the button below to close your ticket when resolved."
        ),
        color=0x2b2d31,
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_footer(text=f"Ticket opened by {member}", icon_url=member.display_avatar.url)

    mention_str = admin_role.mention if admin_role else ""
    await channel.send(
        content=f"{member.mention} {mention_str}",
        embed=embed,
        view=TicketControlView(),
    )

    await interaction.response.send_message(
        f"Your ticket has been opened: {channel.mention}", ephemeral=True
    )

    await send_log(
        title="Ticket Opened",
        description=f"**User:** {member.mention} (`{member.id}`)\n**Category:** {cat_info['label']}\n**Channel:** {channel.mention}",
        color=0x57F287,
        webhook_key="wh_tickets_opened",
    )

async def close_ticket(interaction: discord.Interaction):
    channel = interaction.channel
    admin_role = interaction.guild.get_role(CONFIG["admin_role_id"])
    is_admin = admin_role and admin_role in interaction.user.roles

    if not is_admin and not channel.name.startswith("ticket-"):
        await interaction.response.send_message("You cannot close this ticket.", ephemeral=True)
        return

    await interaction.response.send_message("Closing ticket in 5 seconds...")

    # Build transcript (message content requires the privileged message_content
    # intent - if not enabled, content will be empty; we log what we can)
    messages = []
    msg_count = 0
    async for msg in channel.history(limit=200, oldest_first=True):
        if not msg.author.bot:
            msg_count += 1
            content = msg.content or "[no content - enable Message Content Intent]"
            messages.append(f"[{msg.created_at.strftime('%H:%M')}] {msg.author}: {content}")
    transcript = "\n".join(messages) if messages else f"No messages recorded ({msg_count} total)."

    await send_log(
        title="Ticket Closed",
        description=f"**Channel:** {channel.name}\n**Closed by:** {interaction.user.mention}\n**Messages:** {msg_count}",
        color=0xED4245,
        webhook_key="wh_tickets_closed",
    )
    # Post transcript to its own channel if configured
    if transcript:
        await send_log(
            title=f"Transcript - {channel.name}",
            description=f"```{transcript[:1900]}```",
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
            await interaction.response.send_message(
                "Invalid key. Please check your key and try again.", ephemeral=True
            )
            return

        if row["status"] == "banned":
            await interaction.response.send_message(
                "This key has been banned. Contact staff if you believe this is an error.", ephemeral=True
            )
            return

        # Link key to discord ID
        ok = register_key_to_discord(key, member.id)
        if not ok:
            await interaction.response.send_message(
                "This key is already linked to another Discord account. Contact staff.", ephemeral=True
            )
            return

        verified_role = guild.get_role(CONFIG["verified_role_id"])
        if verified_role and verified_role not in member.roles:
            await member.add_roles(verified_role, reason="Key verification")

        expires = row["expires_at"] or "Never"
        product = row["product"] or "default"

        await interaction.response.send_message(
            f"Verified! You now have access to the server.\n"
            f"**Key:** `{key}`\n**Product:** {product}\n**Expires:** {expires}",
            ephemeral=True,
        )

        await send_log(
            title="User Verified",
            description=f"**User:** {member.mention} (`{member.id}`)\n**Key:** `{key}`\n**Product:** {product}",
            color=0x57F287,
            webhook_key="wh_key_generated",
        )


class VerifyView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Verify", emoji="✅", style=discord.ButtonStyle.success, custom_id="verify_button")
    async def verify_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        # Check if already verified
        verified_role = interaction.guild.get_role(CONFIG["verified_role_id"])
        if verified_role and verified_role in interaction.user.roles:
            await interaction.response.send_message("You are already verified!", ephemeral=True)
            return
        await interaction.response.send_modal(VerifyModal())

# ─── HWID RESET VIEW ──────────────────────────────────────────────────────────

class HWIDView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Reset HWID", emoji="🔄", style=discord.ButtonStyle.secondary, custom_id="hwid_reset_button")
    async def hwid_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        success, message = reset_hwid(str(interaction.user.id))
        if success:
            embed = discord.Embed(
                title="HWID Reset Successful",
                description=message,
                color=0x57F287,
            )
            await send_log(
                title="HWID Reset",
                description=f"**User:** {interaction.user.mention} (`{interaction.user.id}`)",
                color=0xFEE75C,
                webhook_key="wh_key_generated",
            )
        else:
            embed = discord.Embed(
                title="HWID Reset Failed",
                description=message,
                color=0xED4245,
            )
        await interaction.response.send_message(embed=embed, ephemeral=True)


# ─── SETUP PINGS VIEW ─────────────────────────────────────────────────────────

class SetupPingsView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(
        label="Setup Pings",
        emoji="🔔",
        style=discord.ButtonStyle.secondary,
        custom_id="setup_pings_toggle",
    )
    async def toggle_setup_pings(self, interaction: discord.Interaction, button: discord.ui.Button):
        role_id = CONFIG["setup_pings_role_id"]
        if not role_id:
            await interaction.response.send_message(
                "Setup pings role is not configured. Contact staff.", ephemeral=True
            )
            return
        role = interaction.guild.get_role(role_id)
        if not role:
            await interaction.response.send_message(
                "Setup pings role not found. Contact staff.", ephemeral=True
            )
            return
        member = interaction.user
        if role in member.roles:
            await member.remove_roles(role, reason="Setup pings toggle")
            await interaction.response.send_message(
                f"Removed **{role.name}** - you will no longer receive setup pings.", ephemeral=True
            )
        else:
            await member.add_roles(role, reason="Setup pings toggle")
            await interaction.response.send_message(
                f"Added **{role.name}** - you will be pinged when setup team is available.", ephemeral=True
            )


# ─── BOT ──────────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
# Members and message_content are privileged intents.
# Enable them in the Discord Developer Portal if you want full member cache
# and message transcript content. The bot runs without them - role ops use
# interaction.user directly, and transcripts fall back to message count only.
intents.members = False
intents.message_content = False

bot = commands.Bot(command_prefix="!", intents=intents)

SENTINEL = "/data/.customer_channels_done"

async def _setup_customer_channels(guild: discord.Guild):
    """Auto-create verify and hwid-reset channels if not done yet. Prints IDs for Railway env vars."""
    if os.path.exists(SENTINEL):
        return

    log.info("First run: setting up customer channels...")

    admin_role = guild.get_role(CONFIG["admin_role_id"])

    # Find or create the category
    CATEGORY_NAME = "CUSTOMER BOT"
    category = discord.utils.get(guild.categories, name=CATEGORY_NAME)
    if not category:
        cat_overwrites = {
            guild.default_role: discord.PermissionOverwrite(view_channel=True, send_messages=False),
        }
        if admin_role:
            cat_overwrites[admin_role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True,
                manage_channels=True, manage_messages=True,
            )
        category = await guild.create_category(CATEGORY_NAME, overwrites=cat_overwrites)
        log.info(f"  Created category: {CATEGORY_NAME} ({category.id})")
    else:
        log.info(f"  Category '{CATEGORY_NAME}' already exists ({category.id})")

    # Channels to create inside the category
    CHANNELS = [
        ("rules",      True),
        ("verify",     True),
        ("hwid-reset", True),
        ("tickets",    True),
    ]

    created = {}
    for ch_name, public in CHANNELS:
        existing = discord.utils.get(guild.text_channels, name=ch_name)
        if existing:
            created[ch_name] = existing
            log.info(f"  #{ch_name} already exists ({existing.id})")
            continue

        overwrites = {
            guild.default_role: discord.PermissionOverwrite(
                view_channel=public,
                send_messages=False,
                read_message_history=public,
            ),
        }
        if admin_role:
            overwrites[admin_role] = discord.PermissionOverwrite(
                view_channel=True, send_messages=True,
                manage_channels=True, manage_messages=True,
            )

        ch = await guild.create_text_channel(name=ch_name, category=category, overwrites=overwrites)
        created[ch_name] = ch
        log.info(f"  Created #{ch_name} ({ch.id})")

    # Post verify panel
    verify_ch = created.get("verify")
    if verify_ch:
        embed = discord.Embed(
            title="Verification",
            description=(
                "To access this server, verify your license key.\n\n"
                "Click **Verify** below and enter your license key when prompted.\n"
                "Your key is linked to your Discord account permanently."
            ),
            color=0x2b2d31,
        )
        embed.set_footer(text="One key per Discord account.")
        await verify_ch.send(embed=embed, view=VerifyView())

    # Post HWID panel
    hwid_ch = created.get("hwid-reset")
    if hwid_ch:
        embed = discord.Embed(
            title="HWID Reset",
            description=(
                "If you have changed hardware or reinstalled Windows, you can reset your HWID here.\n\n"
                "Click **Reset HWID** below. You have a limited number of resets.\n"
                "If you have used all resets, open a ticket in the key/HWID category."
            ),
            color=0x2b2d31,
        )
        embed.set_footer(text="HWID resets are limited. Use only when necessary.")
        await hwid_ch.send(embed=embed, view=HWIDView())

    # Post ticket panel
    ticket_ch = created.get("tickets")
    if ticket_ch:
        embed = discord.Embed(
            title="Tickets",
            description="Choose a category. A private channel opens and staff meet you there.",
            color=0x2b2d31,
        )
        for cat_id, cat in TICKET_CATEGORIES.items():
            embed.add_field(name=f"{cat['emoji']} {cat['label']}", value=cat["desc"], inline=False)
        await ticket_ch.send(embed=embed, view=TicketPanelView())

    # Post rules
    rules_ch = created.get("rules")
    if rules_ch:
        embed = discord.Embed(
            title="Server Rules",
            description=(
                "By being in this server you agree to the following rules.\n"
                "Violations may result in removal from the server or key termination."
            ),
            color=0x2b2d31,
        )
        rules = [
            ("1. Respect everyone", "Harassment, discrimination, and toxicity are not tolerated."),
            ("2. No sharing keys", "License keys are non-transferable. Sharing a key will result in a permanent ban."),
            ("3. No chargebacks", "Initiating a chargeback voids your license immediately with no refund."),
            ("4. No leaking", "Do not share, leak, or redistribute any files or software from this server."),
            ("5. No ban evasion", "Attempting to bypass a ban results in a permanent blacklist."),
            ("6. Use correct channels", "Keep discussions in their respective channels."),
            ("7. No advertising", "Advertising other products or services without permission is not allowed."),
            ("8. Follow Discord ToS", "All Discord Terms of Service rules apply at all times."),
        ]
        for name, value in rules:
            embed.add_field(name=name, value=value, inline=False)
        embed.set_footer(text="Last updated by staff")
        await rules_ch.send(embed=embed)

    # Print IDs for Railway
    print("\n" + "=" * 60)
    print("===== CUSTOMER BOT - RAILWAY ENV VARS =====")
    print("Paste these into your Railway customer bot service:")
    print("=" * 60)
    for ch_name, ch in created.items():
        key = f"{ch_name.upper().replace('-', '_')}_CHANNEL_ID"
        print(f"{key}={ch.id}")
    print(f"GUILD_ID={guild.id}")
    print("=" * 60 + "\n")

    # Write sentinel so this doesn't re-run
    os.makedirs("/data", exist_ok=True)
    with open(SENTINEL, "w") as f:
        f.write("done")

    log.info("Customer channel setup complete.")


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

    guild = bot.get_guild(CONFIG["guild_id"])
    if guild:
        await _setup_customer_channels(guild)
    else:
        log.warning(f"Guild {CONFIG['guild_id']} not found - skipping channel setup")

# ─── SLASH COMMANDS ───────────────────────────────────────────────────────────

@bot.tree.command(name="setup-tickets", description="[Admin] Post the ticket panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_tickets(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Tickets",
        description="Choose a category. A private channel opens and staff meet you there.",
        color=0x2b2d31,
    )
    for cat_id, cat in TICKET_CATEGORIES.items():
        embed.add_field(
            name=f"{cat['emoji']} {cat['label']}",
            value=cat["desc"],
            inline=False,
        )
    await interaction.channel.send(embed=embed, view=TicketPanelView())
    await interaction.response.send_message("Ticket panel posted.", ephemeral=True)


@bot.tree.command(name="setup-verify", description="[Admin] Post the verification panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_verify(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Verification",
        description=(
            "To access this server, verify your license key.\n\n"
            "Click **Verify** below and enter your license key when prompted.\n"
            "Your key is linked to your Discord account permanently."
        ),
        color=0x2b2d31,
    )
    embed.set_footer(text="One key per Discord account.")
    await interaction.channel.send(embed=embed, view=VerifyView())
    await interaction.response.send_message("Verification panel posted.", ephemeral=True)


@bot.tree.command(name="setup-hwid", description="[Admin] Post the HWID reset panel in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_hwid(interaction: discord.Interaction):
    embed = discord.Embed(
        title="HWID Reset",
        description=(
            "If you have changed hardware or reinstalled Windows, you can reset your HWID here.\n\n"
            "Click **Reset HWID** below. You have a limited number of resets.\n"
            "If you have used all resets, open a ticket in the key/HWID category."
        ),
        color=0x2b2d31,
    )
    embed.set_footer(text="HWID resets are limited. Use only when necessary.")
    await interaction.channel.send(embed=embed, view=HWIDView())
    await interaction.response.send_message("HWID reset panel posted.", ephemeral=True)


@bot.tree.command(name="setup-rules", description="[Admin] Post the rules embed in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_rules(interaction: discord.Interaction):
    embed = discord.Embed(
        title="Server Rules",
        description=(
            "By being in this server you agree to the following rules.\n"
            "Violations may result in removal from the server or key termination."
        ),
        color=0x2b2d31,
    )
    rules = [
        ("1. Respect everyone", "Harassment, discrimination, and toxicity are not tolerated."),
        ("2. No sharing keys", "License keys are non-transferable. Sharing a key will result in a permanent ban."),
        ("3. No chargebacks", "Initiating a chargeback voids your license immediately with no refund."),
        ("4. No leaking", "Do not share, leak, or redistribute any files or software from this server."),
        ("5. No ban evasion", "Attempting to bypass a ban results in a permanent blacklist."),
        ("6. Use correct channels", "Keep discussions in their respective channels. Keep #general clean."),
        ("7. No advertising", "Advertising other products or services without permission is not allowed."),
        ("8. Follow Discord ToS", "All Discord Terms of Service rules apply at all times."),
    ]
    for name, value in rules:
        embed.add_field(name=name, value=value, inline=False)
    embed.set_footer(text="Last updated by staff")
    await interaction.channel.send(embed=embed)
    await interaction.response.send_message("Rules posted.", ephemeral=True)


@bot.tree.command(name="setup-info", description="[Admin] Post the setup instructions embed in the current channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def setup_info_cmd(interaction: discord.Interaction):
    guild = interaction.guild

    # Resolve ticket channel mention
    ticket_ch = guild.get_channel(CONFIG["ticket_channel_id"])
    ticket_ref = ticket_ch.mention if ticket_ch else "#open-a-ticket"

    # Resolve setup alerts channel mention
    alerts_ch_id = CONFIG["setup_alerts_channel_id"]
    alerts_ch = guild.get_channel(alerts_ch_id) if alerts_ch_id else None
    alerts_ref = alerts_ch.mention if alerts_ch else "#setup-alerts"

    embed = discord.Embed(
        title="Awaiting Setup?",
        description="Complete every step below, then wait for the Setup Team.",
        color=0x2b2d31,
    )
    embed.add_field(
        name="🔔 GET SETUP PINGS ROLE",
        value="Click the button below to get the Setup Pings role (click again to remove it).",
        inline=False,
    )
    embed.add_field(
        name="📋 OPEN A SETUP TICKET",
        value=(
            f"Open a setup ticket here: {ticket_ref}\n"
            "Your Invoice ID is in your DMs with this bot."
        ),
        inline=False,
    )
    embed.add_field(
        name="⏰ WAIT FOR SETUP TEAM",
        value=(
            f"Check {alerts_ref} regularly.\n"
            "When a setup team member is available, ping them in your ticket **once** "
            "with your **AnyDesk code & invoice ID**."
        ),
        inline=False,
    )
    embed.add_field(
        name="⚠️ IMPORTANT",
        value="Do **NOT** ping staff unless they have announced they are available for setups.",
        inline=False,
    )

    await interaction.channel.send(embed=embed, view=SetupPingsView())
    await interaction.response.send_message("Setup info posted.", ephemeral=True)


@bot.tree.command(name="key", description="Check your license key status.")
async def key_cmd(interaction: discord.Interaction):
    row = lookup_user(str(interaction.user.id))
    if not row:
        await interaction.response.send_message(
            "No key is linked to your account. Use `/verify` or the verification panel to link your key.",
            ephemeral=True,
        )
        return
    expires = row["expires_at"] or "Never"
    hwid_used = row["hwid"] is not None
    max_resets = CONFIG.get("max_hwid_resets", 1)
    resets_left = max(0, int(max_resets) - int(row["hwid_resets"]))
    embed = discord.Embed(title="Your License", color=0x2b2d31)
    embed.add_field(name="Key", value=f"`{row['key']}`", inline=False)
    embed.add_field(name="Product", value=row["product"] or "default", inline=True)
    embed.add_field(name="Status", value=row["status"].capitalize(), inline=True)
    embed.add_field(name="Expires", value=expires, inline=True)
    embed.add_field(name="HWID Bound", value="Yes" if hwid_used else "No", inline=True)
    embed.add_field(name="HWID Resets Left", value=str(resets_left), inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="hwid-reset", description="Reset your HWID (limited uses).")
async def hwid_reset_cmd(interaction: discord.Interaction):
    success, message = reset_hwid(str(interaction.user.id))
    if success:
        embed = discord.Embed(
            title="HWID Reset Successful",
            description=message,
            color=0x57F287,
        )
        await send_log(
            title="HWID Reset",
            description=f"**User:** {interaction.user.mention} (`{interaction.user.id}`)",
            color=0xFEE75C,
            webhook_key="wh_key_generated",
        )
    else:
        embed = discord.Embed(
            title="HWID Reset Failed",
            description=message,
            color=0xED4245,
        )
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="verify", description="Link your license key to your Discord account.")
async def verify_cmd(interaction: discord.Interaction):
    verified_role = interaction.guild.get_role(CONFIG["verified_role_id"])
    if verified_role and verified_role in interaction.user.roles:
        await interaction.response.send_message("You are already verified!", ephemeral=True)
        return
    await interaction.response.send_modal(VerifyModal())


# Admin commands
@bot.tree.command(name="lookup", description="[Admin] Look up a user's key by Discord ID.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def lookup_cmd(interaction: discord.Interaction, user: discord.Member):
    row = lookup_user(str(user.id))
    if not row:
        await interaction.response.send_message(f"No key linked to {user.mention}.", ephemeral=True)
        return
    expires = row["expires_at"] or "Never"
    embed = discord.Embed(title=f"Key Lookup: {user}", color=0x5865F2)
    embed.add_field(name="Key", value=f"`{row['key']}`", inline=False)
    embed.add_field(name="Product", value=row["product"] or "default", inline=True)
    embed.add_field(name="Status", value=row["status"].capitalize(), inline=True)
    embed.add_field(name="Expires", value=expires, inline=True)
    embed.add_field(name="HWID", value=f"`{row['hwid']}`" if row["hwid"] else "Not bound", inline=False)
    embed.add_field(name="HWID Resets", value=str(row["hwid_resets"]), inline=True)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="close", description="[Admin] Force-close a ticket channel.")
@app_commands.checks.has_role(CONFIG["admin_role_id"])
async def close_cmd(interaction: discord.Interaction):
    if not interaction.channel.name.startswith("ticket-"):
        await interaction.response.send_message("This is not a ticket channel.", ephemeral=True)
        return
    await close_ticket(interaction)


# ─── ENTRY POINT ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    start_health_server(CONFIG["api_port"])
    bot.run(CONFIG["token"])
