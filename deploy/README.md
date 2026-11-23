# Moving the bots to a VPS

Runs all four bots (main/loader, void, customer, staff) on one Ubuntu/Debian
VPS under `systemd`, sharing one database. Because they are on the same box they
share `keylock.db` and talk over `localhost`, so key delivery and verify work
without any external URLs.

## Port map (one box, one port each)

| Bot          | Script            | Port | Reached by                         |
|--------------|-------------------|------|------------------------------------|
| Main/loader  | `bot.py`          | 8080 | your loader client (`/verify`)     |
| Customer     | `customer_bot.py` | 8081 | staff bot, for key delivery        |
| Staff        | `staff_bot.py`    | 8082 | -                                  |
| Void (sales) | `void_bot.py`     | 8083 | customer bot, for invoice verify   |

Inter-bot calls are wired to `http://127.0.0.1:<port>` in the env templates.

## Before you start: save your Railway data

Your license keys, users, payments and tickets live in `keylock.db` on Railway.
Get that file first (Railway CLI `railway ssh` into a service and copy
`/data/keylock.db` out), or ask and a DB-export command can be added to a bot.
You will drop it onto the VPS in step 3.

## Install

1. Get the code onto the VPS. Easiest is to copy this repo into `/opt/voidbots`
   (scp, or `git clone` if you add a deploy key for the private repo).
2. Run the setup script:
   ```
   sudo bash /opt/voidbots/deploy/setup.sh
   ```
   It installs Python, the `cairosvg` system lib, a virtualenv with the
   dependencies, the env templates, and the systemd services.
3. Put your saved database in place:
   ```
   cp /path/to/keylock.db /opt/voidbots/data/keylock.db
   chown voidbots:voidbots /opt/voidbots/data/keylock.db
   ```
4. Fill in the env files in `/opt/voidbots/env/` (`main.env`, `customer.env`,
   `staff.env`, `void.env`) with your tokens, guild/role/channel IDs and
   webhooks. Use the **same** `INTERNAL_API_KEY` in customer, staff and void.
5. Start them, enabled on boot:
   ```
   sudo systemctl enable --now voidbot-main voidbot-void voidbot-customer voidbot-staff
   ```

## Running the bots

- Status:  `systemctl status voidbot-customer`
- Logs:    `journalctl -u voidbot-customer -f`
- Restart: `sudo systemctl restart voidbot-staff`
- Update:  `git -C /opt/voidbots pull && sudo systemctl restart voidbot-main voidbot-void voidbot-customer voidbot-staff`

## Notes

- Keep the Railway services running until the VPS is confirmed working, then
  delete them. Do not run both at once pointed at Discord with the same tokens.
- The loader client's verify URL changes from the Railway domain to your VPS:
  point it at `http://<vps-ip>:8080`. Open that port in the firewall; keep
  8081-8083 closed to the internet (they are localhost-only between the bots).
- `EMOJI_*` variables can stay blank. Each bot uploads its emojis from the
  `emojis/` folder on first boot.
