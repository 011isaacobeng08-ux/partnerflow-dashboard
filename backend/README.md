# PartnerFlow Admin API

This backend runs in the existing PartnerFlow Python project. It imports the existing `config.py` and uses the same `config.DB_PATH` as both bots.

## Security
- Discord OAuth uses only the `identify` scope.
- The server checks each Discord user ID against a separate `admin_allowlist` table.
- `ADMIN_OWNER_ID` is the designated owner and is separate from `OWNER_IDS`.
- Only the designated owner can grant or revoke admins.
- Sessions are signed, secure, HTTP-only cookies. All API requests require an approved session.
- The OAuth secret and session secret must be private Wispbyte environment variables.

## Existing database
The API creates only two new tables: `admin_allowlist` and `admin_audit_logs`. It does not reset or migrate the bot's existing tables. It uses the exact path from `config.DB_PATH`; do not set a second database path.

## Startup
The updated root `start.py` starts this API in the same Wispbyte app when `ADMIN_API_ENABLED=1`. Keep the current command:

```sh
pip install -r requirements.txt && python start.py
```

Set `PORT` to the port provided by the host, if Wispbyte supplies one.

## Required private environment variables
- `ADMIN_API_ENABLED=1`
- `ADMIN_APP_ORIGIN=https://011isaacobeng08-ux.github.io/partnerflow-dashboard`
- `ADMIN_DISCORD_CLIENT_ID`
- `ADMIN_DISCORD_CLIENT_SECRET`
- `ADMIN_DISCORD_REDIRECT_URI=https://YOUR-APP-HOST/auth/callback`
- `ADMIN_SESSION_SECRET` (at least 32 characters, random)
- `ADMIN_OWNER_ID` (your Discord user ID)

Register the exact redirect URI in the Discord Developer Portal. Never commit real credentials to GitHub.

## API scope
Login, allowlist management, and read-only views for server records, pending reviews, verification, tickets, premium records and admin audit events are implemented. Bot-changing actions are deliberately not exposed yet.
