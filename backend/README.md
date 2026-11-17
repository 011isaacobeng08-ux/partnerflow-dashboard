# PartnerFlow Admin API

This is the server-side authentication and admin allowlist service for the GitHub Pages control panel.

## Security model
- Discord OAuth uses the `identify` scope only.
- The backend checks the Discord user ID against the separate `admin_allowlist` table.
- `ADMIN_OWNER_ID` is the one designated owner account and is not stored as an ordinary allowlist entry.
- Only that owner can list, grant, or revoke admin access.
- Every protected endpoint checks the session and allowlist on the server.
- The OAuth client secret and session signing secret belong only in private host environment variables.

## Database
Set `ADMIN_DB_PATH` to the exact SQLite database file PartnerFlow already uses. On startup, this API creates only the `admin_allowlist` table if it does not exist. It does not reset or modify existing bot tables. Back up the database before first deployment.

## Hosting configuration
Install dependencies from this folder's `requirements.txt`, then run:

```sh
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Set the working directory to `backend`. Configure all values from `.env.example` as private environment variables in the host panel; do not commit real values.

In the Discord Developer Portal, add the exact value of `DISCORD_REDIRECT_URI` to the OAuth2 redirect URLs. Use the same application that owns the PartnerFlow bot.

## Important integration note
This API is a separate web process. It must be launched alongside the existing main and helper bot processes by the current Wispbyte startup configuration. Do not replace the existing bot startup command until the current Wispbyte project files and process limits have been checked. Do not run a second copy of the bots or point this service at a guessed database path.

The static website still needs its sign-in and admin-management UI wired to the deployed API URL. The API is not live until it is deployed with the correct private environment variables and verified against the existing database.
