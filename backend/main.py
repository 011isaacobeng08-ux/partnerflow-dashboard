from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

import config

APP_ORIGIN = os.getenv("ADMIN_APP_ORIGIN", "https://011isaacobeng08-ux.github.io/partnerflow-dashboard").rstrip("/")
DISCORD_CLIENT_ID = os.getenv("ADMIN_DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("ADMIN_DISCORD_CLIENT_SECRET", "").strip()
DISCORD_REDIRECT_URI = os.getenv("ADMIN_DISCORD_REDIRECT_URI", "").strip()
SESSION_SECRET = os.getenv("ADMIN_SESSION_SECRET", "").strip()
ADMIN_OWNER_ID = os.getenv("ADMIN_OWNER_ID", "").strip()
DB_PATH = Path(config.DB_PATH).resolve()

app = FastAPI(title="PartnerFlow Admin API", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET or "NOT_CONFIGURED",
    same_site="none",
    https_only=True,
    session_cookie="pf_admin_session",
    max_age=60 * 60 * 8,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[APP_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

def settings_ready() -> bool:
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET and DISCORD_REDIRECT_URI
                and len(SESSION_SECRET) >= 32 and ADMIN_OWNER_ID.isdigit())

def connect_db() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="PartnerFlow database was not found at config.DB_PATH.")
    con = sqlite3.connect(str(DB_PATH), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout = 10000")
    con.execute("""CREATE TABLE IF NOT EXISTS admin_allowlist (
        discord_id TEXT PRIMARY KEY, added_by TEXT NOT NULL,
        added_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT NOT NULL,
        action TEXT NOT NULL, target_id TEXT,
        created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
    )""")
    con.commit()
    return con

def is_allowed(user_id: str) -> bool:
    if not ADMIN_OWNER_ID.isdigit():
        return False
    if user_id == ADMIN_OWNER_ID:
        return True
    with closing(connect_db()) as con:
        row = con.execute("SELECT 1 FROM admin_allowlist WHERE discord_id = ?", (user_id,)).fetchone()
    return row is not None

def current_user(request: Request) -> dict:
    user = request.session.get("discord_user")
    if not user or not user.get("id"):
        raise HTTPException(status_code=401, detail="Sign in with Discord first.")
    if not is_allowed(str(user["id"])):
        request.session.clear()
        raise HTTPException(status_code=403, detail="This Discord ID is not approved for PartnerFlow Admin.")
    return user

def owner_user(request: Request) -> dict:
    user = current_user(request)
    if str(user["id"]) != ADMIN_OWNER_ID:
        raise HTTPException(status_code=403, detail="Only the designated owner can manage admin access.")
    return user

@app.middleware("http")
async def protect_writes(request: Request, call_next):
    if request.method in {"POST", "DELETE"} and request.url.path.startswith("/api/"):
        if request.headers.get("origin", "").rstrip("/") != APP_ORIGIN:
            return Response("Invalid request origin", status_code=403)
    return await call_next(request)

@app.get("/health")
def health():
    return {"ok": True, "service": "partnerflow-admin-api", "configured": settings_ready()}

@app.get("/auth/login")
def login(request: Request):
    if not settings_ready():
        raise HTTPException(status_code=503, detail="Discord OAuth environment variables are not configured.")
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    params = {"client_id": DISCORD_CLIENT_ID, "redirect_uri": DISCORD_REDIRECT_URI,
              "response_type": "code", "scope": "identify", "state": state}
    return RedirectResponse("https://discord.com/oauth2/authorize?" + urlencode(params))

@app.get("/auth/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    if not settings_ready():
        raise HTTPException(status_code=503, detail="Discord OAuth is not configured.")
    expected = request.session.pop("oauth_state", None)
    if not code or not expected or not secrets.compare_digest(state, expected):
        raise HTTPException(status_code=400, detail="Invalid or expired Discord sign-in state.")
    async with httpx.AsyncClient(timeout=15) as client:
        token_response = await client.post(
            "https://discord.com/api/oauth2/token",
            data={"client_id": DISCORD_CLIENT_ID, "client_secret": DISCORD_CLIENT_SECRET,
                  "grant_type": "authorization_code", "code": code, "redirect_uri": DISCORD_REDIRECT_URI},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_response.status_code != 200:
            raise HTTPException(status_code=502, detail="Discord sign-in could not be completed.")
        access_token = token_response.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=502, detail="Discord did not return an access token.")
        user_response = await client.get("https://discord.com/api/users/@me",
                                         headers={"Authorization": f"Bearer {access_token}"})
    if user_response.status_code != 200:
        raise HTTPException(status_code=502, detail="Could not retrieve your Discord account.")
    profile = user_response.json()
    user_id = str(profile.get("id", ""))
    if not user_id or not is_allowed(user_id):
        request.session.clear()
        return RedirectResponse(APP_ORIGIN + "/?auth=denied", status_code=303)
    request.session.clear()
    request.session["discord_user"] = {
        "id": user_id, "username": profile.get("global_name") or profile.get("username") or "Admin"
    }
    return RedirectResponse(APP_ORIGIN + "/?auth=success", status_code=303)

@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    return {"authenticated": True, "id": str(user["id"]), "username": user["username"],
            "is_owner": str(user["id"]) == ADMIN_OWNER_ID}

@app.post("/api/logout")
def logout(request: Request):
    current_user(request)
    request.session.clear()
    return {"ok": True}

@app.get("/api/overview")
def overview(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        def count(sql: str) -> int:
            return int(con.execute(sql).fetchone()[0])
        return {
            "servers": count("SELECT COUNT(*) FROM bot_guilds"),
            "pending_reviews": count("SELECT COUNT(*) FROM reviews WHERE status='pending'"),
            "pending_verifications": count("SELECT COUNT(*) FROM verifications WHERE status='pending'"),
            "open_tickets": count("SELECT COUNT(*) FROM tickets WHERE status='open'"),
            "premium_servers": count("SELECT COUNT(*) FROM premium"),
            "unredeemed_codes": count("SELECT COUNT(*) FROM codes WHERE redeemed_at IS NULL"),
            "recent_deliveries": count("SELECT COUNT(*) FROM deliveries WHERE posted_at >= CAST(strftime('%s','now') AS INTEGER)-604800"),
        }

@app.get("/api/servers")
def servers(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        rows = con.execute("SELECT guild_id,name,owner_id,member_count,icon_url,joined_at FROM bot_guilds ORDER BY name COLLATE NOCASE LIMIT 250").fetchall()
    return {"servers": [dict(row) for row in rows]}

@app.get("/api/reviews")
def reviews(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        rows = con.execute("""SELECT id,guild_id,guild_name,user_id,user_name,content,flags,status,kind,created_at
                              FROM reviews WHERE status='pending' ORDER BY created_at ASC LIMIT 100""").fetchall()
    items = []
    for row in rows:
        item = dict(row)
        try:
            item["flags"] = json.loads(item.get("flags") or "[]")
        except (TypeError, ValueError):
            item["flags"] = []
        items.append(item)
    return {"reviews": items}

@app.get("/api/verifications")
def verifications(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        rows = con.execute("SELECT user_id,status,created_at FROM verifications WHERE status='pending' ORDER BY created_at ASC LIMIT 100").fetchall()
    return {"verifications": [dict(row) for row in rows]}

@app.get("/api/tickets")
def tickets(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        rows = con.execute("SELECT channel_id,guild_id,user_id,claimed_by,status,created_at FROM tickets WHERE status='open' ORDER BY created_at ASC LIMIT 100").fetchall()
    return {"tickets": [dict(row) for row in rows]}

@app.get("/api/premium")
def premium(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        plans = con.execute("SELECT guild_id,plan,expires_at,activated_by,updated_at FROM premium ORDER BY updated_at DESC LIMIT 200").fetchall()
        codes = con.execute("SELECT code,plan,created_at,redeemed_by,redeemed_guild_id,redeemed_at FROM codes ORDER BY created_at DESC LIMIT 100").fetchall()
    return {"premium": [dict(row) for row in plans], "codes": [dict(row) for row in codes]}

@app.get("/api/admins")
def list_admins(request: Request):
    owner_user(request)
    with closing(connect_db()) as con:
        rows = con.execute("SELECT discord_id,added_by,added_at FROM admin_allowlist ORDER BY added_at ASC").fetchall()
    return {"owner_id": ADMIN_OWNER_ID, "admins": [dict(row) for row in rows]}

class AdminInput(BaseModel):
    discord_id: str

def validate_discord_id(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[0-9]{17,20}", value):
        raise HTTPException(status_code=422, detail="Enter a valid Discord user ID.")
    if value == ADMIN_OWNER_ID:
        raise HTTPException(status_code=400, detail="The owner account is managed separately.")
    return value

@app.post("/api/admins")
def add_admin(payload: AdminInput, request: Request):
    owner = owner_user(request)
    discord_id = validate_discord_id(payload.discord_id)
    with closing(connect_db()) as con:
        try:
            con.execute("INSERT INTO admin_allowlist(discord_id,added_by) VALUES (?,?)", (discord_id, str(owner["id"])))
            con.execute("INSERT INTO admin_audit_logs(actor_id,action,target_id) VALUES (?,'admin_granted',?)", (str(owner["id"]), discord_id))
            con.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="That Discord ID is already approved.")
    return {"ok": True, "discord_id": discord_id}

@app.delete("/api/admins/{discord_id}")
def remove_admin(discord_id: str, request: Request):
    owner = owner_user(request)
    discord_id = validate_discord_id(discord_id)
    with closing(connect_db()) as con:
        cur = con.execute("DELETE FROM admin_allowlist WHERE discord_id=?", (discord_id,))
        if cur.rowcount:
            con.execute("INSERT INTO admin_audit_logs(actor_id,action,target_id) VALUES (?,'admin_revoked',?)", (str(owner["id"]), discord_id))
        con.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="That Discord ID is not on the allowlist.")
    return {"ok": True, "discord_id": discord_id}

@app.get("/api/audit")
def audit(request: Request):
    current_user(request)
    with closing(connect_db()) as con:
        rows = con.execute("SELECT id,actor_id,action,target_id,created_at FROM admin_audit_logs ORDER BY created_at DESC LIMIT 100").fetchall()
    return {"events": [dict(row) for row in rows]}
