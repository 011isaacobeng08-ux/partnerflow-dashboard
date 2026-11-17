import os
import re
import secrets
import sqlite3
from contextlib import closing
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

APP_ORIGIN = os.environ["APP_ORIGIN"].rstrip("/")
DISCORD_CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
DISCORD_CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
DISCORD_REDIRECT_URI = os.environ["DISCORD_REDIRECT_URI"]
SESSION_SECRET = os.environ["SESSION_SECRET"]
ADMIN_OWNER_ID = os.environ["ADMIN_OWNER_ID"]
ADMIN_DB_PATH = os.getenv("ADMIN_DB_PATH", "data/bot.db")

app = FastAPI(title="PartnerFlow Admin API")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
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

def db():
    # Creates only the admin allowlist table; it does not alter existing bot tables.
    folder = os.path.dirname(ADMIN_DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    con = sqlite3.connect(ADMIN_DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("""
        CREATE TABLE IF NOT EXISTS admin_allowlist (
            discord_id TEXT PRIMARY KEY,
            added_by TEXT NOT NULL,
            added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.commit()
    return con

def is_allowed(user_id: str) -> bool:
    if user_id == ADMIN_OWNER_ID:
        return True
    with closing(db()) as con:
        return con.execute(
            "SELECT 1 FROM admin_allowlist WHERE discord_id = ?", (user_id,)
        ).fetchone() is not None

def current_user(request: Request):
    user = request.session.get("discord_user")
    if not user or not user.get("id"):
        raise HTTPException(status_code=401, detail="Sign in with Discord first.")
    if not is_allowed(str(user["id"])):
        request.session.clear()
        raise HTTPException(status_code=403, detail="Your Discord ID is not on the admin allowlist.")
    return user

def require_owner(request: Request):
    user = current_user(request)
    if str(user["id"]) != ADMIN_OWNER_ID:
        raise HTTPException(status_code=403, detail="Only the designated owner can change admin access.")
    return user

@app.middleware("http")
async def protect_mutations(request: Request, call_next):
    if request.method in {"POST", "DELETE"} and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin", "").rstrip("/")
        if origin != APP_ORIGIN:
            return Response("Invalid request origin", status_code=403)
    return await call_next(request)

@app.get("/health")
def health():
    return {"ok": True, "service": "partnerflow-admin-api"}

@app.get("/auth/login")
def login(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }
    return RedirectResponse("https://discord.com/oauth2/authorize?" + urlencode(params))

@app.get("/auth/callback")
async def callback(request: Request, code: str = "", state: str = ""):
    expected = request.session.pop("oauth_state", None)
    if not code or not expected or not secrets.compare_digest(state, expected):
        raise HTTPException(status_code=400, detail="Invalid or expired Discord sign-in state.")
    async with httpx.AsyncClient(timeout=15) as client:
        token_response = await client.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_response.status_code != 200:
            raise HTTPException(status_code=502, detail="Discord sign-in could not be completed.")
        token = token_response.json().get("access_token")
        if not token:
            raise HTTPException(status_code=502, detail="Discord did not return an access token.")
        user_response = await client.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {token}"},
        )
    if user_response.status_code != 200:
        raise HTTPException(status_code=502, detail="Could not retrieve your Discord account.")
    user = user_response.json()
    user_id = str(user.get("id", ""))
    if not user_id or not is_allowed(user_id):
        request.session.clear()
        raise HTTPException(status_code=403, detail="This Discord account has not been approved for PartnerFlow Admin.")
    request.session.clear()
    request.session["discord_user"] = {
        "id": user_id,
        "username": user.get("global_name") or user.get("username", "Admin"),
    }
    return RedirectResponse(APP_ORIGIN + "/?auth=success", status_code=303)

@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    return {"authenticated": True, "id": str(user["id"]), "username": user["username"], "is_owner": str(user["id"]) == ADMIN_OWNER_ID}

@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

class AdminInput(BaseModel):
    discord_id: str

def validate_id(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"[0-9]{17,20}", value):
        raise HTTPException(status_code=422, detail="Enter a valid Discord user ID.")
    if value == ADMIN_OWNER_ID:
        raise HTTPException(status_code=400, detail="The owner account is managed separately.")
    return value

@app.get("/api/admins")
def list_admins(request: Request):
    require_owner(request)
    with closing(db()) as con:
        rows = con.execute(
            "SELECT discord_id, added_by, added_at FROM admin_allowlist ORDER BY added_at"
        ).fetchall()
    return {"admins": [dict(row) for row in rows]}

@app.post("/api/admins")
def add_admin(payload: AdminInput, request: Request):
    owner = require_owner(request)
    discord_id = validate_id(payload.discord_id)
    with closing(db()) as con:
        try:
            con.execute(
                "INSERT INTO admin_allowlist(discord_id, added_by) VALUES (?, ?)",
                (discord_id, str(owner["id"])),
            )
            con.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="That Discord ID is already approved.")
    return {"ok": True, "discord_id": discord_id}

@app.delete("/api/admins/{discord_id}")
def remove_admin(discord_id: str, request: Request):
    require_owner(request)
    discord_id = validate_id(discord_id)
    with closing(db()) as con:
        cur = con.execute("DELETE FROM admin_allowlist WHERE discord_id = ?", (discord_id,))
        con.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="That Discord ID is not on the allowlist.")
    return {"ok": True, "discord_id": discord_id}
