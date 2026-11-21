"""Educational FastAPI security lab: JWT + rotating opaque refresh tokens.

Run: export JWT_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(48))')
     uvicorn app.main:app --reload
"""
import hashlib
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jwt import InvalidTokenError
from pydantic import BaseModel, Field
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

DB_PATH = os.environ.get("DB_PATH", "security_lab.sqlite3")
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    raise RuntimeError("Set JWT_SECRET to a random secret of at least 32 characters")
ISSUER = "fastapi-security-lab"
AUDIENCE = "security-lab-api"
ACCESS_SECONDS = 15 * 60
REFRESH_SECONDS = 7 * 24 * 60 * 60
hashing = PasswordHasher()
app = FastAPI(title="FastAPI Security Lab")
oauth2 = OAuth2PasswordBearer(tokenUrl="/login", scopes={"items:read": "Read own items", "items:write": "Create own items"})

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout=10000")
    try:
        yield con
    finally:
        con.close()

def initialize():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS sessions (
          id TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
          refresh_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
          revoked INTEGER NOT NULL DEFAULT 0,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS items (
          id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
          title TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id)
        );
        """)

initialize()

class Credentials(BaseModel):
    username: str
    password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class Tokens(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class ItemInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)

class ItemOutput(BaseModel):
    id: int
    title: str
    owner_id: int

class Principal(BaseModel):
    id: int
    session_id: str
    scopes: list[str]

def fail_auth():
    raise HTTPException(status_code=401, detail="Invalid or expired credentials", headers={"WWW-Authenticate": "Bearer"})

def verify_password(password: str, stored: str) -> bool:
    try:
        return hashing.verify(stored, password)
    except (VerifyMismatchError, VerificationError):
        return False

def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def access_token(user_id: int, sid: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "sid": sid,
                       "scope": "items:read items:write", "iss": ISSUER,
                       "aud": AUDIENCE, "iat": now,
                       "exp": now + timedelta(seconds=ACCESS_SECONDS)},
                      JWT_SECRET, algorithm="HS256")

def create_session(user_id: int) -> Tokens:
    sid = secrets.token_urlsafe(24)
    refresh = secrets.token_urlsafe(48)
    with db() as con:
        con.execute("INSERT INTO sessions(id,user_id,refresh_hash,expires_at) VALUES(?,?,?,?)",
                    (sid, user_id, digest(refresh), int(time.time()) + REFRESH_SECONDS))
    return Tokens(access_token=access_token(user_id, sid), refresh_token=refresh)

@app.post("/register", status_code=201)
def register(credentials: Credentials):
    if len(credentials.password) < 12 or len(credentials.username) < 3:
        raise HTTPException(422, "Username must have 3+ characters and password 12+")
    with db() as con:
        try:
            con.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                        (credentials.username, hashing.hash(credentials.password)))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username already exists") from None
    return {"message": "registered"}

@app.post("/login", response_model=Tokens)
def login(credentials: Credentials):
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE username=?", (credentials.username,)).fetchone()
    if not user or not verify_password(credentials.password, user["password_hash"]) or not user["active"]:
        fail_auth()
    return create_session(user["id"])

@app.post("/refresh", response_model=Tokens)
def refresh(request: RefreshRequest):
    old_hash = digest(request.refresh_token)
    new_refresh = secrets.token_urlsafe(48)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        session = con.execute("SELECT * FROM sessions WHERE refresh_hash=?", (old_hash,)).fetchone()
        if not session or session["revoked"] or session["expires_at"] <= int(time.time()):
            con.execute("ROLLBACK")
            fail_auth()
        user = con.execute("SELECT active FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or not user["active"]:
            con.execute("ROLLBACK")
            fail_auth()
        con.execute("UPDATE sessions SET refresh_hash=? WHERE id=?", (digest(new_refresh), session["id"]))
        con.execute("COMMIT")
    return Tokens(access_token=access_token(session["user_id"], session["id"]), refresh_token=new_refresh)

async def current_user(security_scopes: SecurityScopes, token: Annotated[str, Depends(oauth2)]) -> Principal:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"],
                             issuer=ISSUER, audience=AUDIENCE,
                             options={"require": ["sub", "sid", "exp", "iat", "iss", "aud"]})
        uid = int(payload["sub"])
        sid = payload["sid"]
        scopes = payload.get("scope", "").split()
        if not isinstance(sid, str):
            fail_auth()
    except (InvalidTokenError, ValueError, TypeError, KeyError):
        fail_auth()
    with db() as con:
        row = con.execute("""SELECT u.active, s.revoked, s.expires_at
                             FROM sessions s JOIN users u ON u.id=s.user_id
                             WHERE s.id=? AND s.user_id=?""", (sid, uid)).fetchone()
    if not row or not row["active"] or row["revoked"] or row["expires_at"] <= int(time.time()):
        fail_auth()
    if any(scope not in scopes for scope in security_scopes.scopes):
        raise HTTPException(403, "Insufficient scope")
    return Principal(id=uid, session_id=sid, scopes=scopes)

@app.get("/me")
def me(user: Annotated[Principal, Depends(current_user)]):
    return {"user_id": user.id, "session_id": user.session_id}

@app.post("/logout")
def logout(user: Annotated[Principal, Depends(current_user)]):
    with db() as con:
        con.execute("UPDATE sessions SET revoked=1 WHERE id=? AND user_id=?", (user.session_id, user.id))
    return {"message": "logged out"}

@app.post("/items", response_model=ItemOutput, status_code=201)
def add_item(item: ItemInput, user: Annotated[Principal, Security(current_user, scopes=["items:write"])]):
    with db() as con:
        cur = con.execute("INSERT INTO items(owner_id,title) VALUES(?,?)", (user.id, item.title))
        return ItemOutput(id=cur.lastrowid, title=item.title, owner_id=user.id)

@app.get("/items/{item_id}", response_model=ItemOutput)
def get_item(item_id: int, user: Annotated[Principal, Security(current_user, scopes=["items:read"])]):
    with db() as con:
        row = con.execute("SELECT * FROM items WHERE id=? AND owner_id=?", (item_id, user.id)).fetchone()
    if row is None:
        raise HTTPException(404, "Item not found")
    return ItemOutput(**dict(row))

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}
