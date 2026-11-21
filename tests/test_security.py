import os
import secrets
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app

# Must configure environment before importing the app.
_tmp = tempfile.TemporaryDirectory()
os.environ["DB_PATH"] = str(Path(_tmp.name) / "test.sqlite3")
os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)

client = TestClient(app)

def register_login(username):
    password = "very-secure-password-123"
    assert client.post("/register", json={"username": username, "password": password}).status_code == 201
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()

def auth(token):
    return {"Authorization": f"Bearer {token}"}

def test_login_refresh_logout_and_revocation():
    tokens = register_login("alice")
    assert client.get("/me", headers=auth(tokens["access_token"])).status_code == 200
    new = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert new.status_code == 200
    newer = new.json()
    assert newer["refresh_token"] != tokens["refresh_token"]
    assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.post("/logout", headers=auth(newer["access_token"])).status_code == 200
    assert client.get("/me", headers=auth(newer["access_token"])).status_code == 401
    assert client.post("/refresh", json={"refresh_token": newer["refresh_token"]}).status_code == 401

def test_ownership_isolation():
    alice = register_login("bob")
    other = register_login("charlie")
    created = client.post("/items", headers=auth(alice["access_token"]), json={"title": "private"})
    assert created.status_code == 201
    item_id = created.json()["id"]
    assert client.get(f"/items/{item_id}", headers=auth(alice["access_token"])).status_code == 200
    assert client.get(f"/items/{item_id}", headers=auth(other["access_token"])).status_code == 404
    assert client.get(f"/items/{item_id}").status_code == 401

def test_bad_password_and_invalid_token():
    assert client.post("/login", json={"username": "missing", "password": "wrong"}).status_code == 401
    assert client.get("/me", headers=auth("not.a.jwt")).status_code == 401
