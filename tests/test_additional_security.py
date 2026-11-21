import time
from uuid import uuid4

import jwt
from fastapi.testclient import TestClient

from app import main


def user_tokens(client):
    username = f"user_{uuid4().hex}"
    password = "correct-horse-battery-staple"
    assert client.post("/register", json={"username": username, "password": password}).status_code == 201
    result = client.post("/login", json={"username": username, "password": password})
    assert result.status_code == 200
    return result.json(), username, password


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_registration_duplicate_and_weak_password():
    with TestClient(main.app) as client:
        tokens, username, password = user_tokens(client)
        assert tokens["token_type"] == "bearer"
        assert client.post("/register", json={"username": username, "password": password}).status_code == 409
        assert client.post("/register", json={"username": "abc", "password": "short"}).status_code == 422


def test_missing_and_tampered_access_token():
    with TestClient(main.app) as client:
        tokens, _, _ = user_tokens(client)
        assert client.get("/me").status_code == 401
        token = tokens["access_token"]
        parts = token.split(".")
        parts[1] = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
        assert client.get("/me", headers=headers(".".join(parts))).status_code == 401


def test_expired_and_wrong_audience_token():
    with TestClient(main.app) as client:
        tokens, _, _ = user_tokens(client)
        claims = jwt.decode(tokens["access_token"], main.JWT_SECRET, algorithms=["HS256"], audience=main.AUDIENCE, issuer=main.ISSUER)
        expired = dict(claims, exp=int(time.time()) - 60)
        wrong_audience = dict(claims, aud="other-api")
        for payload in (expired, wrong_audience):
            token = jwt.encode(payload, main.JWT_SECRET, algorithm="HS256")
            assert client.get("/me", headers=headers(token)).status_code == 401


def test_scope_denial_and_item_validation():
    with TestClient(main.app) as client:
        tokens, _, _ = user_tokens(client)
        claims = jwt.decode(tokens["access_token"], main.JWT_SECRET, algorithms=["HS256"], audience=main.AUDIENCE, issuer=main.ISSUER)
        read_only = jwt.encode(dict(claims, scope="items:read"), main.JWT_SECRET, algorithm="HS256")
        assert client.post("/items", json={"title": "private"}, headers=headers(read_only)).status_code == 403
        assert client.post("/items", json={"title": ""}, headers=headers(tokens["access_token"])).status_code == 422
        assert client.post("/items", json={"title": "x" * 201}, headers=headers(tokens["access_token"])).status_code == 422


def test_refresh_rotation_and_revocation():
    with TestClient(main.app) as client:
        tokens, _, _ = user_tokens(client)
        rotated = client.post("/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert rotated.status_code == 200
        newer = rotated.json()
        assert newer["refresh_token"] != tokens["refresh_token"]
        assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
        assert client.post("/logout", headers=headers(newer["access_token"])).status_code == 200
        assert client.get("/me", headers=headers(tokens["access_token"])).status_code == 401
        assert client.post("/refresh", json={"refresh_token": newer["refresh_token"]}).status_code == 401
