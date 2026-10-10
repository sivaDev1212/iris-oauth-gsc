from urllib.parse import parse_qs, urlparse

from app import crypto, tokens
from app.models import GoogleConnection, IndexingLog, User

from .conftest import FakeResp

ALL_SCOPES = (
    "openid email https://www.googleapis.com/auth/webmasters "
    "https://www.googleapis.com/auth/indexing"
)


def _login(client, monkeypatch, refresh_token="rt-123"):
    r = client.get("/auth/login")
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]

    def fake_post(url, **kw):
        assert kw["data"]["code_verifier"]  # PKCE verifier sent
        body = {"access_token": "at-1", "expires_in": 3600, "scope": ALL_SCOPES}
        if refresh_token:
            body["refresh_token"] = refresh_token
        return FakeResp(200, body)

    monkeypatch.setattr("app.auth.httpx.post", fake_post)
    monkeypatch.setattr(
        "app.auth.httpx.get", lambda *a, **k: FakeResp(200, {"sub": "g-1", "email": "a@b.com"})
    )
    return client.get(f"/auth/callback?code=abc&state={state}")


def test_crypto_roundtrip_and_rotation(monkeypatch):
    ct = crypto.encrypt("secret-refresh")
    assert "secret-refresh" not in ct
    assert crypto.decrypt(ct) == "secret-refresh"


def test_login_redirect_has_pkce_state_offline(client):
    r = client.get("/auth/login")
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"]
    assert q["access_type"] == ["offline"]
    assert q["prompt"] == ["consent"]
    assert q["state"][0] and q["code_challenge"][0]
    assert "https://www.googleapis.com/auth/webmasters" in q["scope"][0]


def test_callback_rejects_bad_state(client):
    client.get("/auth/login")
    r = client.get("/auth/callback?code=abc&state=WRONG")
    assert r.status_code == 400


def test_callback_stores_encrypted_token(client, db, monkeypatch):
    r = _login(client, monkeypatch)
    assert r.status_code == 302
    conn = db.query(GoogleConnection).one()
    assert conn.status == "active"
    assert conn.encrypted_refresh_token and "rt-123" not in conn.encrypted_refresh_token
    assert crypto.decrypt(conn.encrypted_refresh_token) == "rt-123"
    assert client.get("/auth/status").json()["connection"] == "active"


def test_callback_without_refresh_token_fails_for_new_user(client, monkeypatch):
    r = _login(client, monkeypatch, refresh_token=None)
    assert r.status_code == 400


def test_refresh_when_expired(client, db, monkeypatch):
    _login(client, monkeypatch)
    uid = db.query(User).one().id
    tokens._cache.clear()  # access token "expired"
    monkeypatch.setattr(
        "app.tokens.httpx.post",
        lambda *a, **k: FakeResp(200, {"access_token": "at-2", "expires_in": 3600}),
    )
    assert tokens.get_access_token(db, uid) == "at-2"
    assert tokens.get_access_token(db, uid) == "at-2"  # served from cache


def test_invalid_grant_marks_needs_reauth(client, db, monkeypatch):
    """Revoked in Google account / password-change policy / expiry -> invalid_grant."""
    _login(client, monkeypatch)
    uid = db.query(User).one().id
    tokens._cache.clear()
    monkeypatch.setattr(
        "app.tokens.httpx.post",
        lambda *a, **k: FakeResp(400, {"error": "invalid_grant", "error_description": "Token revoked"}),
    )
    r = client.get("/sites")
    assert r.status_code == 401
    assert r.json()["error"] == "reauth_required"
    db.expire_all()
    conn = db.query(GoogleConnection).filter_by(user_id=uid).one()
    assert conn.status == "needs_reauth"
    assert conn.encrypted_refresh_token is None  # dead token deleted
    assert client.get("/auth/status").json()["reauth_url"] == "/auth/login"


def test_network_failure_does_not_delete_token(client, db, monkeypatch):
    import httpx

    _login(client, monkeypatch)
    uid = db.query(User).one().id
    tokens._cache.clear()

    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr("app.tokens.httpx.post", boom)
    r = client.get("/sites")
    assert r.status_code == 503
    db.expire_all()
    assert db.query(GoogleConnection).filter_by(user_id=uid).one().status == "active"


def test_revoke_deletes_tokens(client, db, monkeypatch):
    _login(client, monkeypatch)
    calls = []
    monkeypatch.setattr("app.tokens.httpx.post", lambda url, **k: calls.append(url) or FakeResp(200))
    r = client.post("/auth/revoke")
    assert r.json() == {"revoked": True, "google_status": 200}
    assert calls == [tokens.REVOKE_URL]
    db.expire_all()
    conn = db.query(GoogleConnection).one()
    assert conn.status == "revoked" and conn.encrypted_refresh_token is None


def test_401_from_api_triggers_one_refresh_retry(client, db, monkeypatch):
    _login(client, monkeypatch)
    monkeypatch.setattr(
        "app.tokens.httpx.post",
        lambda *a, **k: FakeResp(200, {"access_token": "at-new", "expires_in": 3600}),
    )
    seen = []

    def fake_request(method, url, headers=None, **kw):
        seen.append(headers["Authorization"])
        if headers["Authorization"] == "Bearer at-1":
            return FakeResp(401, {"error": {"message": "expired"}})
        return FakeResp(200, {"siteEntry": []})

    monkeypatch.setattr("app.google_client.httpx.request", fake_request)
    r = client.get("/sites")
    assert r.status_code == 200
    assert seen == ["Bearer at-1", "Bearer at-new"]


def test_indexing_request_logs_and_returns(client, db, monkeypatch):
    _login(client, monkeypatch)
    monkeypatch.setattr(
        "app.google_client.httpx.request",
        lambda *a, **k: FakeResp(200, {"urlNotificationMetadata": {"url": "https://x.com/job/1"}}),
    )
    r = client.post("/indexing/request", json={"url": "https://x.com/job/1"})
    assert r.status_code == 200
    assert r.json()["quota_used_24h"] == 1
    assert db.query(IndexingLog).count() == 1


def test_indexing_rejects_bad_url(client, monkeypatch):
    _login(client, monkeypatch)
    assert client.post("/indexing/request", json={"url": "ftp://nope"}).status_code == 422


def test_indexing_403_explains_ownership(client, monkeypatch):
    _login(client, monkeypatch)
    monkeypatch.setattr(
        "app.google_client.httpx.request",
        lambda *a, **k: FakeResp(403, {"error": {"message": "Permission denied"}}),
    )
    r = client.post("/indexing/request", json={"url": "https://x.com/p"})
    assert r.status_code == 403 and "OWNER" in r.json()["detail"]


def test_requires_login(client):
    assert client.get("/sites").status_code == 401
