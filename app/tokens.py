"""Token lifecycle: store (encrypted), cache access tokens, refresh, mark dead, revoke."""
import logging
import threading
import time

import httpx
from sqlalchemy.orm import Session

from . import crypto
from .config import get_settings
from .models import GoogleConnection, utcnow

log = logging.getLogger("iris.tokens")

TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
EXPIRY_SKEW_SECONDS = 60  # refresh a little early to avoid edge-of-expiry failures


class ReauthRequired(Exception):
    """User must go through /auth/login again (token revoked/expired/never granted)."""


class GoogleAPIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# ---- access-token cache (in memory; swap for Redis when running >1 worker) ----
_cache: dict[int, tuple[str, float]] = {}
_locks: dict[int, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_for(user_id: int) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(user_id, threading.Lock())


def cache_access_token(user_id: int, token: str, expires_in: int) -> None:
    _cache[user_id] = (token, time.time() + int(expires_in))


def clear_cache(user_id: int) -> None:
    _cache.pop(user_id, None)


def _cached(user_id: int) -> str | None:
    entry = _cache.get(user_id)
    if entry and entry[1] - EXPIRY_SKEW_SECONDS > time.time():
        return entry[0]
    return None


# ---- persistence helpers ----
def get_connection(db: Session, user_id: int) -> GoogleConnection | None:
    return db.query(GoogleConnection).filter_by(user_id=user_id).first()


def save_refresh_token(
    db: Session, user_id: int, refresh_token: str, scopes: str
) -> GoogleConnection:
    conn = get_connection(db, user_id)
    if conn is None:
        conn = GoogleConnection(user_id=user_id)
        db.add(conn)
    conn.encrypted_refresh_token = crypto.encrypt(refresh_token)
    conn.scopes = scopes
    conn.status = "active"
    conn.last_error = None
    db.commit()
    return conn


def mark_needs_reauth(db: Session, conn: GoogleConnection, reason: str) -> None:
    """Refresh token is dead: delete it, flag the connection, drop cached access token."""
    conn.encrypted_refresh_token = None
    conn.status = "needs_reauth"
    conn.last_error = reason[:500]
    db.commit()
    clear_cache(conn.user_id)
    log.warning("connection user_id=%s marked needs_reauth: %s", conn.user_id, reason)


# ---- refresh ----
def get_access_token(db: Session, user_id: int, stale: str | None = None) -> str:
    """Return a valid access token, refreshing transparently if needed.

    `stale` is the token that just got a 401 from Google; if another request has already
    refreshed in the meantime we reuse that fresh token instead of refreshing again.
    """
    if stale is None:
        tok = _cached(user_id)
        if tok:
            return tok

    with _lock_for(user_id):  # one refresh per user at a time
        tok = _cached(user_id)
        if tok and tok != stale:
            return tok

        conn = get_connection(db, user_id)
        if conn is not None:
            db.refresh(conn)
        if conn is None or conn.status != "active" or not conn.encrypted_refresh_token:
            raise ReauthRequired("No active Google connection; please reconnect.")

        s = get_settings()
        refresh_token = crypto.decrypt(conn.encrypted_refresh_token)
        try:
            resp = httpx.post(
                TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": s.google_client_id,
                    "client_secret": s.google_client_secret,
                },
                timeout=15,
            )
        except httpx.HTTPError as exc:  # network trouble is NOT a reason to delete the token
            raise GoogleAPIError(503, f"Could not reach Google token endpoint: {exc}") from exc

        body = _json(resp)
        if resp.status_code == 200 and "access_token" in body:
            cache_access_token(user_id, body["access_token"], body.get("expires_in", 3600))
            conn.last_refreshed_at = utcnow()
            if body.get("refresh_token"):  # Google occasionally rotates it
                conn.encrypted_refresh_token = crypto.encrypt(body["refresh_token"])
            db.commit()
            return body["access_token"]

        error = body.get("error", "")
        if error == "invalid_grant":
            # Revoked by user, password-change policy on sensitive scopes, 6mo idle,
            # >100 tokens for this client, Testing-mode 7-day expiry, admin removal...
            mark_needs_reauth(db, conn, f"invalid_grant: {body.get('error_description', '')}")
            raise ReauthRequired("Google access was revoked or expired; please reconnect.")
        if error in ("invalid_client", "unauthorized_client"):
            raise GoogleAPIError(500, f"OAuth client misconfigured: {error}")
        raise GoogleAPIError(
            502 if resp.status_code >= 500 else 400,
            f"Token refresh failed: {error or resp.status_code}",
        )


# ---- revoke ----
def revoke(db: Session, user_id: int) -> dict:
    """Revoke at Google, then delete local tokens regardless of Google's answer."""
    conn = get_connection(db, user_id)
    google_status: int | None = None
    if conn is not None and conn.encrypted_refresh_token:
        try:
            token = crypto.decrypt(conn.encrypted_refresh_token)
            r = httpx.post(
                REVOKE_URL,
                data={"token": token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            google_status = r.status_code  # 200 ok; 400 = already invalid, still fine for us
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("revoke call failed for user_id=%s: %s", user_id, type(exc).__name__)
    if conn is not None:
        conn.encrypted_refresh_token = None
        conn.status = "revoked"
        conn.last_error = None
        db.commit()
    clear_cache(user_id)
    return {"revoked": True, "google_status": google_status}


def _json(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}
