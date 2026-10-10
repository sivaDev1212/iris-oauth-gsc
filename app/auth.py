"""OAuth 2.0 authorization-code flow with PKCE + state, offline access."""
import base64
import hashlib
import logging
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from . import tokens
from .config import SCOPES, get_settings
from .db import get_db
from .models import User

log = logging.getLogger("iris.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    uid = request.session.get("user_id")
    user = db.get(User, uid) if uid else None
    if user is None:
        raise HTTPException(401, "Not logged in. Visit /auth/login")
    return user


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43-128
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


@router.get("/login")
def login(request: Request):
    s = get_settings()
    state = secrets.token_urlsafe(32)
    verifier, challenge = _pkce_pair()
    request.session["oauth_state"] = state
    request.session["pkce_verifier"] = verifier

    params = {
        "response_type": "code",
        "client_id": s.google_client_id,
        "redirect_uri": s.redirect_uri,
        "scope": " ".join(SCOPES),
        "state": state,  # CSRF protection
        "code_challenge": challenge,  # PKCE
        "code_challenge_method": "S256",
        "access_type": "offline",  # ask for a refresh token
        "prompt": "consent",  # force consent so Google re-issues the refresh token
        "include_granted_scopes": "true",
    }
    return RedirectResponse(f"{AUTH_URL}?{urlencode(params)}", status_code=302)


@router.get("/callback")
def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        raise HTTPException(400, f"Google returned an error: {error}")
    expected_state = request.session.pop("oauth_state", None)
    verifier = request.session.pop("pkce_verifier", None)
    if not code or not state or not expected_state or not secrets.compare_digest(state, expected_state):
        raise HTTPException(400, "Invalid or missing OAuth state (possible CSRF)")
    if not verifier:
        raise HTTPException(400, "Missing PKCE verifier; restart login")

    s = get_settings()
    try:
        tr = httpx.post(
            tokens.TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": s.redirect_uri,
                "client_id": s.google_client_id,
                "client_secret": s.google_client_secret,
                "code_verifier": verifier,
            },
            timeout=15,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(502, "Could not reach Google token endpoint") from exc
    body = tokens._json(tr)
    if tr.status_code != 200 or "access_token" not in body:
        log.warning("code exchange failed: %s", body.get("error"))
        raise HTTPException(400, f"Token exchange failed: {body.get('error', tr.status_code)}")

    access_token = body["access_token"]
    try:
        ui = httpx.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    except httpx.HTTPError as exc:
        raise HTTPException(502, "Could not fetch Google profile") from exc
    info = tokens._json(ui)
    if "sub" not in info:
        raise HTTPException(400, "Google profile did not include a user id")

    user = db.query(User).filter_by(google_sub=info["sub"]).first()
    if user is None:
        user = User(google_sub=info["sub"], email=info.get("email", ""))
        db.add(user)
        db.commit()

    granted = body.get("scope", "")
    refresh_token = body.get("refresh_token")
    if refresh_token:
        tokens.save_refresh_token(db, user.id, refresh_token, granted)
    else:
        existing = tokens.get_connection(db, user.id)
        if not (existing and existing.status == "active" and existing.encrypted_refresh_token):
            raise HTTPException(
                400,
                "Google did not return a refresh token. Remove this app at "
                "https://myaccount.google.com/permissions and connect again.",
            )

    tokens.cache_access_token(user.id, access_token, body.get("expires_in", 3600))
    request.session["user_id"] = user.id  # session fixation: fresh value set after login
    return RedirectResponse("/auth/status", status_code=302)


@router.get("/status")
def status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    conn = tokens.get_connection(db, user.id)
    return {
        "email": user.email,
        "connection": conn.status if conn else "none",
        "scopes": conn.scopes.split() if conn else [],
        "last_refreshed_at": conn.last_refreshed_at if conn else None,
        "last_error": conn.last_error if conn else None,
        "reauth_url": "/auth/login" if (not conn or conn.status != "active") else None,
    }


@router.post("/revoke")
def revoke(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return tokens.revoke(db, user.id)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return JSONResponse({"logged_out": True})
