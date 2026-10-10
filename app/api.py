"""Authenticated API routes: Search Console reads + on-demand indexing request."""
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import google_client, tokens
from .auth import current_user
from .config import INDEXING_SCOPE, get_settings
from .db import get_db
from .models import IndexingLog, User, utcnow

router = APIRouter(tags=["google"])


def _require_scope(db: Session, user: User, scope: str) -> None:
    conn = tokens.get_connection(db, user.id)
    if conn is None or conn.status != "active":
        raise tokens.ReauthRequired("No active Google connection; please reconnect.")
    if scope not in conn.scopes.split():
        raise HTTPException(
            403,
            f"Scope not granted: {scope}. Re-run /auth/login and tick all permission boxes.",
        )


class IndexRequest(BaseModel):
    url: str
    type: Literal["URL_UPDATED", "URL_DELETED"] = "URL_UPDATED"

    @field_validator("url")
    @classmethod
    def _http_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class InspectRequest(BaseModel):
    url: str
    site_url: str  # exactly as listed in Search Console, e.g. https://example.com/ or sc-domain:example.com


class SitemapRequest(BaseModel):
    site_url: str
    sitemap_url: str


@router.get("/sites")
def sites(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return google_client.list_sites(db, user.id)


@router.post("/inspection")
def inspection(body: InspectRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Read-only index status (URL Inspection API)."""
    return google_client.inspect_url(db, user.id, body.url, body.site_url)


@router.post("/sitemaps")
def sitemaps(body: SitemapRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Sitemap submission is the officially supported general-purpose 'please crawl' signal."""
    return google_client.submit_sitemap(db, user.id, body.site_url, body.sitemap_url)


@router.post("/indexing/request")
def request_indexing(
    body: IndexRequest, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    """Notify Google that a URL changed via the Indexing API.

    LIMITATION: Search Console's own "Request indexing" button is not exposed by any API.
    The Indexing API officially supports only JobPosting and BroadcastEvent (livestream)
    pages, and the caller must be a verified owner of the property.
    """
    _require_scope(db, user, INDEXING_SCOPE)

    quota = get_settings().indexing_daily_quota
    since = utcnow() - timedelta(hours=24)
    used = (
        db.query(func.count(IndexingLog.id))
        .filter(IndexingLog.created_at >= since, IndexingLog.http_status == 200)
        .scalar()
    )
    if used >= quota:
        raise HTTPException(429, f"Daily Indexing API quota ({quota}) reached for this project.")

    try:
        status, data = google_client.publish_url_notification(db, user.id, body.url, body.type)
    except tokens.GoogleAPIError as exc:
        db.add(
            IndexingLog(user_id=user.id, url=body.url, notification_type=body.type, http_status=exc.status)
        )
        db.commit()
        if exc.status == 403:
            raise HTTPException(
                403,
                "Google refused the request: you must be a verified OWNER of this site in "
                "Search Console and the Indexing API must be enabled in the Cloud project.",
            ) from exc
        raise

    db.add(IndexingLog(user_id=user.id, url=body.url, notification_type=body.type, http_status=status))
    db.commit()
    return {
        "submitted": True,
        "note": "Indexing API only officially supports JobPosting / BroadcastEvent pages. "
        "This does not guarantee indexing.",
        "quota_used_24h": used + 1,
        "quota_limit": quota,
        "google": data,
    }


@router.get("/indexing/status")
def indexing_status(url: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    _require_scope(db, user, INDEXING_SCOPE)
    return google_client.indexing_metadata(db, user.id, url)
