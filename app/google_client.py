"""Thin wrappers over Google APIs. Every call goes through _call() so refresh/401-retry is uniform."""
from urllib.parse import quote

import httpx
from sqlalchemy.orm import Session

from . import tokens
from .tokens import GoogleAPIError

SC_BASE = "https://www.googleapis.com/webmasters/v3"
INSPECT_URL = "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect"
INDEXING_PUBLISH_URL = "https://indexing.googleapis.com/v3/urlNotifications:publish"
INDEXING_METADATA_URL = "https://indexing.googleapis.com/v3/urlNotifications/metadata"


def _call(db: Session, user_id: int, method: str, url: str, **kwargs) -> tuple[int, dict]:
    token = tokens.get_access_token(db, user_id)
    for attempt in (0, 1):
        try:
            resp = httpx.request(
                method, url, headers={"Authorization": f"Bearer {token}"}, timeout=30, **kwargs
            )
        except httpx.HTTPError as exc:
            raise GoogleAPIError(503, f"Google API unreachable: {exc}") from exc
        if resp.status_code == 401 and attempt == 0:
            # Access token rejected early (e.g. revoked) -> force one refresh and retry once.
            token = tokens.get_access_token(db, user_id, stale=token)
            continue
        break

    data = tokens._json(resp)
    if resp.status_code >= 400:
        msg = (data.get("error") or {}).get("message") if isinstance(data.get("error"), dict) else None
        raise GoogleAPIError(resp.status_code, msg or f"Google API error {resp.status_code}")
    return resp.status_code, data


# ---- Search Console ----
def list_sites(db: Session, user_id: int) -> dict:
    return _call(db, user_id, "GET", f"{SC_BASE}/sites")[1]


def inspect_url(db: Session, user_id: int, inspection_url: str, site_url: str) -> dict:
    """URL Inspection API: READ-ONLY index status. It cannot request indexing."""
    body = {"inspectionUrl": inspection_url, "siteUrl": site_url}
    return _call(db, user_id, "POST", INSPECT_URL, json=body)[1]


def submit_sitemap(db: Session, user_id: int, site_url: str, sitemap_url: str) -> dict:
    url = f"{SC_BASE}/sites/{quote(site_url, safe='')}/sitemaps/{quote(sitemap_url, safe='')}"
    status, data = _call(db, user_id, "PUT", url)
    return {"submitted": True, "http_status": status, **data}


# ---- Indexing API ----
def publish_url_notification(
    db: Session, user_id: int, url: str, notification_type: str = "URL_UPDATED"
) -> tuple[int, dict]:
    return _call(
        db, user_id, "POST", INDEXING_PUBLISH_URL, json={"url": url, "type": notification_type}
    )


def indexing_metadata(db: Session, user_id: int, url: str) -> dict:
    return _call(db, user_id, "GET", INDEXING_METADATA_URL, params={"url": url})[1]
