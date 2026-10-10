import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware

from . import api, auth, models  # noqa: F401  (models import registers tables)
from .config import get_settings
from .db import Base, engine
from .tokens import GoogleAPIError, ReauthRequired

logging.basicConfig(level=logging.INFO)
# Never log request bodies/headers or token values anywhere in this app.
logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)  # use Alembic migrations in production
    yield


app = FastAPI(title="iris - Google Search Console OAuth utility", lifespan=lifespan)
_s = get_settings()
app.add_middleware(
    SessionMiddleware,
    secret_key=_s.session_secret,
    https_only=_s.https_only_cookies,
    same_site="lax",
    max_age=60 * 60 * 8,
)
app.include_router(auth.router)
app.include_router(api.router)


@app.exception_handler(ReauthRequired)
async def _reauth(_: Request, exc: ReauthRequired):
    return JSONResponse(
        status_code=401,
        content={"error": "reauth_required", "detail": str(exc), "reauth_url": "/auth/login"},
    )


@app.exception_handler(GoogleAPIError)
async def _google_error(_: Request, exc: GoogleAPIError):
    return JSONResponse(status_code=exc.status, content={"error": "google_api_error", "detail": exc.message})


@app.get("/")
def root():
    return {"service": "iris-oauth-gsc", "login": "/auth/login", "docs": "/docs"}


@app.get("/healthz")
def healthz():
    return {"ok": True}
