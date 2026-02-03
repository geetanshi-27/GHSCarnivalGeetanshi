from __future__ import annotations

import os
import sys
from pathlib import Path
import logging

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from apscheduler.schedulers.background import BackgroundScheduler

if __package__ is None or __package__ == "":
    backend_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(backend_root))

from app.api.main import api_router  # noqa: E402
from app.db.prisma import connect_prisma, disconnect_prisma  # noqa: E402

load_dotenv()

app = FastAPI(title="GHS Carnival API")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Keep-alive scheduler to prevent Render from spinning down
scheduler = BackgroundScheduler()

def keep_alive_task():
    """Simple task to keep the service active on Render"""
    logger.info("Keep-alive ping: Service is active")

# Schedule keep-alive task every 10 minutes
scheduler.add_job(keep_alive_task, 'interval', minutes=10, id='keep_alive')
scheduler.start()

# CORS configuration
cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins else ["http://localhost:5173"],  # Fallback to default
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],  # Expose cookie headers for better iOS compatibility
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response: Response = await call_next(request)
    # Basic hardening headers (safe defaults for an API)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    return response


@app.on_event("startup")
async def on_startup() -> None:
    await connect_prisma()


@app.on_event("shutdown")
async def on_shutdown() -> None:
    await disconnect_prisma()
    scheduler.shutdown()


@app.get("/")
@app.head("/")
async def root():
    """Root endpoint redirect"""
    return {"message": "GHS Carnival API", "docs": "/docs", "health": "/api/health"}


app.include_router(api_router, prefix="/api")
