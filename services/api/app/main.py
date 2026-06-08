from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import health, ingest, log_analyzer, ngfw, playbooks, stream
from app.core.config import settings

app = FastAPI(
    title="Nepal Fortress ONE API",
    version="0.1.0",
    description="Real-time cybersecurity telemetry, NGFW, SIEM, and SOAR APIs.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+):(3000|5173)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(ingest.router, prefix="/api/v1")
app.include_router(ngfw.router, prefix="/api/v1")
app.include_router(playbooks.router, prefix="/api/v1")
app.include_router(stream.router, prefix="/api/v1")
app.include_router(log_analyzer.router)
