#!/usr/bin/env python
"""Fortress XDR AI - FastAPI Backend Entry Point"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from datetime import datetime
import os

from app.api import alerts, incidents, hunts, ai, reports, health
from app.core.config import settings
from app.core.security import get_current_user
from app.core.database import engine, Base

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Fortress XDR AI",
    description="AI-Powered Security Operations Center Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Create database tables
Base.metadata.create_all(bind=engine)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(alerts.router, prefix="/api/v1", tags=["Alerts"])
app.include_router(incidents.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(hunts.router, prefix="/api/v1", tags=["Threat Hunting"])
app.include_router(ai.router, prefix="/api/v1", tags=["AI Analysis"])
app.include_router(reports.router, prefix="/api/v1", tags=["Reporting"])

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Fortress XDR AI - Enterprise Security Operations Center",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "fortress-xdr-ai-backend"
    }

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("BACKEND_PORT", 8000)),
        reload=True
    )
