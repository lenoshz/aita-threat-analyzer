"""
API v1 router
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    auth,
    threats,
    reports,
    alerts,
    logs,
    analytics,
    users,
    data_sources
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(threats.router, prefix="/threats", tags=["Threat Intelligence"])
api_router.include_router(reports.router, prefix="/reports", tags=["Threat Reports"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Security Alerts"])
api_router.include_router(logs.router, prefix="/logs", tags=["Log Analysis"])
api_router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
api_router.include_router(users.router, prefix="/users", tags=["User Management"])
api_router.include_router(data_sources.router, prefix="/data-sources", tags=["Data Sources"])