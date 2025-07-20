"""
Alerts endpoints
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_alerts():
    """Get security alerts"""
    return {"message": "Alerts endpoint - coming soon"}