"""
Logs endpoints
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_logs():
    """Get security logs"""
    return {"message": "Logs endpoint - coming soon"}