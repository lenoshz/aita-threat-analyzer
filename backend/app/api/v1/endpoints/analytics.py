"""
Analytics endpoints
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_analytics():
    """Get analytics data"""
    return {"message": "Analytics endpoint - coming soon"}