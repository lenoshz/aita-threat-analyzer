"""
Users endpoints
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_users():
    """Get users"""
    return {"message": "Users endpoint - coming soon"}