"""
Reports endpoints
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_reports():
    """Get threat reports"""
    return {"message": "Reports endpoint - coming soon"}