"""
Data sources endpoints
"""

from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_data_sources():
    """Get data sources"""
    return {"message": "Data sources endpoint - coming soon"}