"""
Threat intelligence endpoints
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from app.database.session import get_db
from app.models import ThreatIntelligence, User
from app.schemas.threats import (
    ThreatCreate, ThreatUpdate, ThreatResponse, 
    ThreatSearch, ThreatStats, ThreatAnalysis
)
from app.api.v1.endpoints.auth import get_current_active_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/", response_model=ThreatResponse, status_code=status.HTTP_201_CREATED)
async def create_threat(
    threat_data: ThreatCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Create a new threat intelligence entry"""
    db_threat = ThreatIntelligence(
        source=threat_data.source,
        external_id=threat_data.external_id,
        title=threat_data.title,
        description=threat_data.description,
        threat_type=threat_data.threat_type,
        severity=threat_data.severity,
        cvss_score=threat_data.cvss_score,
        cvss_vector=threat_data.cvss_vector,
        ip_addresses=threat_data.ip_addresses,
        domains=threat_data.domains,
        urls=threat_data.urls,
        file_hashes=threat_data.file_hashes,
        tags=threat_data.tags,
        references=threat_data.references,
        raw_data=threat_data.raw_data
    )
    
    db.add(db_threat)
    await db.commit()
    await db.refresh(db_threat)
    
    logger.info(f"New threat created: {db_threat.id} by user {current_user.username}")
    return db_threat


@router.get("/", response_model=List[ThreatResponse])
async def get_threats(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    source: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    is_active: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get threat intelligence entries with filtering"""
    query = select(ThreatIntelligence)
    
    # Apply filters
    filters = []
    if source:
        filters.append(ThreatIntelligence.source == source)
    if threat_type:
        filters.append(ThreatIntelligence.threat_type == threat_type)
    if severity:
        filters.append(ThreatIntelligence.severity == severity)
    if is_active is not None:
        filters.append(ThreatIntelligence.is_active == is_active)
    
    if filters:
        query = query.where(and_(*filters))
    
    query = query.order_by(ThreatIntelligence.discovered_date.desc())
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    threats = result.scalars().all()
    
    return threats


@router.get("/search", response_model=List[ThreatResponse])
async def search_threats(
    search_params: ThreatSearch = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Advanced threat search with multiple criteria"""
    query = select(ThreatIntelligence)
    
    filters = []
    
    # Text search
    if search_params.query:
        search_filter = or_(
            ThreatIntelligence.title.ilike(f"%{search_params.query}%"),
            ThreatIntelligence.description.ilike(f"%{search_params.query}%"),
            ThreatIntelligence.external_id.ilike(f"%{search_params.query}%")
        )
        filters.append(search_filter)
    
    # Filters
    if search_params.source:
        filters.append(ThreatIntelligence.source == search_params.source)
    if search_params.threat_type:
        filters.append(ThreatIntelligence.threat_type == search_params.threat_type)
    if search_params.severity:
        filters.append(ThreatIntelligence.severity.in_(search_params.severity))
    if search_params.min_risk_score is not None:
        filters.append(ThreatIntelligence.risk_score >= search_params.min_risk_score)
    if search_params.max_risk_score is not None:
        filters.append(ThreatIntelligence.risk_score <= search_params.max_risk_score)
    if search_params.is_active is not None:
        filters.append(ThreatIntelligence.is_active == search_params.is_active)
    if search_params.is_verified is not None:
        filters.append(ThreatIntelligence.is_verified == search_params.is_verified)
    if search_params.date_from:
        filters.append(ThreatIntelligence.discovered_date >= search_params.date_from)
    if search_params.date_to:
        filters.append(ThreatIntelligence.discovered_date <= search_params.date_to)
    
    if filters:
        query = query.where(and_(*filters))
    
    # Pagination
    offset = (search_params.page - 1) * search_params.size
    query = query.order_by(ThreatIntelligence.risk_score.desc().nulls_last())
    query = query.offset(offset).limit(search_params.size)
    
    result = await db.execute(query)
    threats = result.scalars().all()
    
    return threats


@router.get("/stats", response_model=ThreatStats)
async def get_threat_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get threat intelligence statistics"""
    from datetime import datetime, timedelta
    
    # Total threats
    total_result = await db.execute(select(func.count(ThreatIntelligence.id)))
    total_threats = total_result.scalar()
    
    # Active threats
    active_result = await db.execute(
        select(func.count(ThreatIntelligence.id)).where(ThreatIntelligence.is_active == True)
    )
    active_threats = active_result.scalar()
    
    # Verified threats
    verified_result = await db.execute(
        select(func.count(ThreatIntelligence.id)).where(ThreatIntelligence.is_verified == True)
    )
    verified_threats = verified_result.scalar()
    
    # By severity
    severity_result = await db.execute(
        select(ThreatIntelligence.severity, func.count(ThreatIntelligence.id))
        .group_by(ThreatIntelligence.severity)
    )
    by_severity = dict(severity_result.all())
    
    # By type
    type_result = await db.execute(
        select(ThreatIntelligence.threat_type, func.count(ThreatIntelligence.id))
        .group_by(ThreatIntelligence.threat_type)
    )
    by_type = dict(type_result.all())
    
    # By source
    source_result = await db.execute(
        select(ThreatIntelligence.source, func.count(ThreatIntelligence.id))
        .group_by(ThreatIntelligence.source)
    )
    by_source = dict(source_result.all())
    
    # Recent threats (last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_result = await db.execute(
        select(func.count(ThreatIntelligence.id))
        .where(ThreatIntelligence.discovered_date >= yesterday)
    )
    recent_threats = recent_result.scalar()
    
    return ThreatStats(
        total_threats=total_threats,
        active_threats=active_threats,
        verified_threats=verified_threats,
        by_severity=by_severity,
        by_type=by_type,
        by_source=by_source,
        recent_threats=recent_threats
    )


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific threat by ID"""
    result = await db.execute(
        select(ThreatIntelligence).where(ThreatIntelligence.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    return threat


@router.put("/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    threat_id: int,
    threat_data: ThreatUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update a threat intelligence entry"""
    result = await db.execute(
        select(ThreatIntelligence).where(ThreatIntelligence.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    # Update fields
    update_data = threat_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(threat, field, value)
    
    await db.commit()
    await db.refresh(threat)
    
    logger.info(f"Threat updated: {threat_id} by user {current_user.username}")
    return threat


@router.delete("/{threat_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_threat(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Delete a threat intelligence entry"""
    if current_user.role not in ["admin", "superuser"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    result = await db.execute(
        select(ThreatIntelligence).where(ThreatIntelligence.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    await db.delete(threat)
    await db.commit()
    
    logger.info(f"Threat deleted: {threat_id} by user {current_user.username}")


@router.post("/{threat_id}/analyze", response_model=ThreatAnalysis)
async def analyze_threat(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Perform AI analysis on a threat"""
    result = await db.execute(
        select(ThreatIntelligence).where(ThreatIntelligence.id == threat_id)
    )
    threat = result.scalar_one_or_none()
    
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found"
        )
    
    # This would integrate with ML/AI analysis service
    # For now, return mock analysis
    analysis = ThreatAnalysis(
        threat_id=threat_id,
        risk_assessment="High priority threat requiring immediate attention",
        mitigation_recommendations=[
            "Apply latest security patches",
            "Monitor network traffic for IOCs",
            "Update threat detection rules",
            "Review access controls"
        ],
        related_threats=[],
        timeline=[
            {
                "date": threat.discovered_date.isoformat(),
                "event": "Threat discovered",
                "source": threat.source
            }
        ],
        confidence_level=threat.confidence_score or 0.8
    )
    
    logger.info(f"Threat analysis requested: {threat_id} by user {current_user.username}")
    return analysis