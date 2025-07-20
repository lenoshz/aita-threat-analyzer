"""
Threat intelligence schemas
"""

from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime


class ThreatBase(BaseModel):
    """Base threat schema"""
    source: str
    external_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None


class ThreatCreate(ThreatBase):
    """Threat creation schema"""
    ip_addresses: Optional[List[str]] = []
    domains: Optional[List[str]] = []
    urls: Optional[List[str]] = []
    file_hashes: Optional[Dict[str, str]] = {}
    tags: Optional[List[str]] = []
    references: Optional[List[str]] = []
    raw_data: Optional[Dict[str, Any]] = {}
    
    @validator('severity')
    def validate_severity(cls, v):
        if v and v not in ['critical', 'high', 'medium', 'low']:
            raise ValueError('Severity must be one of: critical, high, medium, low')
        return v
    
    @validator('cvss_score')
    def validate_cvss_score(cls, v):
        if v is not None and (v < 0.0 or v > 10.0):
            raise ValueError('CVSS score must be between 0.0 and 10.0')
        return v


class ThreatUpdate(BaseModel):
    """Threat update schema"""
    title: Optional[str] = None
    description: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    ip_addresses: Optional[List[str]] = None
    domains: Optional[List[str]] = None
    urls: Optional[List[str]] = None
    file_hashes: Optional[Dict[str, str]] = None
    tags: Optional[List[str]] = None
    references: Optional[List[str]] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None


class ThreatResponse(ThreatBase):
    """Threat response schema"""
    id: int
    ip_addresses: List[str]
    domains: List[str]
    urls: List[str]
    file_hashes: Dict[str, str]
    risk_score: Optional[float] = None
    confidence_score: Optional[float] = None
    predicted_category: Optional[str] = None
    summary: Optional[str] = None
    tags: List[str]
    references: List[str]
    published_date: Optional[datetime] = None
    discovered_date: datetime
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_active: bool
    is_verified: bool
    
    class Config:
        from_attributes = True


class ThreatSearch(BaseModel):
    """Threat search schema"""
    query: Optional[str] = None
    source: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[List[str]] = None
    min_risk_score: Optional[float] = None
    max_risk_score: Optional[float] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    tags: Optional[List[str]] = None
    page: int = 1
    size: int = 20
    
    @validator('page')
    def validate_page(cls, v):
        if v < 1:
            raise ValueError('Page must be >= 1')
        return v
    
    @validator('size')
    def validate_size(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Size must be between 1 and 100')
        return v


class ThreatStats(BaseModel):
    """Threat statistics schema"""
    total_threats: int
    active_threats: int
    verified_threats: int
    by_severity: Dict[str, int]
    by_type: Dict[str, int]
    by_source: Dict[str, int]
    recent_threats: int  # Last 24 hours
    
    
class ThreatAnalysis(BaseModel):
    """Threat analysis response schema"""
    threat_id: int
    risk_assessment: str
    mitigation_recommendations: List[str]
    related_threats: List[int]
    timeline: List[Dict[str, Any]]
    confidence_level: float