"""
Rate limiting middleware
"""

import time
import redis
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Redis client for rate limiting
redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    password=settings.REDIS_PASSWORD,
    db=settings.REDIS_DB + 1,  # Use different DB for rate limiting
    decode_responses=True
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis"""
    
    def __init__(self, app, calls_per_minute: int = None):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute or settings.RATE_LIMIT_PER_MINUTE
        self.window_size = 60  # 1 minute in seconds
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks and internal endpoints
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)
        
        # Get client identifier (IP address)
        client_ip = self.get_client_ip(request)
        
        # Check rate limit
        if not await self.is_allowed(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again later.",
                headers={"Retry-After": "60"}
            )
        
        return await call_next(request)
    
    def get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to client host
        return request.client.host if request.client else "unknown"
    
    async def is_allowed(self, client_ip: str) -> bool:
        """Check if client is allowed based on rate limit"""
        try:
            current_time = int(time.time())
            window_start = current_time - self.window_size
            
            # Redis key for this client
            key = f"rate_limit:{client_ip}"
            
            # Use Redis pipeline for atomic operations
            pipe = redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(current_time): current_time})
            
            # Set expiry
            pipe.expire(key, self.window_size)
            
            # Execute pipeline
            results = pipe.execute()
            
            current_requests = results[1]  # Count of current requests
            
            return current_requests < self.calls_per_minute
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # Allow request if Redis is down
            return True