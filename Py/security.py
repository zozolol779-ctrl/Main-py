import time
from fastapi import Request, HTTPException
from typing import Dict, Tuple

class RateLimiter:
    """
    In-memory Token Bucket Rate Limiter.
    """
    def __init__(self):
        # {ip: (tokens, last_refill_time)}
        self.buckets: Dict[str, Tuple[float, float]] = {}
        
    def check(self, request: Request, limit: int = 10, window: int = 60):
        """
        limit: Number of requests allowed
        window: Time window in seconds
        """
        client_ip = request.client.host
        now = time.time()
        
        if client_ip not in self.buckets:
            self.buckets[client_ip] = (limit, now)
        
        tokens, last_refill = self.buckets[client_ip]
        
        # Refill tokens
        elapsed = now - last_refill
        refill_rate = limit / window
        new_tokens = elapsed * refill_rate
        tokens = min(limit, tokens + new_tokens)
        
        if tokens < 1:
            raise HTTPException(status_code=429, detail="Too Many Requests - Rate Limit Exceeded")
            
        # Consume token
        self.buckets[client_ip] = (tokens - 1, now)
        return True

# Singleton
limiter = RateLimiter()

async def check_rate_limit(request: Request):
    """
    Dependency for critical endpoints.
    5 requests per minute per IP.
    """
    limiter.check(request, limit=50, window=60) # Default strict limit for general API

async def check_strict_limit(request: Request):
    """
    Very strict limit for AI/Heavy endpoints.
    5 requests per minute.
    """
    limiter.check(request, limit=5, window=60)
