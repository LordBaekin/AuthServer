import logging
import redis
from config import config

# Global Redis client instances
_rate_limit_redis = None
_token_redis = None

def get_redis_client(purpose='rate_limit'):
    """
    Get a Redis client for the specified purpose.
    
    Args:
        purpose (str): Either 'rate_limit' or 'token'
    
    Returns:
        redis.Redis or None: Redis client or None if Redis is not available
    """
    global _rate_limit_redis, _token_redis
    
    # Configuration values (with appropriate defaults)
    redis_enabled = config.get("REDIS_ENABLED", False)
    if not redis_enabled:
        return None
        
    redis_host = config.get("REDIS_HOST", "localhost")
    redis_port = int(config.get("REDIS_PORT", 6379))
    redis_password = config.get("REDIS_PASSWORD", None)
    
    # Different databases for different purposes
    if purpose == 'rate_limit':
        redis_db = int(config.get("REDIS_RATELIMIT_DB", 0))
        if _rate_limit_redis is None:
            try:
                _rate_limit_redis = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password,
                    db=redis_db,
                    socket_timeout=3,
                    socket_connect_timeout=3,
                    health_check_interval=30
                )
                # Test the connection
                _rate_limit_redis.ping()
                logging.info(f"Redis client for rate limiting initialized (DB: {redis_db})")
            except (redis.ConnectionError, redis.RedisError) as e:
                logging.warning(f"Redis connection failed for rate limiting: {e}")
                _rate_limit_redis = None
        return _rate_limit_redis
    
    elif purpose == 'token':
        redis_db = int(config.get("REDIS_TOKEN_DB", 1))
        if _token_redis is None:
            try:
                _token_redis = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    password=redis_password,
                    db=redis_db,
                    socket_timeout=3,
                    socket_connect_timeout=3,
                    health_check_interval=30
                )
                # Test the connection
                _token_redis.ping()
                logging.info(f"Redis client for token management initialized (DB: {redis_db})")
            except (redis.ConnectionError, redis.RedisError) as e:
                logging.warning(f"Redis connection failed for token management: {e}")
                _token_redis = None
        return _token_redis
    
    return None

def check_redis_connection():
    """
    Check if Redis is available for both rate limiting and token management.
    
    Returns:
        dict: Status of Redis connections
    """
    rate_limit_status = False
    token_status = False
    
    # Check rate limiting Redis
    rate_limit_client = get_redis_client('rate_limit')
    if rate_limit_client:
        try:
            if rate_limit_client.ping():
                rate_limit_status = True
        except:
            pass
    
    # Check token Redis
    token_client = get_redis_client('token')
    if token_client:
        try:
            if token_client.ping():
                token_status = True
        except:
            pass
    
    return {
        'rate_limit': rate_limit_status,
        'token': token_status,
        'overall': rate_limit_status and token_status
    }

def get_redis_info():
    """
    Get Redis server information for diagnostics.
    
    Returns:
        dict: Redis server info or None if unavailable
    """
    client = get_redis_client('rate_limit')
    if not client:
        return None
        
    try:
        return client.info()
    except:
        return None
