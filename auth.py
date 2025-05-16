# auth.py - Authentication functions with enhanced security
import re
import time
import bcrypt
import jwt
import uuid
import logging
import hashlib
import os
import json
from functools import wraps
from flask import g, request, jsonify
from datetime import datetime, timedelta

from db import db_execute, log_security_event
from config import config

# Redis connection for token blacklist (initialize later)
try:
    import redis
    _redis_client = None
except ImportError:
    _redis_client = None
    logging.warning("Redis not found. Token blacklisting will use database only. Install redis with: pip install redis")

def get_redis_client():
    """Get a Redis client for token operations"""
    from redis_service import get_redis_client as get_redis
    return get_redis('token')

def is_valid_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return isinstance(email, str) and bool(re.match(pattern, email))

def is_valid_username(username):
    """Validate username format"""
    # Allow alphanumeric characters, underscores, hyphens, 3-30 chars
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return isinstance(username, str) and bool(re.match(pattern, username))

def check_password_strength(password):
    """
    Validates password against security policy
    Returns (bool valid, str message)
    """
    if not isinstance(password, str):
        return False, "Password must be a string"
    
    if len(password) < config["PASSWORD_MIN_LENGTH"]:
        return False, f"Password must be at least {config['PASSWORD_MIN_LENGTH']} characters"
    
    checks = []
    messages = []
    
    if config["PASSWORD_REQUIRE_MIXED_CASE"]:
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        checks.append(has_upper and has_lower)
        if not (has_upper and has_lower):
            messages.append("both uppercase and lowercase letters")
    
    if config["PASSWORD_REQUIRE_DIGIT"]:
        has_digit = any(c.isdigit() for c in password)
        checks.append(has_digit)
        if not has_digit:
            messages.append("at least one number")
    
    if config["PASSWORD_REQUIRE_SPECIAL"]:
        special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
        has_special = any(c in special_chars for c in password)
        checks.append(has_special)
        if not has_special:
            messages.append("at least one special character")
    
    if all(checks):
        return True, "Password meets requirements"
    else:
        return False, f"Password must contain {', '.join(messages)}"

def check_password_history(user_id, new_password):
    """
    Check if password has been used before
    Returns (bool is_new, str message)
    """
    history_count = config.get("PASSWORD_HISTORY_COUNT", 0)
    if history_count <= 0:
        return True, "Password history check disabled"
        
    # Get user's password history
    try:
        user = db_execute(
            'SELECT password FROM users WHERE id = ?',
            (user_id,),
            fetchone=True
        )
        
        if not user:
            return False, "User not found"
            
        # Check current password
        if bcrypt.checkpw(new_password.encode(), user['password']):
            return False, "Cannot reuse current password"
            
        # In a real implementation, you'd store password history
        # For simplicity, we're just checking current password
        
        return True, "Password is not in history"
    except Exception as e:
        logging.error(f"Password history check error: {str(e)}")
        return False, "Error checking password history"

def sanitize_input(data):
    """
    Clean user input to prevent injection attacks
    This is an additional layer of protection besides parameterized queries
    """
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, str):
        # Basic sanitization - remove dangerous characters
        # Note: This doesn't replace proper parameterized queries,
        # but adds an extra layer of protection
        sanitized = data.replace('<', '&lt;').replace('>', '&gt;')
        
        # Check for potential SQL injection patterns
        sql_patterns = [
            '--',           # SQL comment
            ';',            # Statement terminator
            '/*',           # Block comment start
            '*/',           # Block comment end
            'UNION',        # UNION operator
            'SELECT',       # SELECT statement
            'INSERT',       # INSERT statement
            'UPDATE',       # UPDATE statement
            'DELETE',       # DELETE statement
            'DROP',         # DROP statement
            'EXEC',         # EXEC statement
            'EXECUTE',      # EXECUTE statement
            'xp_',          # Extended stored procedures in SQL Server
        ]
        
        # Log suspicious patterns (don't block, as parameterized queries handle this)
        for pattern in sql_patterns:
            if pattern.lower() in sanitized.lower():
                logging.warning(f"Potentially malicious input detected: {data}")
                logging.warning(f"Suspicious pattern: {pattern}")
                break
                
        return sanitized
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    else:
        return data

from flask import request

def get_client_info():
    """
    Retrieve the client's IP address and User-Agent string from the request,
    and always return them as plain Python str.
    """
    # Try X-Forwarded-For first (may contain a comma-separated list)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        # Trust only the leftmost IP in the chain
        ip = ip.split(',', 1)[0].strip()

    # Fallback to the User-Agent header (always a string)
    user_agent = request.headers.get('User-Agent', '')

    return ip, user_agent

def get_client_fingerprint():
    """Generate a fingerprint for the client"""
    ip, user_agent = get_client_info()
    fingerprint_data = f"{ip}:{user_agent}"
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()

def check_account_status(username):
    """
    Check if account is locked due to failed login attempts
    Returns (bool is_locked, int remaining_time)
    """
    lockout_threshold = int(config.get("ACCOUNT_LOCKOUT_THRESHOLD", 5))
    lockout_duration  = int(config.get("ACCOUNT_LOCKOUT_DURATION", 900))
    
    if lockout_threshold <= 0:
        return False, 0  # Lockout disabled
    
    try:
        user = db_execute(
            'SELECT id, failed_login_count, account_status FROM users WHERE username = ?',
            (username,),
            fetchone=True
        )
        
        if not user:
            # Don't reveal user existence, simulate lockout check
            return False, 0
            
        if user['account_status'] == 'locked':
            # Check when it was locked
            last_failed = db_execute(
                '''SELECT MAX(timestamp) as lock_time FROM login_attempts 
                   WHERE username = ? AND success = 0''',
                (username,),
                fetchone=True
            )
            
            if last_failed and last_failed['lock_time']:
                lock_time = last_failed['lock_time']
                current_time = int(time.time())
                elapsed = current_time - lock_time
                
                if elapsed < lockout_duration:
                    remaining = lockout_duration - elapsed
                    return True, remaining
                else:
                    # Lockout period expired, reset status
                    db_execute(
                        'UPDATE users SET account_status = "active", failed_login_count = 0 WHERE id = ?',
                        (user['id'],),
                        commit=True
                    )
            
        return False, 0
    except Exception as e:
        logging.error(f"Account status check error: {str(e)}")
        return False, 0  # Default to not locked on error

def update_login_attempt(username, success, ip_address, user_agent):
    """
    Record login attempt and update account status if needed
    """
    try:
        timestamp = int(time.time())
        
        # Record the attempt
        db_execute(
            'INSERT INTO login_attempts (username, ip_address, user_agent, success, timestamp) VALUES (?, ?, ?, ?, ?)',
            (username, ip_address, user_agent, 1 if success else 0, timestamp),
            commit=True
        )
        
        if not success:
            # Update failed login count
            user = db_execute(
                'SELECT id, failed_login_count FROM users WHERE username = ?',
                (username,),
                fetchone=True
            )
            
            if user:
                lockout_threshold = config.get("ACCOUNT_LOCKOUT_THRESHOLD", 5)
                new_count = user['failed_login_count'] + 1
                
                if new_count >= lockout_threshold:
                    # Lock the account
                    db_execute(
                        'UPDATE users SET failed_login_count = ?, account_status = "locked" WHERE id = ?',
                        (new_count, user['id']),
                        commit=True
                    )
                    
                    # Log security event
                    log_security_event(
                        user['id'], 
                        'ACCOUNT_LOCKED', 
                        f"Account locked after {new_count} failed login attempts",
                        ip_address,
                        'high',  # Higher risk level
                        json.dumps({'failed_count': new_count})
                    )
                else:
                    # Just update the counter
                    db_execute(
                        'UPDATE users SET failed_login_count = ? WHERE id = ?',
                        (new_count, user['id']),
                        commit=True
                    )
        else:
            # Successful login - reset failed count
            user = db_execute(
                'SELECT id FROM users WHERE username = ?',
                (username,),
                fetchone=True
            )
            
            if user:
                db_execute(
                    'UPDATE users SET failed_login_count = 0, account_status = "active" WHERE id = ?',
                    (user['id'],),
                    commit=True
                )
        
        return True
    except Exception as e:
        logging.error(f"Failed to update login attempt: {str(e)}")
        return False

def create_access_token(user_id, additional_data=None):
    """Generate a new JWT access token for the given user"""
    # Get shorter expiration for access tokens
    expiration = int(time.time()) + config.get("ACCESS_TOKEN_EXPIRATION", 3600)
    
    # Generate a random token ID (jti)
    token_id = str(uuid.uuid4())
    
    # Get client info for the token
    client_ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
    
    # Create a fingerprint for the client
    fingerprint = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
    
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'iat': int(time.time()),
        'jti': token_id,
        'type': 'access',
        'fingerprint': fingerprint
    }
    
    if additional_data:
        payload.update(additional_data)
        
    # Add token to the database for tracking
    try:
        timestamp = int(time.time())
        
        # Convert additional_data to JSON string if present
        json_data = None
        if additional_data:
            try:
                json_data = json.dumps(additional_data)
            except:
                pass
                
        db_execute(
            '''INSERT INTO user_sessions 
               (token, user_id, created_at, expires_at, ip_address, user_agent, last_active, token_type, additional_data, device_fingerprint) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (token_id, user_id, timestamp, expiration, client_ip, user_agent, timestamp, 'access', json_data, fingerprint),
            commit=True
        )
    except Exception as e:
        logging.error(f"Failed to record token in database: {str(e)}")
    
    # Use the specified algorithm from config
    algorithm = config.get("TOKEN_ALGORITHM", "HS256")
    return jwt.encode(payload, config["JWT_SECRET"], algorithm=algorithm)

def create_refresh_token(user_id):
    """Generate a refresh token with longer expiration"""
    # Get longer expiration for refresh tokens
    expiration = int(time.time()) + config.get("REFRESH_TOKEN_EXPIRATION", 2592000)
    
    # Generate a random token ID (jti)
    token_id = str(uuid.uuid4())
    
    # Get client info for the token
    client_ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
    
    # Create a fingerprint for the client
    fingerprint = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
    
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'iat': int(time.time()),
        'jti': token_id,
        'type': 'refresh',
        'fingerprint': fingerprint
    }
    
    # Add token to the database for tracking
    try:
        timestamp = int(time.time())
        db_execute(
            '''INSERT INTO user_sessions 
               (token, user_id, created_at, expires_at, ip_address, user_agent, last_active, token_type, device_fingerprint) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (token_id, user_id, timestamp, expiration, client_ip, user_agent, timestamp, 'refresh', fingerprint),
            commit=True
        )
    except Exception as e:
        logging.error(f"Failed to record refresh token in database: {str(e)}")
    
    # Use the specified algorithm from config
    algorithm = config.get("TOKEN_ALGORITHM", "HS256")
    return jwt.encode(payload, config["JWT_SECRET"], algorithm=algorithm)

def verify_token(token):
    """Verify a JWT token and return its payload"""
    try:
        # Use the specified algorithm from config
        algorithm = config.get("TOKEN_ALGORITHM", "HS256")
        payload = jwt.decode(token, config["JWT_SECRET"], algorithms=[algorithm])
        
        # Check if token is blacklisted
        if is_token_blacklisted(payload.get('jti')):
            logging.warning(f"Attempt to use blacklisted token: {payload.get('jti')}")
            return None
            
        # Get client info for fingerprint verification
        client_ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
        current_fingerprint = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
        
        # Check fingerprint if enabled and token contains it
        if config.get("VERIFY_TOKEN_FINGERPRINT", True) and 'fingerprint' in payload:
            # For refresh tokens, strictly verify the fingerprint
            if payload.get('type') == 'refresh' and payload.get('fingerprint') != current_fingerprint:
                logging.warning(f"Fingerprint mismatch for refresh token: {payload.get('jti')}")
                return None
                
            # For access tokens, log but allow mismatches (to handle IP changes)
            if payload.get('type') == 'access' and payload.get('fingerprint') != current_fingerprint:
                logging.info(f"Access token fingerprint changed: {payload.get('jti')}")
        
        return payload
    except jwt.ExpiredSignatureError:
        logging.info("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        logging.warning(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Token verification error: {str(e)}")
        return None

def is_token_blacklisted(token_id):
    """Check if a token has been blacklisted"""
    if not token_id:
        return False
        
    # Try Redis first if available
    redis_client = get_redis_client()
    if redis_client:
        try:
            return redis_client.exists(f"blacklist:{token_id}")
        except Exception as e:
            logging.error(f"Redis blacklist check error: {str(e)}")
            # Fall back to database check
            
    # Check database if Redis not available
    try:
        result = db_execute(
            'SELECT is_valid FROM user_sessions WHERE token = ?',
            (token_id,),
            fetchone=True
        )
        
        if result:
            return result['is_valid'] == 0
            
        return False
    except Exception as e:
        logging.error(f"Database blacklist check error: {str(e)}")
        return False

def blacklist_token(token):
    """Add a token to the blacklist"""
    try:
        # Decode the token to get its ID and expiration
        algorithm = config.get("TOKEN_ALGORITHM", "HS256")
        payload = jwt.decode(token, config["JWT_SECRET"], algorithms=[algorithm])
        
        token_id = payload.get('jti')
        token_exp = payload.get('exp')
        
        if not token_id:
            logging.warning("Attempted to blacklist token without JTI")
            return False
            
        # Calculate seconds until expiration
        now = int(time.time())
        ttl = max(0, token_exp - now) if token_exp else 86400  # Default 1 day
        
        # Add to Redis if available
        redis_client = get_redis_client()
        redis_success = False
        if redis_client:
            try:
                # Store token in Redis blacklist with TTL
                redis_client.setex(f"blacklist:{token_id}", ttl, "1")
                logging.info(f"Token {token_id} added to Redis blacklist")
                redis_success = True
            except Exception as e:
                logging.error(f"Redis blacklist error: {str(e)}")
                # Fall back to database
        
        # Always update database (as fallback)
        db_execute(
            'UPDATE user_sessions SET is_valid = 0 WHERE token = ?',
            (token_id,),
            commit=True
        )
        
        logging.info(f"Token {token_id} blacklisted successfully")
        return True
    except Exception as e:
        logging.error(f"Failed to blacklist token: {str(e)}")
        return False

def revoke_all_user_tokens(user_id):
    """Revoke all tokens for a specific user"""
    try:
        # Get all active tokens for the user
        tokens = db_execute(
            'SELECT token, expires_at FROM user_sessions WHERE user_id = ? AND is_valid = 1',
            (user_id,),
            fetchall=True
        )
        
        if not tokens:
            return True
            
        # Add to Redis blacklist if available
        redis_client = get_redis_client()
        if redis_client:
            try:
                for token in tokens:
                    token_id = token['token']
                    expires_at = token['expires_at']
                    
                    # Calculate TTL
                    now = int(time.time())
                    ttl = max(0, expires_at - now)
                    
                    # Add to Redis blacklist
                    redis_client.setex(f"blacklist:{token_id}", ttl, "1")
            except Exception as e:
                logging.error(f"Redis batch blacklist error: {str(e)}")
        
        # Update in database
        db_execute(
            'UPDATE user_sessions SET is_valid = 0 WHERE user_id = ? AND is_valid = 1',
            (user_id,),
            commit=True
        )
        
        logging.info(f"All tokens for user {user_id} revoked successfully")
        return True
    except Exception as e:
        logging.error(f"Failed to revoke user tokens: {str(e)}")
        return False

def token_required(f):
    """Decorator to require JWT token for protected routes with enhanced security"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
            
        try:
            payload = verify_token(token)
            
            if not payload:
                return jsonify({'error': 'Invalid or expired token'}), 401
                
            # Check token type - only accept access tokens
            if payload.get('type') != 'access':
                return jsonify({'error': 'Invalid token type'}), 401
                
            g.user_id = payload['user_id']
            g.token_jti = payload.get('jti')
            
            # Update last activity time in user_sessions table
            ip, user_agent = get_client_info()
            db_execute(
                'UPDATE user_sessions SET last_active = ? WHERE token = ?',
                (int(time.time()), payload.get('jti')),
                commit=True
            )
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logging.error(f"Token verification error: {str(e)}")
            return jsonify({'error': 'Token verification failed'}), 401
            
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # First require a valid token
        @token_required
        def check_admin(*args, **kwargs):
            user_id = g.user_id
            
            # Check if user is admin
            user = db_execute(
                'SELECT username FROM users WHERE id = ? AND username = ?',
                (user_id, config["ADMIN_USERNAME"]),
                fetchone=True
            )
            
            if not user:
                return jsonify({'error': 'Administrator privileges required'}), 403
                
            return f(*args, **kwargs)
            
        return check_admin(*args, **kwargs)
    return decorated

def track_login_attempts(username, ip, success=False):
    """
    Track login attempts for rate limiting purposes
    Uses Redis if available, otherwise falls back to database
    """
    redis_client = None
    try:
        # Try to get Redis client from token management
        redis_client = get_redis_client()
    except:
        pass
    
    # Use Redis if available
    if redis_client:
        try:
            key = f"login_attempts:{username}:{ip}"
            window = config.get("RATE_LIMIT_LOGIN_ATTEMPTS_WINDOW", 3600)  # 1 hour default
            
            if success and config.get("RATE_LIMIT_LOGIN_SUCCESS_RESET", True):
                # Reset counter on successful login
                redis_client.delete(key)
                return 0
            else:
                # Increment counter and set expiry
                count = redis_client.incr(key)
                redis_client.expire(key, window)
                return count
        except Exception as e:
            logging.error(f"Redis login tracking error: {str(e)}")
            # Fall back to database
    
    # Use database if Redis not available
    try:
        timestamp = int(time.time())
        window_start = timestamp - config.get("RATE_LIMIT_LOGIN_ATTEMPTS_WINDOW", 3600)
        
        if success and config.get("RATE_LIMIT_LOGIN_SUCCESS_RESET", True):
            # Add success record and clear failed count
            db_execute(
                'INSERT INTO login_attempts (username, ip_address, user_agent, success, timestamp) VALUES (?, ?, ?, ?, ?)',
                (username, ip, request.headers.get('User-Agent', ''), 1, timestamp),
                commit=True
            )
            return 0
        else:
            # Add failed attempt record
            db_execute(
                'INSERT INTO login_attempts (username, ip_address, user_agent, success, timestamp) VALUES (?, ?, ?, ?, ?)',
                (username, ip, request.headers.get('User-Agent', ''), 0, timestamp),
                commit=True
            )
            
            # Count recent failed attempts
            result = db_execute(
                'SELECT COUNT(*) as count FROM login_attempts WHERE username = ? AND ip_address = ? AND success = 0 AND timestamp > ?',
                (username, ip, window_start),
                fetchone=True
            )
            
            return result['count'] if result else 1
    except Exception as e:
        logging.error(f"Database login tracking error: {str(e)}")
        return 0