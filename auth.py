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
import sys
from functools import wraps
from flask import g, request, jsonify, abort
from datetime import datetime, timedelta
import jwt 
from db import db_execute, log_security_event, db_query_one
from config import config





def get_current_user_id():
    """
    Extract the Bearer token from Authorization,
    verify it against your user_sessions table,
    and return the corresponding user_id.
    """
    auth  = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, "Missing or malformed Authorization header")
    token = auth.split(None, 1)[1]

    # look up the session
    row = db_query_one(
        "SELECT user_id FROM user_sessions "
        "WHERE token = ? AND is_valid = 1 AND expires_at > ?",
        (token, int(time.time()))
    )
    if not row:
        abort(401, "Invalid or expired token")

    return row["user_id"]





# Path to RSA key files
PRIVATE_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'private_key.pem')
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public_key.pem')

def ensure_rsa_keys_exist(force=False):
    """Generate RSA keys if they don't exist or force is True"""
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH) or force:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Save private key
            pem_private = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(PRIVATE_KEY_PATH, 'wb') as f:
                f.write(pem_private)
            
            # Save public key
            public_key = private_key.public_key()
            pem_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(PUBLIC_KEY_PATH, 'wb') as f:
                f.write(pem_public)
                
            action = "Generated" if not force else "Regenerated"
            logging.info(f"{action} new RSA key pair at {PRIVATE_KEY_PATH} and {PUBLIC_KEY_PATH}")
            return True
        except ImportError:
            logging.error("cryptography package not installed. Install with: pip install cryptography")
            return False
        except Exception as e:
            logging.error(f"Failed to generate RSA keys: {str(e)}")
            return False
    return True

# Ensure RSA keys exist at module load time
try:
    if not ensure_rsa_keys_exist():
        logging.error("Failed to ensure RSA keys exist. JWT signing will fail!")
        # Uncomment the following line if you want to force the server to exit on missing keys
        # sys.exit(1)
except Exception as e:
    logging.error(f"Critical error ensuring RSA keys: {e}")

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
    """Generate a new JWT access token for the given user with Coherence Cloud claims"""
    # Get shorter expiration for access tokens
    expiration = int(time.time()) + config.get("JWT_EXPIRATION", 3600)
    
    # Generate a random token ID (jti)
    token_id = str(uuid.uuid4())
    
    # Get client info for the token
    client_ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
    
    # Create a fingerprint for the client
    fingerprint = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
    
    # Base payload with standard JWT claims
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'iat': int(time.time()),
        'jti': token_id,
        'type': 'access',
        'fingerprint': fingerprint,
        # Add the following required claims for Coherence Cloud
        'iss': config.get("JWT_ISSUER", "vespeyr-auth-server"),
        'aud': config.get("JWT_AUDIENCE", "coherence-cloud-api"),
        'sub': str(user_id)  # Ensure subject is a string
    }
    
    # Add any additional user data to the payload
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
    
    # ALWAYS USE RS256 FOR COHERENCE CLOUD
    try:
        # Check if private key exists
        if not os.path.exists(PRIVATE_KEY_PATH):
            # Try to generate it first
            if not ensure_rsa_keys_exist(force=True):
                raise ValueError("Failed to generate RSA keys needed for JWT signing")
        
        # Read the private key and use RS256    
        with open(PRIVATE_KEY_PATH, 'r') as key_file:
            private_key = key_file.read()
            
        token = jwt.encode(payload, private_key, algorithm="RS256")
        logging.info(f"Generated RS256 JWT token for user {user_id}")
        return token
    except Exception as e:
        logging.error(f"Failed to sign token with RS256: {e}")
        # If we absolutely need a fallback, we could use HS256 but that won't work with Coherence
        # Instead, let the error propagate
        raise ValueError(f"Cannot create JWT token: {e}")

def create_refresh_token(user_id):
    """Generate a refresh token with longer expiration and Coherence Cloud claims"""
    # Get longer expiration for refresh tokens
    expiration = int(time.time()) + config.get("REFRESH_TOKEN_EXPIRATION", 2592000)
    
    # Generate a random token ID (jti)
    token_id = str(uuid.uuid4())
    
    # Get client info for the token
    client_ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
    
    # Create a fingerprint for the client
    fingerprint = hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()
    
    # Create payload with Coherence Cloud required claims
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'iat': int(time.time()),
        'jti': token_id,
        'type': 'refresh',
        'fingerprint': fingerprint,
        # Add the following required claims for Coherence Cloud
        'iss': config.get("JWT_ISSUER", "vespeyr-auth-server"),
        'aud': config.get("JWT_AUDIENCE", "coherence-cloud-api"),
        'sub': str(user_id)  # Ensure subject is a string
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
    
    # ALWAYS USE RS256 FOR COHERENCE CLOUD
    try:
        # Check if private key exists
        if not os.path.exists(PRIVATE_KEY_PATH):
            # Try to generate it first
            if not ensure_rsa_keys_exist(force=True):
                raise ValueError("Failed to generate RSA keys needed for JWT signing")
        
        # Read the private key and use RS256    
        with open(PRIVATE_KEY_PATH, 'r') as key_file:
            private_key = key_file.read()
            
        token = jwt.encode(payload, private_key, algorithm="RS256")
        logging.info(f"Generated RS256 JWT refresh token for user {user_id}")
        return token
    except Exception as e:
        logging.error(f"Failed to sign refresh token with RS256: {e}")
        # If we absolutely need a fallback, we could use HS256 but that won't work with Coherence
        # Instead, let the error propagate
        raise ValueError(f"Cannot create JWT refresh token: {e}")

def verify_token(token):
    """Verify a JWT token and return its payload"""
    try:
        # Get the token header without verification to determine algorithm
        unverified_header = jwt.get_unverified_header(token)
        algorithm = unverified_header.get('alg', 'HS256')
        
        if algorithm == 'RS256':
            # RSA verification
            if not os.path.exists(PUBLIC_KEY_PATH):
                logging.error(f"Cannot verify RS256 token: Public key not found at {PUBLIC_KEY_PATH}")
                return None
                
            with open(PUBLIC_KEY_PATH, 'r') as key_file:
                public_key = key_file.read()
            payload = jwt.decode(
                token, 
                public_key, 
                algorithms=["RS256"],
                audience=config.get("JWT_AUDIENCE", "coherence-cloud-api"),
                options={"verify_aud": True}
            )
        else:
            # HMAC verification - keep for legacy tokens but can be removed in the future
            logging.warning("Verifying token with HS256 - this will not work with Coherence Cloud")
            payload = jwt.decode(
                token, 
                config["JWT_SECRET"], 
                algorithms=["HS256"]
            )
        
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
        # Get the token header without verification to determine algorithm
        unverified_header = jwt.get_unverified_header(token)
        algorithm = unverified_header.get('alg', 'HS256')
        
        if algorithm == 'RS256':
            # RSA verification
            if not os.path.exists(PUBLIC_KEY_PATH):
                logging.error(f"Cannot verify RS256 token: Public key not found at {PUBLIC_KEY_PATH}")
                return False
                
            with open(PUBLIC_KEY_PATH, 'r') as key_file:
                public_key = key_file.read()
            payload = jwt.decode(token, public_key, algorithms=["RS256"])
        else:
            # HMAC verification
            payload = jwt.decode(token, config["JWT_SECRET"], algorithms=["HS256"])
        
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

def get_user_by_id(user_id):
    """
    Retrieve a user by their ID
    Returns user dict or None if not found
    """
    try:
        user = db_execute(
            'SELECT id, username, email, created_at, last_login, login_count, account_status FROM users WHERE id = ?',
            (user_id,),
            fetchone=True
        )
        return user
    except Exception as e:
        logging.error(f"Error getting user by ID {user_id}: {e}")
        return None

def get_user_by_username(username):
    """
    Retrieve a user by their username
    Returns user dict or None if not found
    """
    try:
        user = db_execute(
            'SELECT id, username, email, password, created_at, last_login, login_count, account_status, failed_login_count FROM users WHERE username = ?',
            (username,),
            fetchone=True
        )
        return user
    except Exception as e:
        logging.error(f"Error getting user by username {username}: {e}")
        return None

def update_user(user_id, **kwargs):
    """
    Update user information
    
    Args:
        user_id: The user's ID
        **kwargs: Fields to update (email, last_login, login_count, etc.)
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not kwargs:
            return True  # Nothing to update
            
        # Build dynamic update query
        valid_fields = ['email', 'last_login', 'login_count', 'account_status', 'failed_login_count', 'last_password_change']
        
        # Filter out invalid fields
        update_fields = {k: v for k, v in kwargs.items() if k in valid_fields}
        
        if not update_fields:
            logging.warning(f"No valid fields to update for user {user_id}")
            return False
            
        # Build SET clause
        set_clause = ', '.join([f"{field} = ?" for field in update_fields.keys()])
        values = list(update_fields.values()) + [user_id]
        
        query = f"UPDATE users SET {set_clause} WHERE id = ?"
        
        db_execute(query, values, commit=True)
        
        logging.info(f"Updated user {user_id} with fields: {list(update_fields.keys())}")
        return True
        
    except Exception as e:
        logging.error(f"Error updating user {user_id}: {e}")
        return False

def create_user(username, email, password):
    """
    Create a new user account
    
    Args:
        username: User's chosen username
        email: User's email address  
        password: User's password (will be hashed)
        
    Returns:
        tuple: (bool success, str user_id_or_error_message)
    """
    try:
        # Validate inputs
        username = sanitize_input(username)
        email = sanitize_input(email)
        
        if not is_valid_username(username):
            return False, "Invalid username format"
            
        if not is_valid_email(email):
            return False, "Invalid email format"
            
        # Check password strength
        password_valid, password_msg = check_password_strength(password)
        if not password_valid:
            return False, password_msg
            
        # Check if username already exists
        existing_user = get_user_by_username(username)
        if existing_user:
            return False, "Username already exists"
            
        # Check if email already exists
        existing_email = db_execute(
            'SELECT id FROM users WHERE email = ?',
            (email,),
            fetchone=True
        )
        if existing_email:
            return False, "Email already registered"
            
        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Generate user ID
        user_id = str(uuid.uuid4())
        timestamp = int(time.time())
        
        # Create user
        db_execute(
            '''INSERT INTO users 
               (id, username, email, password, created_at, last_login, login_count, account_status, failed_login_count, last_password_change) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (user_id, username, email, password_hash, timestamp, 0, 0, 'active', 0, timestamp),
            commit=True
        )
        
        # Log security event
        ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
        log_security_event(
            user_id,
            'USER_CREATED',
            f"New user account created: {username}",
            ip,
            user_agent,
            'low'
        )
        
        logging.info(f"Created new user: {username} (ID: {user_id})")
        return True, user_id
        
    except Exception as e:
        logging.error(f"Error creating user {username}: {e}")
        return False, f"Account creation failed: {str(e)}"

def change_user_password(user_id, old_password, new_password):
    """
    Change a user's password
    
    Args:
        user_id: The user's ID
        old_password: Current password for verification
        new_password: New password to set
        
    Returns:
        tuple: (bool success, str message)
    """
    try:
        # Get current user
        user = get_user_by_id(user_id)
        if not user:
            return False, "User not found"
            
        # Get full user info including password
        user_with_password = db_execute(
            'SELECT password FROM users WHERE id = ?',
            (user_id,),
            fetchone=True
        )
        
        if not user_with_password:
            return False, "User not found"
            
        # Verify old password
        if not bcrypt.checkpw(old_password.encode('utf-8'), user_with_password['password']):
            return False, "Current password is incorrect"
            
        # Check new password strength
        password_valid, password_msg = check_password_strength(new_password)
        if not password_valid:
            return False, password_msg
            
        # Check password history
        history_valid, history_msg = check_password_history(user_id, new_password)
        if not history_valid:
            return False, history_msg
            
        # Hash new password
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        timestamp = int(time.time())
        
        # Update password
        db_execute(
            'UPDATE users SET password = ?, last_password_change = ? WHERE id = ?',
            (new_password_hash, timestamp, user_id),
            commit=True
        )
        
        # Log security event
        ip, user_agent = get_client_info() if hasattr(request, 'remote_addr') else ('unknown', 'unknown')
        log_security_event(
            user_id,
            'PASSWORD_CHANGED',
            "User changed their password",
            ip,
            user_agent,
            'medium'
        )
        
        # Revoke all existing tokens to force re-login
        revoke_all_user_tokens(user_id)
        
        logging.info(f"Password changed for user {user_id}")
        return True, "Password changed successfully"
        
    except Exception as e:
        logging.error(f"Error changing password for user {user_id}: {e}")
        return False, "Failed to change password"