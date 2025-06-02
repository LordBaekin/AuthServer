# api.py - Flask routes and API
import logging
import time
import bcrypt
import uuid
import hashlib
from datetime import datetime
import os
import signal
import threading
import json
import sqlite3
import traceback
from db import db_query_all

from redis_service import get_redis_client

# Flask imports
from flask import Flask, request, jsonify, g, redirect, abort 
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.middleware.proxy_fix import ProxyFix
from auth import get_user_by_id, update_user, get_current_user_id

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# CORS support
from flask_cors import CORS

# Import our modules
from config import config, APP_VERSION, save_config
from db import (
    db_execute,
    log_security_event,
    close_db_connections,
    get_connection_pool_stats,
    db_query_one
)
from email_service import send_template_email
from auth import (
    is_valid_email,
    is_valid_username,
    check_password_strength,
    check_password_history,
    get_client_info,
    check_account_status,
    update_login_attempt,
    sanitize_input,
    create_access_token,
    create_refresh_token,
    verify_token,
    token_required,
    admin_required
)






# ---- Security Middleware ----
class SecurityMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            headers.extend([
                ('X-Content-Type-Options', 'nosniff'),
                ('X-Frame-Options', 'DENY'),
                ('X-XSS-Protection', '1; mode=block'),
                ("Content-Security-Policy", "default-src 'self'")
            ])
            # only add HSTS when running under HTTPS in production
            if environ.get('wsgi.url_scheme') == 'https' and not config.get("DEBUG_MODE", False):
                headers.append(('Strict-Transport-Security', 'max-age=31536000; includeSubDomains'))
            return start_response(status, headers, exc_info)
        return self.app(environ, custom_start_response)


# ---- Flask app factory ----
def create_app(test_config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=config["JWT_SECRET"],
        SERVER_NAME=None,
        PREFERRED_URL_SCHEME='https' if config["ENABLE_HTTPS_REDIRECT"] else 'http',
        JSON_SORT_KEYS=False,
        JSONIFY_PRETTYPRINT_REGULAR=False,
    )
    if test_config:
        app.config.update(test_config)

    # Middleware
    app.wsgi_app = SecurityMiddleware(app.wsgi_app)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # CORS
    origins = config["ALLOWED_ORIGINS"].split(',')
    CORS(app, resources={
    r"/auth/*":       {"origins": origins},
    r"/inventory/*":  {"origins": origins},
    r"/quests/*":     {"origins": origins},
    r"/stats/*":      {"origins": origins},
    r"/characters/*": {"origins": origins},
    r"/characters":   {"origins": origins},
    })


    # Rate limiter
    if config.get("REDIS_ENABLED", False):
        redis_client = get_redis_client('rate_limit')
        if redis_client:
            try:
                from flask_limiter.storage.redis import RedisStorage
                limiter = Limiter(
                    key_func=get_remote_address,
                    default_limits=[config["RATE_LIMIT_DEFAULT"]],
                    storage=RedisStorage(redis_client)
                )
                logging.info("Rate limiting using Redis storage")
            except ImportError:
                logging.warning("Could not import RedisStorage. Using in-memory rate limiting.")
                limiter = Limiter(key_func=get_remote_address,
                                  default_limits=[config["RATE_LIMIT_DEFAULT"]])
        else:
            logging.warning("Redis unavailable. Using in-memory rate limiting.")
            limiter = Limiter(key_func=get_remote_address,
                              default_limits=[config["RATE_LIMIT_DEFAULT"]])
    else:
        logging.info("Rate limiting using in-memory storage (Redis disabled)")
        limiter = Limiter(key_func=get_remote_address,
                          default_limits=[config["RATE_LIMIT_DEFAULT"]])
    limiter.init_app(app)

    # Loggers
    loggers = {
        'app': logging.getLogger('vespeyr.app'),
        'access': logging.getLogger('vespeyr.access'),
        'security': logging.getLogger('vespeyr.security')
    }


    import io

    def force_utf8_logger_streams(loggers_dict):
        for logger in loggers_dict.values():
            for handler in logger.handlers:
                stream = getattr(handler, 'stream', None)
                if isinstance(stream, io.TextIOWrapper):
                    try:
                        # Re-wrap in UTF-8 to support unicode like '->'
                        handler.setStream(io.TextIOWrapper(
                            stream.buffer,
                            encoding='utf-8',
                            errors='replace',  # prevents crash on fallback
                            line_buffering=True
                        ))
                    except Exception as e:
                        print(f"[UTF8 WRAP ERROR] {e}")

    # Only do this if running directly (not gunicorn or production)
    if threading.current_thread() is threading.main_thread():
        force_utf8_logger_streams(loggers)





    # Request logging
    @app.before_request
    def log_request():
        if request.path.startswith('/auth/'):
            ip, ua = get_client_info()
            loggers['access'].info(f"{request.method} {request.path} - IP:{ip} UA:{ua}")

    # Teardown
    @app.teardown_appcontext
    def cleanup(exception=None):
        close_db_connections()

    # HTTPS redirect (skip in DEBUG)
    @app.before_request
    def enforce_https():
        if (not config.get("DEBUG_MODE", False)
            and config.get("ENABLE_HTTPS_REDIRECT", True)
            and not request.is_secure
            and request.headers.get('X-Forwarded-Proto', 'http') != 'https'):
            if request.url.startswith('http://'):
                return redirect(request.url.replace('http://', 'https://', 1), code=301)

    # ---- Routes ----

    @app.route('/health', methods=['GET'])
    def health():
        db_ok = False
        try:
            db_execute('SELECT 1', fetchone=True)
            db_ok = True
        except:
            pass

        smtp_ok = False
        if config.get("SMTP_HOST") and config.get("SMTP_USER") and config.get("SMTP_PASS"):
            try:
                import smtplib
                with smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"], timeout=5) as smtp:
                    smtp.starttls()
                    smtp.login(config["SMTP_USER"], config["SMTP_PASS"])
                    smtp_ok = True
            except:
                pass

        status = 'ok' if db_ok else 'degraded'
        return jsonify({
            'status': status,
            'uptime': time.time(),
            'version': APP_VERSION,
            'database': 'connected' if db_ok else 'error',
            'email': 'configured' if smtp_ok else 'not_configured',
            'timestamp': datetime.now().isoformat()
        }), (200 if db_ok else 503)

    @app.route('/auth/register', methods=['POST'])
    @limiter.limit(config["RATE_LIMIT_DEFAULT"])
    def register():
        try:
            # 1) Parse & sanitize JSON
            data = sanitize_input(request.json or {})

            # 2) Required fields
            for k in ('username', 'email', 'password'):
                if k not in data or not isinstance(data[k], str):
                    return jsonify({'error': f'{k} required'}), 400

            # 3) Format & strength validations
            if not is_valid_username(data['username']):
                return jsonify({'error': 'Invalid username format.'}), 400
            if not is_valid_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            valid, msg = check_password_strength(data['password'])
            if not valid:
                return jsonify({'error': msg}), 400

            # 4) Hash and prepare to insert
            hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
            user_id = str(uuid.uuid4())
            ts = int(time.time())

            # 5) Attempt the INSERT
            try:
                db_execute(
                    'INSERT INTO users '
                    '(id, username, email, password, created_at, last_password_change) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (user_id, data['username'], data['email'], hashed, ts, ts),
                    commit=True
                )
            except sqlite3.IntegrityError as e:
                err = str(e).lower()
                loggers['app'].warning(f"IntegrityError during registration: {err}")

                # Duplicate username?
                if 'unique' in err and ('username' in err or 'users.username' in err):
                    return jsonify({'error': 'Username already exists. Please choose another.'}), 409
                # Duplicate email?
                if 'unique' in err and 'email' in err:
                    return jsonify({'error': 'Email address already registered.'}), 409

                # Something else went wrong at the DB level
                loggers['app'].error(f"Unexpected IntegrityError: {e}")
                return jsonify({'error': 'Registration failed due to a database constraint.'}), 500

            # 6) Issue JWTs / sessions
            token   = create_access_token(user_id)
            refresh = create_refresh_token(user_id)
            expiry  = ts + config["JWT_EXPIRATION"]

            db_execute(
                'INSERT INTO user_sessions '
                '(token, user_id, created_at, expires_at, ip_address, user_agent, last_active) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (token, user_id, ts, expiry, *get_client_info(), ts),
                commit=True
            )

            # 7) Send confirmation email
            try:
                from email_service import send_template_email

                email_success = send_template_email(
                    to_email=data['email'],
                    template_name="welcome",  # Must match EMAIL_TEMPLATES key
                    subject="Welcome to Vespeyr",
                    context={
                        "username": data['username'],
                        "email": data['email'],
                        "login_link": config.get("FRONTEND_LOGIN_URL", "https://vespeyr.com/login")
                    }
                )

                if email_success:
                    loggers['app'].info(f"Welcome email sent to {data['email']}")
                else:
                    loggers['app'].warning(f"Email sending reported failure for {data['email']}")

            except Exception as email_err:
                loggers['app'].warning(f"Email send failed after registration: {email_err}")

            # 8) Return success response
            return jsonify({
                'id':            user_id,
                'username':      data['username'],
                'access_token':  token,
                'refresh_token': refresh,
                'expires_in':    config["JWT_EXPIRATION"],
                'token_type':    'Bearer',
                'message':       'Registration successful',
                'email_sent':    email_success if 'email_success' in locals() else False
            }), 201

        except Exception as e:
            loggers['app'].error(f"Registration error: {e}")
            traceback.print_exc()
            return jsonify({'error': 'Server error during registration'}), 500



        

    @app.route('/auth/login', methods=['POST'])
    @limiter.limit(config["RATE_LIMIT_LOGIN"])
    def login():
        try:
            # Accept JSON or form
            if request.is_json:
                data = sanitize_input(request.get_json() or {})
            else:
                # Accept both 'username' and 'name' keys for maximum Unity compatibility
                form = request.form or {}
                data = {
                    'username': form.get('username') or form.get('name'),
                    'password': form.get('password')
                }
                data = sanitize_input(data)

            ip, ua = get_client_info()

            # Required fields
            for k in ('username', 'password'):
                if not data.get(k):
                    return jsonify({'error': f'{k} required'}), 400
                if not isinstance(data[k], str):
                    return jsonify({'error': 'Invalid credentials format'}), 400

            # Account lockout
            locked, left = check_account_status(data['username'])
            if locked:
                m, s = divmod(left, 60)
                return jsonify({
                    'error': 'Too many failed attempts',
                    'lockout_remaining': f"{m}m {s}s"
                }), 429

            # Fetch user
            user = db_execute(
                'SELECT id, password, username, email, account_status '
                'FROM users WHERE username = ?',
                (data['username'],),
                fetchone=True
            )
            ts = int(time.time())

            # Successful login
            if user and user['account_status'] == 'active' \
               and bcrypt.checkpw(data['password'].encode(), user['password']):

                # 1) Invalidate all previous sessions
                db_execute(
                    'UPDATE user_sessions SET is_valid = 0 WHERE user_id = ?',
                    (user['id'],),
                    commit=True
                )

                # 2) Update user last_login & count
                db_execute(
                    'UPDATE users SET last_login = ?, login_count = login_count + 1 WHERE id = ?',
                    (ts, user['id']),
                    commit=True
                )

                # 3) Issue new tokens
                token   = create_access_token(user['id'], {
                              'username': user['username'],
                              'email':    user['email']
                          })
                refresh = create_refresh_token(user['id'])
                expiry  = ts + config["JWT_EXPIRATION"]

                # 4) Insert only this new session
                db_execute(
                    'INSERT INTO user_sessions '
                    '(token, user_id, created_at, expires_at, ip_address, user_agent, last_active) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (token, user['id'], ts, expiry, ip, ua, ts),
                    commit=True
                )

                # 5) Log and respond
                loggers['app'].info(
                    f"Successful login: {user['username']} ({user['id']}) from {ip}"
                )
                log_security_event(
                    user['id'], 'USER_LOGIN',
                    f"Successful login from {ip}", ip
                )
                update_login_attempt(data['username'], True, ip, ua)

                return jsonify({
                    'id':           user['id'],
                    'username':     user['username'],
                    'access_token': token,
                    'refresh_token': refresh,
                    'expires_in':   config["JWT_EXPIRATION"],
                    'token_type':   'Bearer',
                    'message':      'Login successful'
                }), 200

            # Failed login attempt
            update_login_attempt(data['username'], False, ip, ua)
            if user:
                log_security_event(
                    user['id'], 'LOGIN_FAILED',
                    f"Failed login attempt from {ip}", ip
                )
                loggers['app'].warning(
                    f"Failed login for user: {user['username']} from IP: {ip}"
                )
            else:
                loggers['app'].warning(
                    f"Failed login attempt for unknown username: {data['username']} from IP: {ip}"
                )

            return jsonify({'error': 'Invalid credentials'}), 401

        except Exception as e:
            loggers['app'].error(f"Login error: {e}")
            traceback.print_exc() 
            return jsonify({'error': 'Server error during login'}), 500



    @app.route('/auth/refresh', methods=['POST'])
    @limiter.limit("10 per minute")
    def refresh_token_endpoint():
        try:
            data = sanitize_input(request.json or {})
            ip, ua = get_client_info()

            # Require the refresh token
            if 'refresh_token' not in data:
                return jsonify({'error': 'refresh_token required'}), 400

            # Verify it's a proper refresh token
            payload = verify_token(data['refresh_token'])
            if not payload or payload.get('type') != 'refresh':
                return jsonify({'error': 'Invalid refresh token'}), 401

            user_id = payload.get('user_id')
            if not user_id:
                return jsonify({'error': 'Invalid token format'}), 401

            # Ensure the user still exists & is active
            user = db_execute(
                'SELECT username, email, account_status FROM users WHERE id = ?',
                (user_id,), fetchone=True
            )
            if not user or user['account_status'] != 'active':
                return jsonify({'error': 'User account inactive or not found'}), 401

            # Generate a fresh pair of tokens
            new_token   = create_access_token(user_id, {
                              'username': user['username'],
                              'email':    user['email']
                          })
            new_refresh = create_refresh_token(user_id)
            ts          = int(time.time())
            expiry      = ts + config["JWT_EXPIRATION"]

            # 1) Invalidate *all* previous sessions for this user
            db_execute(
                'UPDATE user_sessions SET is_valid = 0 WHERE user_id = ?',
                (user_id,),
                commit=True
            )

            # 2) Insert only the new refreshed session
            db_execute(
                'INSERT INTO user_sessions '
                '(token, user_id, created_at, expires_at, ip_address, user_agent, last_active) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (new_token, user_id, ts, expiry, ip, ua, ts),
                commit=True
            )

            # Log the refresh event
            log_security_event(
                user_id, 'TOKEN_REFRESH',
                f"Access token refreshed from {ip}", ip
            )

            # Return the new tokens
            return jsonify({
                'access_token':  new_token,
                'refresh_token': new_refresh,
                'expires_in':    config["JWT_EXPIRATION"],
                'token_type':    'Bearer'  # Added token_type
            }), 200

        except Exception as e:
            loggers['app'].error(f"Token refresh error: {e}")
            return jsonify({'error': 'Server error during token refresh'}), 500

    @app.route('/leave_world', methods=['POST'])
    @token_required
    def leave_world():
        """
        Clears world_key for the current user's active session and
        deactivates the active character for that world.
        Logs both user_id and character_name when leaving.
        """
        user_id     = g.user_id
        auth_header = request.headers.get('Authorization', '')
        now_utc     = datetime.utcnow().isoformat() + "Z"
        current_ts  = int(time.time())

        # ─────────────────────────────────────────────────────────────────────────────
        # 1) Fetch the current session row so we know which world_key is being cleared.
        #    We select the most recently active, valid session for this user.
        # ─────────────────────────────────────────────────────────────────────────────
        session_row = db_query_one(
            '''
            SELECT world_key
              FROM user_sessions
             WHERE user_id = ?
               AND is_valid = 1
               AND expires_at > ?
             ORDER BY last_active DESC
             LIMIT 1
            ''',
            (user_id, current_ts)
        )
        current_world = session_row['world_key'] if session_row and session_row['world_key'] else None

        # ─────────────────────────────────────────────────────────────────────────────
        # 2) Look up which character (if any) is marked as is_active=1 for this user in that world.
        #    This gives us character_name for logging.
        # ─────────────────────────────────────────────────────────────────────────────
        character_name = None
        if current_world:
            char_row = db_query_one(
                '''
                SELECT character_name
                  FROM characters
                 WHERE user_id = ?
                   AND world_key = ?
                   AND is_active = 1
                 LIMIT 1
                ''',
                (user_id, current_world)
            )
            if char_row:
                character_name = char_row['character_name']

        # ─────────────────────────────────────────────────────────────────────────────
        # 3) Log who (user_id + character_name) is leaving which world.
        # ─────────────────────────────────────────────────────────────────────────────
        app.logger.info(
            f"[{now_utc}] [LeaveWorld] user_id={user_id} "
            f"character_name={character_name or '<none>'} "
            f"left world_key={current_world or '<none>'}"
        )

        # ─────────────────────────────────────────────────────────────────────────────
        # 4) Clear out world_key (and also deactivate the character) in the database:
        #    a) Remove world_key from user_sessions (as before).
        #    b) Set is_active = 0 on the characters row.
        # ─────────────────────────────────────────────────────────────────────────────
        # 4a) Clear world_key in the session
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1]
            db_execute(
                '''
                UPDATE user_sessions
                   SET world_key = NULL
                 WHERE user_id = ?
                   AND token = ?
                ''',
                (user_id, token),
                commit=True
            )
        else:
            db_execute(
                '''
                UPDATE user_sessions
                   SET world_key = NULL
                 WHERE user_id = ?
                   AND is_valid = 1
                   AND expires_at > ?
                ''',
                (user_id, current_ts),
                commit=True
            )

        # 4b) Deactivate the character (if one was active in that world)
        if current_world and character_name:
            db_execute(
                '''
                UPDATE characters
                   SET is_active = 0
                 WHERE user_id = ?
                   AND world_key = ?
                   AND character_name = ?
                   AND is_active = 1
                ''',
                (user_id, current_world, character_name),
                commit=True
            )

        return jsonify({'message': 'World and character cleared. You may select a new server.'}), 200



    @app.route('/auth/logout', methods=['POST'])
    @token_required
    def logout():
        try:
            user_id = g.user_id
            ip, _ = get_client_info()
            auth_header = request.headers.get('Authorization', '')
            now = int(time.time())

            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]

                # Invalidate this session and clear world_key for it
                db_execute(
                    'UPDATE user_sessions SET is_valid=0, world_key=NULL WHERE user_id=? AND token=?',
                    (user_id, token), commit=True
                )
            else:
                # As fallback, clear world_key and invalidate all active sessions for this user
                db_execute(
                    'UPDATE user_sessions SET is_valid=0, world_key=NULL WHERE user_id=? AND is_valid=1 AND expires_at > ?',
                    (user_id, now), commit=True
                )

            log_security_event(user_id, 'USER_LOGOUT',
                               f"User logged out from {ip}", ip)
            return jsonify({'message': 'Successfully logged out'}), 200

        except Exception as e:
            logging.getLogger('vespeyr.app').error(f"Logout error: {e}")
            return jsonify({'error': 'Server error during logout'}), 500


    @app.route('/auth/request-password-reset', methods=['POST'])
    @limiter.limit(config["RATE_LIMIT_RESET"])
    def request_reset():
        try:
            data = sanitize_input(request.json or {})
            ip, _ = get_client_info()
            email = data.get('email')

            if not email:
                return jsonify({'error': 'email required'}), 400
            if not is_valid_email(email):
                return jsonify({'error': 'Invalid email format'}), 400

            # Fetch all users with that email
            users = db_execute(
                'SELECT id, username FROM users WHERE email=?',
                (email,), fetchall=True
            )
            if not users:
                loggers['app'].info(f"Password reset requested for non-existent email: {email}")
                return jsonify({'message': 'If your email is registered, you will receive reset instructions'}), 200

            # Build reset links for each account
            accounts_html = ""
            for user in users:
                token = str(uuid.uuid4())
                expires = int(time.time()) + 3600
                db_execute('DELETE FROM reset_tokens WHERE user_id=?', (user['id'],), commit=True)
                db_execute(
                    'INSERT INTO reset_tokens '
                    '(token, user_id, expires_at, created_at, used) '
                    'VALUES (?, ?, ?, ?, ?)',
                    (token, user['id'], expires, int(time.time()), 0),
                    commit=True
                )

                reset_link = config["RESET_URL_BASE"] + token
                accounts_html += f"<p><b>{user['username']}</b>: <a href='{reset_link}'>Reset Password</a></p>\n"

                log_security_event(user['id'], 'PASSWORD_RESET_REQUEST',
                                   f"Password reset requested from {ip}", ip)

            # Send email using new template
            success = send_template_email(
                to_email=email,
                template_name="multi_reset_password",
                subject=f"Reset your {config['APP_NAME']} password(s)",
                context={
                    'email': email,
                    'accounts_html': accounts_html
                }
            )

            if success:
                loggers['app'].info(f"Password reset email sent for {len(users)} user(s) to: {email}")
            else:
                loggers['app'].warning(f"Failed to send password reset email for: {email}")

            return jsonify({'message': 'If your email is registered, you will receive reset instructions'}), 200

        except Exception as e:
            loggers['app'].error(f"Password reset request error: {e}")
            return jsonify({'error': 'Server error processing reset request'}), 500


    @app.route('/auth/reset-password', methods=['POST'])
    def reset_password():
        try:
            data = sanitize_input(request.json or {})
            ip, _ = get_client_info()
            for k in ('token', 'new_password'):
                if k not in data:
                    return jsonify({'error': f'{k} required'}), 400

            valid, msg = check_password_strength(data['new_password'])
            if not valid:
                return jsonify({'error': msg}), 400

            token_data = db_execute(
                'SELECT user_id, expires_at, used FROM reset_tokens WHERE token=?',
                (data['token'],), fetchone=True
            )
            now = int(time.time())
            if not token_data:
                return jsonify({'error': 'Invalid reset token'}), 400
            if token_data['expires_at'] < now:
                db_execute('DELETE FROM reset_tokens WHERE token=?', (data['token'],), commit=True)
                return jsonify({'error': 'Reset token has expired'}), 400
            if token_data['used'] == 1:
                return jsonify({'error': 'This reset token has already been used'}), 400

            user = db_execute(
                'SELECT username, email, password FROM users WHERE id=?',
                (token_data['user_id'],), fetchone=True
            )
            if not user:
                return jsonify({'error': 'User not found'}), 404
            if bcrypt.checkpw(data['new_password'].encode(), user['password']):
                return jsonify({'error': 'New password cannot be the same as current'}), 400

            is_new, _ = check_password_history(token_data['user_id'], data['new_password'])
            if not is_new:
                return jsonify({'error': 'This password has been used recently'}), 400

            hashed = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt())
            db_execute(
                'UPDATE users SET password=?, last_password_change=? WHERE id=?',
                (hashed, now, token_data['user_id']), commit=True
            )
            db_execute('UPDATE reset_tokens SET used=1 WHERE token=?', (data['token'],), commit=True)
            log_security_event(token_data['user_id'], 'PASSWORD_RESET',
                               f"Password reset completed from {ip}", ip)
            db_execute('UPDATE user_sessions '
                       'SET is_valid=0 WHERE user_id=?',
                       (token_data['user_id'],), commit=True)
            send_template_email(
                user['email'],
                'password_changed',
                f"Your {config['APP_NAME']} password has been reset",
                {'username': user['username'],
                 'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 'ip_address': ip}
            )
            return jsonify({'message': 'Password reset successful'}), 200

        except Exception as e:
            loggers['app'].error(f"Password reset error: {e}")
            return jsonify({'error': 'Server error during password reset'}), 500

    @app.route('/auth/profile', methods=['GET'])
    @token_required
    def get_profile():
        try:
            user_id = g.user_id
            user = db_execute(
                '''SELECT username, email, created_at, last_login,
                          login_count, last_password_change, account_status
                   FROM users WHERE id=?''',
                (user_id,), fetchone=True
            )
            if not user:
                return jsonify({'error': 'User not found'}), 404

            sess = db_execute(
                'SELECT COUNT(*) as count FROM user_sessions '
                'WHERE user_id=? AND is_valid=1 AND expires_at>?',
                (user_id, int(time.time())), fetchone=True
            )
            active = sess['count'] if sess else 0

            return jsonify({
                'username': user['username'],
                'email': user['email'],
                'created_at': user['created_at'],
                'last_login': user['last_login'],
                'login_count': user['login_count'],
                'account_status': user['account_status'],
                'last_password_change': user['last_password_change'],
                'active_sessions': active,
                'password_age_days': ((int(time.time()) - user['last_password_change']) // 86400
                                      if user['last_password_change'] else None)
            }), 200

        except Exception as e:
            loggers['app'].error(f"Profile retrieval error: {e}")
            return jsonify({'error': 'Server error retrieving profile'}), 500

    @app.route('/auth/change-password', methods=['POST'])
    @token_required
    def change_password():
        data = sanitize_input(request.json or {})
        for k in ('current_password', 'new_password'):
            if k not in data:
                return jsonify({'error': f'{k} required'}), 400

        user_id = g.user_id
        ip, _ = get_client_info()
        user = db_execute(
            'SELECT password, email, username FROM users WHERE id=?',
            (user_id,), fetchone=True
        )
        if not user or not bcrypt.checkpw(data['current_password'].encode(), user['password']):
            return jsonify({'error': 'Current password incorrect'}), 403

        valid, msg = check_password_strength(data['new_password'])
        if not valid:
            return jsonify({'error': msg}), 400

        is_new, _ = check_password_history(user_id, data['new_password'])
        if not is_new:
            return jsonify({'error': 'Password was used recently'}), 400

        new_hash = bcrypt.hashpw(data['new_password'].encode(), bcrypt.gensalt())
        now = int(time.time())
        db_execute(
            'UPDATE users SET password=?, last_password_change=? WHERE id=?',
            (new_hash, now, user_id), commit=True
        )
        db_execute('UPDATE user_sessions SET is_valid=0 WHERE user_id=?', (user_id,), commit=True)

        log_security_event(user_id, 'PASSWORD_CHANGE',
                           f'Password changed via API from {ip}', ip)
        send_template_email(
            user['email'], 'password_changed',
            f"Your {config['APP_NAME']} password has been changed",
            {'username': user['username'],
             'date': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
             'ip_address': ip}
        )

        return jsonify({'message': 'Password changed successfully'}), 200

    @app.route('/auth/sessions', methods=['GET'])
    @token_required
    def list_sessions():
        user_id = g.user_id
        now = int(time.time())
        rows = db_execute(
            '''SELECT token, created_at, last_active, expires_at, ip_address, user_agent
               FROM user_sessions
               WHERE user_id=? AND is_valid=1 AND expires_at>?''',
            (user_id, now), fetchall=True
        )
        sessions = [dict(r) for r in rows]
        return jsonify({'sessions': sessions}), 200

    @app.route('/auth/sessions/revoke', methods=['POST'])
    @token_required
    def revoke_sessions():
        data = sanitize_input(request.json or {})
        user_id = g.user_id
        current = request.headers.get('Authorization', '').split(' ')[-1]
        if data.get('all_except_current'):
            db_execute(
                'UPDATE user_sessions SET is_valid=0 WHERE user_id=? AND token!=?',
                (user_id, current), commit=True
            )
        elif data.get('token'):
            db_execute(
                'UPDATE user_sessions SET is_valid=0 WHERE user_id=? AND token=?',
                (user_id, data['token']), commit=True
            )
        else:
            return jsonify({'error': 'Must specify all_except_current or token'}), 400

        log_security_event(
            user_id, 'SESSIONS_REVOKED',
            'Sessions revoked via API', get_client_info()[0]
        )
        return jsonify({'message': 'Sessions revoked'}), 200

    @app.route('/auth/admin/users', methods=['GET'])
    @admin_required
    def admin_list_users():
        rows = db_execute(
            '''SELECT id, username, email, account_status, created_at, last_login
               FROM users''',
            fetchall=True
        )
        users = [dict(r) for r in rows]
        return jsonify({'users': users}), 200

    @app.route('/auth/admin/users/<user_id>', methods=['PUT'])
    @admin_required
    def admin_update_user(user_id):
        data = sanitize_input(request.json or {})
        status = data.get('account_status')
        if status not in ('active', 'locked', 'suspended'):
            return jsonify({'error': 'Invalid account_status'}), 400
        db_execute(
            'UPDATE users SET account_status=? WHERE id=?',
            (status, user_id), commit=True
        )
        ip, _ = get_client_info()
        log_security_event(
            user_id, 'ACCOUNT_STATUS_CHANGE',
            f'Status set to {status} by admin', ip
        )
        return jsonify({'message': 'User status updated'}), 200

    @app.route('/auth/admin/security-log', methods=['GET'])
    @admin_required
    def admin_security_log():
        rows = db_execute(
            '''SELECT id, user_id, event_type, description, ip_address, timestamp
               FROM security_events
               ORDER BY timestamp DESC
               LIMIT 1000''',
            (), fetchall=True
        )
        logs = [dict(r) for r in rows]
        return jsonify({'security_log': logs}), 200

    @app.route('/auth/admin/stats', methods=['GET'])
    @admin_required
    def admin_stats():
        user_count = db_execute('SELECT COUNT(*) as count FROM users', fetchone=True)['count']
        active_sessions = db_execute(
            'SELECT COUNT(*) as count FROM user_sessions WHERE is_valid=1 AND expires_at>?',
            (int(time.time()),), fetchone=True
        )['count']
        pool_stats = get_connection_pool_stats()
        return jsonify({
            'user_count': user_count,
            'active_sessions': active_sessions,
            'db_pool': pool_stats
        }), 200


    @app.route('/worlds/status', methods=['GET'])
    def get_worlds_status():
        """
        Returns status and player count for all known worlds.
        """
        # Query all active sessions and join with worlds table (if you have one)
        result = db_execute('''
            SELECT
                world_key,
                COUNT(DISTINCT user_id) as online_players
            FROM
                user_sessions
            WHERE
                is_valid = 1 AND expires_at > ? AND world_key IS NOT NULL
            GROUP BY world_key
        ''', (int(time.time()),), fetchall=True)

        # Optional: If you have a static list of known worlds, join here.
        world_list = []  # You can add static world metadata here if needed
        for row in result:
            world_list.append({
                'world_key': row['world_key'],
                'status': 'Online' if row['online_players'] > 0 else 'Offline',
                'player_count': row['online_players']
            })
        return jsonify(world_list), 200



    @app.route('/worlds/<world_key>/status', methods=['GET'])
    def get_world_status(world_key):
        """
        Returns status and player count for a single world.
        """
        row = db_execute('''
            SELECT
                COUNT(DISTINCT user_id) as online_players
            FROM
                user_sessions
            WHERE
                is_valid = 1 AND expires_at > ? AND world_key = ?
        ''', (int(time.time()), world_key), fetchone=True)

        player_count = row['online_players'] if row else 0

        # If you want to set more rules (e.g., maintenance), adjust "status" logic here
        status = 'Online' if player_count > 0 else 'Offline'
        return jsonify({
            'world_key': world_key,
            'status': status,
            'player_count': player_count
        }), 200



    @app.route('/auth/jwt-info', methods=['GET'])
    def jwt_info():
        """Return JWT configuration information for Coherence"""
        try:
            # Path to the public key
            public_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'public_key.pem')
            
            # Load the public key if it exists
            try:
                with open(public_key_path, 'r') as key_file:
                    public_key = key_file.read()
                
                # Return RSA256 configuration
                return jsonify({
                    'algorithm': 'RS256',
                    'key': public_key,
                    'issuer': config.get('APP_NAME', 'Vespeyr Authentication'),
                    'version': APP_VERSION
                }), 200
            except FileNotFoundError:
                # Fall back to HMAC if RSA isn't configured
                algorithm = config.get("TOKEN_ALGORITHM", "HS256")
                
                # Create a key ID by hashing the secret (don't expose the actual secret)
                key_id = hashlib.sha256(config["JWT_SECRET"].encode()).hexdigest()[:16]
                
                return jsonify({
                    'algorithm': algorithm,
                    'kid': key_id,
                    'issuer': config.get('APP_NAME', 'Vespeyr Authentication'),
                    'version': APP_VERSION
                }), 200
        except Exception as e:
            logging.error(f"JWT info error: {e}")
            return jsonify({'error': 'Internal server error'}), 500

    # Graceful shutdown handler
    def shutdown_handler(signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        os._exit(0)

    if threading.current_thread() is threading.main_thread():
        try:
            signal.signal(signal.SIGTERM, shutdown_handler)
            signal.signal(signal.SIGINT, shutdown_handler)
            logging.info("Registered signal handlers")
        except (ValueError, RuntimeError) as e:
            logging.warning(f"Could not register signal handlers: {e}")



    @app.route('/inventory/<world_key>/<key>/<scene>', methods=['GET'])
    @token_required
    def get_inventory(world_key, key, scene):
        """
        Returns the saved inventory JSON for the authenticated user in the specified world, save_key, and scene.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [InvLoad] user_id={user_id} world_key={world_key} "
            f"save_key={key} scene={scene}"
        )

        inventory_data = db_execute(
            '''
            SELECT ui_data, scene_data
              FROM inventory
             WHERE user_id   = ?
               AND world_key = ?
               AND save_key  = ?
               AND scene     = ?
            ''',
            (user_id, world_key, key, scene),
            fetchone=True
        )

        if not inventory_data:
            app.logger.info(
                f"[{now_utc}] [InvLoad] No row found for user_id={user_id} "
                f"world_key={world_key} save_key={key} scene={scene} -> returning empty"
            )
            return jsonify({'ui_data': '', 'scene_data': ''}), 200

        app.logger.info(
            f"[{now_utc}] [InvLoad] Found row for user_id={user_id} "
            f"world_key={world_key} save_key={key} scene={scene} -> returning data"
        )
        return jsonify({
            'ui_data':    inventory_data['ui_data'],
            'scene_data': inventory_data['scene_data']
        }), 200



    @app.route('/inventory', methods=['POST'])
    @token_required
    def save_inventory():
        """
        Inserts or updates inventory for the authenticated user in the specified world, save_key, and scene.
        Payload must include: 'world_key', 'key', 'scene', 'ui_data', 'scene_data'.
        """
        user_id = g.user_id
        data    = sanitize_input(request.json or {})
        now_utc = datetime.utcnow().isoformat() + "Z"

        # Validate payload
        if not all(k in data for k in ('world_key','key','scene','ui_data','scene_data')):
            app.logger.warning(
                f"[{now_utc}] [InvSave] Missing required fields -> user_id={user_id}"
            )
            return jsonify({'error':'Missing required fields'}), 400

        world_key = data['world_key']
        save_key  = data['key']
        scene     = data['scene']

        app.logger.info(
            f"[{now_utc}] [InvSave] user_id={user_id} world_key={world_key} save_key={save_key} scene={scene}"
        )

        existing = db_execute(
            'SELECT id FROM inventory WHERE user_id=? AND world_key=? AND save_key=? AND scene=?',
            (user_id, world_key, save_key, scene),
            fetchone=True
        )

        timestamp = int(time.time())
        if existing:
            app.logger.info(
                f"[{now_utc}] [InvSave] Updating existing inventory id={existing['id']} "
                f"user_id={user_id} world_key={world_key} save_key={save_key} scene={scene}"
            )
            db_execute(
              '''UPDATE inventory
                 SET ui_data=?, scene_data=?, world_key=?, updated_at=?
                 WHERE id=?''',
              (data['ui_data'], data['scene_data'], world_key, timestamp, existing['id']),
              commit=True
            )
        else:
            app.logger.info(
                f"[{now_utc}] [InvSave] Inserting new inventory for user_id={user_id} "
                f"world_key={world_key} save_key={save_key} scene={scene}"
            )
            db_execute(
              '''INSERT INTO inventory
                 (user_id, save_key, scene, ui_data, scene_data, world_key, created_at, updated_at)
                 VALUES (?,?,?,?,?,?,?,?)''',
              (user_id, save_key, scene,
               data['ui_data'], data['scene_data'], world_key,
               timestamp, timestamp),
              commit=True
            )

        app.logger.info(
            f"[{now_utc}] [InvSave] Inventory saved successfully for user_id={user_id} "
            f"world_key={world_key} save_key={save_key} scene={scene}"
        )
        return jsonify({'message':'Inventory saved successfully'}), 200



    @app.route('/quests/<world_key>/<key>', methods=['GET'])
    @token_required
    def get_quests(world_key, key):
        """
        Returns the saved quest arrays for the authenticated user in the specified world and save_key.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [QuestsLoad] user_id={user_id} world_key={world_key} save_key={key}"
        )

        quest_data = db_execute(
            '''
            SELECT active_quests,
                   completed_quests,
                   failed_quests
              FROM quests
             WHERE user_id   = ?
               AND world_key = ?
               AND save_key  = ?
            ''',
            (user_id, world_key, key),
            fetchone=True
        )

        if not quest_data:
            app.logger.info(
                f"[{now_utc}] [QuestsLoad] No row found for user_id={user_id} "
                f"world_key={world_key} save_key={key} -> returning empty"
            )
            return jsonify({
                'active_quests':    '',
                'completed_quests': '',
                'failed_quests':    ''
            }), 200

        app.logger.info(
            f"[{now_utc}] [QuestsLoad] Found row for user_id={user_id} "
            f"world_key={world_key} save_key={key} -> returning data"
        )
        return jsonify({
            'active_quests':    quest_data['active_quests'],
            'completed_quests': quest_data['completed_quests'],
            'failed_quests':    quest_data['failed_quests']
        }), 200



    @app.route('/quests', methods=['POST'])
    @token_required
    def save_quests():
        """
        Inserts or updates a quest-tracking JSON for the authenticated user in the specified world and save_key.
        Payload must include: 'world_key', 'key', 'active_quests', 'completed_quests', 'failed_quests'.
        """
        user_id = g.user_id
        data    = sanitize_input(request.json or {})
        now_utc = datetime.utcnow().isoformat() + "Z"

        required = ('world_key', 'key', 'active_quests', 'completed_quests', 'failed_quests')
        if not all(k in data for k in required):
            app.logger.warning(
                f"[{now_utc}] [QuestsSave] Missing required fields -> user_id={user_id}"
            )
            return jsonify({'error': 'Missing required fields'}), 400

        world_key = data['world_key']
        save_key  = data['key']

        app.logger.info(
            f"[{now_utc}] [QuestsSave] user_id={user_id} world_key={world_key} save_key={save_key}"
        )

        existing = db_execute(
            '''
            SELECT id
              FROM quests
             WHERE user_id   = ?
               AND world_key = ?
               AND save_key  = ?
            ''',
            (user_id, world_key, save_key),
            fetchone=True
        )

        timestamp = int(time.time())
        if existing:
            app.logger.info(
                f"[{now_utc}] [QuestsSave] Updating existing quest row id={existing['id']} "
                f"user_id={user_id} world_key={world_key} save_key={save_key}"
            )
            db_execute(
                '''
                UPDATE quests
                   SET active_quests    = ?,
                       completed_quests = ?,
                       failed_quests    = ?,
                       updated_at       = ?
                 WHERE id = ?
                ''',
                (
                    data['active_quests'],
                    data['completed_quests'],
                    data['failed_quests'],
                    timestamp,
                    existing['id']
                ),
                commit=True
            )
        else:
            app.logger.info(
                f"[{now_utc}] [QuestsSave] Inserting new quest row for user_id={user_id} "
                f"world_key={world_key} save_key={save_key}"
            )
            db_execute(
                '''
                INSERT INTO quests
                    (user_id, world_key, save_key,
                     active_quests, completed_quests, failed_quests,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    user_id,
                    world_key,
                    save_key,
                    data['active_quests'],
                    data['completed_quests'],
                    data['failed_quests'],
                    timestamp,
                    timestamp
                ),
                commit=True
            )

        app.logger.info(
            f"[{now_utc}] [QuestsSave] Quests saved successfully for user_id={user_id} "
            f"world_key={world_key} save_key={save_key}"
        )
        return jsonify({'message': 'Quests saved successfully'}), 200



    @app.route('/stats/<world_key>/<key>', methods=['GET'])
    @token_required
    def get_stats(world_key, key):
        """
        Returns the saved stats JSON for a given user/world/key.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        # Detailed debug log including timestamp, user, world, and save_key
        app.logger.info(
            f"[{now_utc}] [StatsLoad] user_id={user_id} world_key={world_key} save_key={key}"
        )

        stats_data = db_execute(
            '''
            SELECT stats_json
              FROM stats
             WHERE user_id   = ?
               AND world_key = ?
               AND save_key  = ?
            ''',
            (user_id, world_key, key),
            fetchone=True
        )

        if not stats_data:
            app.logger.info(
                f"[{now_utc}] [StatsLoad] No row found for user_id={user_id}, "
                f"world_key={world_key}, save_key={key} -> returning empty"
            )
            return jsonify({'stats_json': ''}), 200

        app.logger.info(
            f"[{now_utc}] [StatsLoad] Found row for user_id={user_id}, "
            f"world_key={world_key}, save_key={key} -> returning JSON"
        )
        return jsonify({'stats_json': stats_data['stats_json']}), 200


    @app.route('/api/user/preferences', methods=['GET'])
    @jwt_required()
    def get_preferences():
        user_id = get_jwt_identity()
        user = get_user_by_id(user_id)
        if not user:
            return jsonify({'msg': 'User not found'}), 404
        return jsonify({
            'rememberMe':         bool(user.remember_me),
            'autoLoginServer':    bool(user.auto_login_server),
            'autoLoginCharacter': bool(user.auto_login_character),
            'lastServerId':       user.last_server_id      or '',
            'lastCharacterName':  user.last_character_name or ''
        }), 200


    @app.route('/api/user/preferences', methods=['PUT'])
    @jwt_required()
    def update_preferences():
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        # validate presence
        for field in ('rememberMe','autoLoginServer','autoLoginCharacter'):
            if field not in data:
                return jsonify({'msg': f'Missing field {field}'}), 400
        update_user(
            user_id,
            remember_me=bool(data['rememberMe']),
            auto_login_server=bool(data['autoLoginServer']),
            auto_login_character=bool(data['autoLoginCharacter'])
        )
        return jsonify(success=True), 200


    @app.route('/api/user/preferences/last', methods=['POST'])
    @jwt_required()
    def update_last():
        user_id = get_jwt_identity()
        data = request.get_json(force=True)
        updates = {}
        if 'lastServerId' in data:
            updates['last_server_id'] = data['lastServerId'] or None
        if 'lastCharacterName' in data:
            updates['last_character_name'] = data['lastCharacterName'] or None
        if not updates:
            return jsonify({'msg': 'No fields to update'}), 400
        update_user(user_id, **updates)
        return jsonify(success=True), 200


    @app.route('/stats', methods=['POST'])
    @limiter.exempt
    @token_required
    def save_stats():
        """
        Create or update stats JSON for the authenticated user in the specified world.
        """
        user_id = g.user_id
        data    = sanitize_input(request.json or {})
        now_utc = datetime.utcnow().isoformat() + "Z"

        # ——— Log the raw payload for inspection ——————————————————————————————————————————
        app.logger.info(f"[{now_utc}] [StatsSave] Raw payload keys: {list(data.keys())!r}; full payload: {data!r}")
        # ————————————————————————————————————————————————————————————————————————————————

        # 1) Validate required fields
        if not all(k in data for k in ('world_key', 'key', 'stats_json')):
            app.logger.info(
                f"[{now_utc}] [StatsSave] Missing fields -> user_id={user_id}"
            )
            return jsonify({'error': 'Missing required fields'}), 400

        world_key  = data['world_key']
        save_key   = data['key']
        stats_json = data['stats_json']

        # 2) Entry‐point log
        app.logger.info(
            f"[{now_utc}] [StatsSave] user_id={user_id} world_key={world_key} save_key={save_key}"
        )

        # 3) Ensure the user still exists
        user_check = db_execute(
            'SELECT id FROM users WHERE id = ?', (user_id,), fetchone=True
        )
        if not user_check:
            app.logger.warning(
                f"[{now_utc}] [StatsSave] Invalid user session: user_id={user_id}"
            )
            return jsonify({'error': 'Invalid user session. Please log in again.'}), 401

        # 4) Look for an existing row
        existing = db_execute(
            'SELECT id FROM stats WHERE user_id = ? AND world_key = ? AND save_key = ?',
            (user_id, world_key, save_key),
            fetchone=True
        )

        ts = int(time.time())
        try:
            if existing:
                app.logger.info(
                    f"[{now_utc}] [StatsSave] Updating existing stats id={existing['id']}"
                )
                db_execute(
                    'UPDATE stats SET stats_json = ?, updated_at = ? WHERE id = ?',
                    (stats_json, ts, existing['id']),
                    commit=True
                )
            else:
                app.logger.info(
                    f"[{now_utc}] [StatsSave] Inserting new stats row for user_id={user_id}, "
                    f"world_key={world_key}, save_key={save_key}"
                )
                db_execute(
                    '''INSERT INTO stats
                          (user_id, world_key, save_key, stats_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (user_id, world_key, save_key, stats_json, ts, ts),
                    commit=True
                )

            app.logger.info(
                f"[{now_utc}] [StatsSave] Successfully saved stats for user_id={user_id}, "
                f"world_key={world_key}, save_key={save_key}"
            )
            return jsonify({'message': 'Stats saved successfully'}), 200

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [StatsSave] Database error for user_id={user_id}, "
                f"world_key={world_key}, save_key={save_key}: {e}"
            )
            return jsonify({'error': 'Failed to save stats due to a database error'}), 500





    # 1a) List all characters for this user+world
    @app.route("/characters/<world_key>/<path:account_key>", methods=["GET"])
    def list_characters(world_key, account_key):
        """
        List all characters for this authenticated user in the specified world.
        account_key is the “save_key” / account identifier (not used in the query above).
        """
        user_id = get_current_user_id()
        now_utc = datetime.utcnow().isoformat() + "Z"

        # Detailed log
        app.logger.info(
            f"[{now_utc}] [CharList] user_id={user_id} world_key={world_key} account_key={account_key}"
        )

        rows = db_execute(
            "SELECT character_name, character_data FROM characters "
            " WHERE user_id = ? AND world_key = ?",
            (user_id, world_key),
            fetchall=True
        )

        characters = []
        for r in rows:
            data = json.loads(r["character_data"] or "{}")
            data["CharacterName"] = r["character_name"]
            characters.append(data)

        app.logger.info(
            f"[{now_utc}] [CharList] Found {len(characters)} character(s) "
            f"for user_id={user_id} world_key={world_key}"
        )
        return jsonify(characters), 200


    # 1b) Create or update a single character
    @app.route("/characters/<world_key>/<path:account_key>", methods=["POST"])
    def create_or_update_character(world_key, account_key):
        """
        Create a new character or update an existing one (by name) for the authenticated user in a given world.
        Returns 200 on success.
        """
        user_id = get_current_user_id()
        payload = request.get_json(force=True)
        now_utc = datetime.utcnow().isoformat() + "Z"

        if not payload or "CharacterName" not in payload:
            app.logger.warning(
                f"[{now_utc}] [CharSave] Missing CharacterName in payload -> user_id={user_id}"
            )
            abort(400, "Must supply JSON with CharacterName field")

        character_name = payload["CharacterName"]
        data_json      = json.dumps(payload)
        ts             = int(time.time())

        app.logger.info(
            f"[{now_utc}] [CharSave] user_id={user_id} world_key={world_key} "
            f"character_name={character_name} account_key={account_key}"
        )

        db_execute(
            """
            INSERT INTO characters
              (user_id, world_key, character_name, character_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, world_key, character_name)
            DO UPDATE SET
              character_data = excluded.character_data,
              updated_at    = excluded.updated_at
            """,
            (user_id, world_key, character_name, data_json, ts, ts),
            commit=True
        )

        app.logger.info(
            f"[{now_utc}] [CharSave] Successfully created/updated character_name={character_name} "
            f"for user_id={user_id} world_key={world_key}"
        )
        return ("", 200)


    # 1c) Delete a character row by path
    @app.route(
        "/characters/<world_key>/<path:account_key>/<character_name>",
        methods=["DELETE"],
        endpoint="delete_character_by_path"
    )
    @token_required
    @limiter.limit("30 per minute")
    def delete_character_by_path(world_key, account_key, character_name):
        """
        Delete a character (by name) for the authenticated user in the specified world.
        Returns 204 on success.
        """
        user_id = get_current_user_id()
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [CharDelete] user_id={user_id} world_key={world_key} "
            f"character_name={character_name} account_key={account_key}"
        )

        try:
            existing = db_execute(
                "SELECT id FROM characters "
                " WHERE user_id = ? AND world_key = ? AND character_name = ?",
                (user_id, world_key, character_name),
                fetchone=True
            )

            if not existing:
                app.logger.warning(
                    f"[{now_utc}] [CharDelete] Not found or access denied: user_id={user_id}, "
                    f"world_key={world_key}, character_name={character_name}"
                )
                return jsonify({'error': 'Character not found or access denied'}), 404

            db_execute(
                "DELETE FROM characters "
                " WHERE id = ?",
                (existing['id'],),
                commit=True
            )

            app.logger.info(
                f"[{now_utc}] [CharDelete] Deleted character id={existing['id']} "
                f"user_id={user_id} world_key={world_key} character_name={character_name}"
            )
            return ("", 204)

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [CharDelete] Error deleting character_name={character_name} "
                f"for user_id={user_id} world_key={world_key}: {e}"
            )
            return jsonify({'error': 'Failed to delete character due to a database error'}), 500


    # ──────────────────────────────────────────────────────────────────────────────
    # List characters by world (GET)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/characters/<world_key>', methods=['GET'])
    @token_required
    @limiter.limit("60 per minute")
    def get_characters_by_world(world_key):
        """
        Returns a list of characters for the authenticated user in the specified world.
        Each entry includes the stored characterId.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [CharListByWorld] user_id={user_id} world_key={world_key}"
        )

        try:
            rows = db_execute(
                'SELECT character_id, character_data '
                'FROM characters '
                'WHERE user_id = ? AND world_key = ?',
                (user_id, world_key),
                fetchall=True
            )

            characters = []
            for r in rows or []:
                parsed = json.loads(r['character_data'])
                parsed['CharacterId'] = r['character_id']
                characters.append(parsed)

            app.logger.info(
                f"[{now_utc}] [CharListByWorld] Found {len(characters)} character(s) "
                f"for user_id={user_id} world_key={world_key}"
            )
            return jsonify(characters), 200

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [CharListByWorld] Error loading characters "
                f"user_id={user_id} world_key={world_key}: {e}"
            )
            return jsonify({'error': 'Failed to load characters'}), 500




    # ──────────────────────────────────────────────────────────────────────────────
    # List all characters (GET)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/characters', methods=['GET'])
    @token_required
    @limiter.limit("60 per minute")
    def get_characters():
        """
        Returns a list of all characters for the authenticated user.
        Optionally filtered by world_key (query parameter).
        Each entry includes its stored characterId.
        """
        user_id   = g.user_id
        world_key = request.args.get('world_key')
        now_utc   = datetime.utcnow().isoformat() + "Z"

        if world_key:
            app.logger.info(
                f"[{now_utc}] [CharListAll] user_id={user_id} world_key={world_key}"
            )
        else:
            app.logger.info(
                f"[{now_utc}] [CharListAll] user_id={user_id} (no world filter)"
            )

        try:
            if world_key:
                rows = db_execute(
                    'SELECT character_id, character_data '
                    'FROM characters '
                    'WHERE user_id = ? AND world_key = ?',
                    (user_id, world_key),
                    fetchall=True
                )
            else:
                rows = db_execute(
                    'SELECT character_id, character_data '
                    'FROM characters '
                    'WHERE user_id = ?',
                    (user_id,),
                    fetchall=True
                )

            characters = []
            for r in rows or []:
                parsed = json.loads(r['character_data'])
                parsed['CharacterId'] = r['character_id']
                characters.append(parsed)

            app.logger.info(
                f"[{now_utc}] [CharListAll] Returned {len(characters)} character(s) "
                f"for user_id={user_id} world_filter={world_key or 'none'}"
            )
            return jsonify(characters), 200

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [CharListAll] Error loading characters for user_id={user_id} "
                f"world_key={world_key}: {e}"
            )
            return jsonify({'error': 'Failed to load characters'}), 500

  



    # ──────────────────────────────────────────────────────────────────────────────
    # Character save per-world (POST)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/characters', methods=['POST'])
    @token_required
    @limiter.limit("30 per minute")
    def save_character():
        """
        Inserts or updates a character JSON blob under the authenticated user and specified world_key.
        Expects JSON payload:
          {
            "world_key": "<world>",
            "character_data": "<full JSON string>"
          }
        Responds with the assigned characterId.
        """
        user_id = g.user_id
        data    = sanitize_input(request.json or {})
        now_utc = datetime.utcnow().isoformat() + "Z"

        # Validate payload
        if not all(k in data for k in ('world_key', 'character_data')):
            app.logger.warning(
                f"[{now_utc}] [CharSave2] Missing world_key or character_data -> user_id={user_id}"
            )
            return jsonify({'error': 'Missing world_key or character_data'}), 400

        try:
            parsed         = json.loads(data['character_data'])
            character_name = parsed.get('CharacterName')
        except Exception:
            app.logger.warning(
                f"[{now_utc}] [CharSave2] Invalid JSON in character_data -> user_id={user_id}"
            )
            return jsonify({'error': 'Invalid JSON in character_data'}), 400

        if not character_name:
            app.logger.warning(
                f"[{now_utc}] [CharSave2] character_data missing CharacterName -> user_id={user_id}"
            )
            return jsonify({'error': 'character_data must include CharacterName'}), 400

        world_key = data['world_key']

        app.logger.info(
            f"[{now_utc}] [CharSave2] user_id={user_id} world_key={world_key} "
            f"character_name={character_name}"
        )

        # Check for existing record (pull existing character_id if present)
        existing = db_execute(
            'SELECT id, character_id FROM characters '
            'WHERE user_id = ? AND world_key = ? AND character_name = ?',
            (user_id, world_key, character_name),
            fetchone=True
        )

        ts = int(time.time())
        if existing:
            # Update existing
            app.logger.info(
                f"[{now_utc}] [CharSave2] Updating existing character id={existing['id']} "
                f"for user_id={user_id} world_key={world_key} name={character_name}"
            )
            db_execute(
                'UPDATE characters '
                'SET character_data = ?, updated_at = ? '
                'WHERE id = ?',
                (data['character_data'], ts, existing['id']),
                commit=True
            )
            character_id = existing['character_id']
        else:
            # Insert new with a fresh UUID
            character_id = str(uuid.uuid4())
            app.logger.info(
                f"[{now_utc}] [CharSave2] Inserting new character id={character_id} "
                f"user_id={user_id} world_key={world_key} name={character_name}"
            )
            db_execute(
                'INSERT INTO characters '
                '(user_id, world_key, character_id, character_name, character_data, created_at, updated_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (user_id, world_key, character_id, character_name,
                 data['character_data'], ts, ts),
                commit=True
            )

        app.logger.info(
            f"[{now_utc}] [CharSave2] Character saved successfully: id={character_id} "
            f"user_id={user_id} world_key={world_key} name={character_name}"
        )
        return jsonify({
            'message': 'Character saved successfully',
            'characterId': character_id
        }), 200



    from werkzeug.exceptions import HTTPException

    @app.errorhandler(Exception)
    def handle_unhandled_exception(e):
        """Global exception handler to prevent server crashes"""
        if isinstance(e, HTTPException):
            # Pass through HTTP errors (will be handled by Flask)
            return e
    
        # Only log unexpected errors
        logging.error(f"Unhandled exception: {str(e)}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'The requested resource was not found'}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({'error': 'The method is not allowed for this endpoint'}), 405

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({'error': 'Bad request - invalid data provided'}), 400



    # ──────────────────────────────────────────────────────────────────────────────
    # Delete character (POST)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/characters/delete', methods=['POST'])
    @token_required
    @limiter.limit("30 per minute")
    def delete_character():
        """
        Deletes a character for the authenticated user in the specified world.
        Expects JSON payload either:
          { "world_key": "<world>", "character_name": "<name>" }
        or:
          { "world_key": "<world>", "characterId": "<UUID>" }
        """
        user_id = g.user_id
        data    = sanitize_input(request.json or {})
        now_utc = datetime.utcnow().isoformat() + "Z"

        # Validate payload
        if not data.get('world_key') or not (data.get('character_name') or data.get('characterId')):
            app.logger.warning(
                f"[{now_utc}] [CharDelete2] Missing world_key or character_name/characterId -> user_id={user_id}"
            )
            return jsonify({'error': 'Missing world_key and either character_name or characterId'}), 400

        world_key      = data['world_key']
        character_id   = data.get('characterId')
        character_name = data.get('character_name')

        # Detailed log for deletion attempt
        if character_id:
            app.logger.info(
                f"[{now_utc}] [CharDelete2] user_id={user_id} world_key={world_key} by characterId={character_id}"
            )
        else:
            app.logger.info(
                f"[{now_utc}] [CharDelete2] user_id={user_id} world_key={world_key} by character_name={character_name}"
            )

        try:
            # Fetch the row to ensure it belongs to this user
            if character_id:
                existing = db_execute(
                    'SELECT id FROM characters '
                    'WHERE user_id = ? AND world_key = ? AND character_id = ?',
                    (user_id, world_key, character_id),
                    fetchone=True
                )
            else:
                existing = db_execute(
                    'SELECT id FROM characters '
                    'WHERE user_id = ? AND world_key = ? AND character_name = ?',
                    (user_id, world_key, character_name),
                    fetchone=True
                )

            if not existing:
                app.logger.warning(
                    f"[{now_utc}] [CharDelete2] Not found/access denied: user_id={user_id} "
                    f"world_key={world_key} "
                    f"{'(by id)' if character_id else '(by name)'}"
                )
                return jsonify({'error': 'Character not found or access denied'}), 404

            # Perform deletion
            db_execute(
                'DELETE FROM characters WHERE id = ?',
                (existing['id'],),
                commit=True
            )

            app.logger.info(
                f"[{now_utc}] [CharDelete2] Deleted character id={existing['id']} "
                f"user_id={user_id} world_key={world_key}"
            )
            return jsonify({'message': 'Character deleted successfully'}), 200

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [CharDelete2] Error deleting character for user_id={user_id} "
                f"world_key={world_key}: {e}"
            )
            return jsonify({'error': 'Failed to delete character due to a database error'}), 500





    @app.route('/auth/admin/config', methods=['POST'])
    @admin_required
    def admin_update_config():
        """Update a single configuration setting"""
        data = sanitize_input(request.json or {})
        if not data.get('setting'):
            return jsonify({'error': 'setting required'}), 400
        
        setting = data['setting']
        value = data.get('value')
    
        # Only allow updating certain settings through the API
        allowed_settings = ['FORCE_JWT_ALGORITHM', 'JWT_AUDIENCE', 'JWT_ISSUER']
        if setting not in allowed_settings:
            return jsonify({'error': f'Setting {setting} cannot be updated through API'}), 403
    
        # Update the configuration
        config[setting] = value
        save_config(config)
    
        # Log the change
        ip, _ = get_client_info()
        log_security_event(
            g.user_id, 'CONFIG_CHANGED',
            f"Configuration setting {setting} changed to: {value}",
            ip, 'medium'
        )
    
        return jsonify({'message': f'Configuration setting {setting} updated successfully'}), 200

    @app.route('/auth/admin/generate-keys', methods=['POST'])
    @admin_required
    def admin_generate_keys():
        """Generate new RSA key pair for JWT signing"""
        from auth import ensure_rsa_keys_exist
    
        # Generate new keys (overwriting existing ones)
        try:
            if ensure_rsa_keys_exist(force=True):
                # Log the action
                ip, _ = get_client_info()
                log_security_event(
                    g.user_id, 'KEYS_GENERATED',
                    f"New RSA key pair generated for JWT signing",
                    ip, 'high'
                )
                return jsonify({'message': 'New RSA key pair generated successfully'}), 200
            else:
                return jsonify({'error': 'Failed to generate new RSA keys'}), 500
        except Exception as e:
            logging.error(f"Failed to generate new RSA keys: {str(e)}")
            return jsonify({'error': f'Error generating keys: {str(e)}'}), 500
    # ──────────────────────────────────────────────────────────────────────────────
    # Get a single character by CharacterId (for detail view, edit, or Unity compatibility)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/characters/by-id/<character_id>', methods=['GET'])
    @token_required
    def get_character_by_id(character_id):
        """
        Return one character (full JSON object) for the authenticated user by CharacterId.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [CharFetchById] user_id={user_id} character_id={character_id}"
        )

        row = db_execute(
            'SELECT character_data FROM characters WHERE user_id = ? AND character_id = ?',
            (user_id, character_id),
            fetchone=True
        )
        if not row:
            app.logger.warning(
                f"[{now_utc}] [CharFetchById] Character not found for user_id={user_id} character_id={character_id}"
            )
            return jsonify({'error': 'Character not found'}), 404

        parsed = json.loads(row['character_data'])
        parsed['CharacterId'] = character_id

        app.logger.info(
            f"[{now_utc}] [CharFetchById] Returning character_id={character_id} for user_id={user_id}"
        )
        return jsonify(parsed), 200


    # ──────────────────────────────────────────────────────────────────────────────
    # DELETE: Remove inventory by world, key, scene (optional for DGV/Unity)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/inventory/<world_key>/<key>/<scene>', methods=['DELETE'])
    @token_required
    def delete_inventory(world_key, key, scene):
        """
        Delete inventory for the authenticated user by world_key, save_key, and scene.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [InvDelete] user_id={user_id} world_key={world_key} save_key={key} scene={scene}"
        )

        try:
            existing = db_execute(
                'SELECT id FROM inventory WHERE user_id = ? AND world_key = ? AND save_key = ? AND scene = ?',
                (user_id, world_key, key, scene),
                fetchone=True
            )
            if not existing:
                app.logger.warning(
                    f"[{now_utc}] [InvDelete] No inventory row found for user_id={user_id} "
                    f"world_key={world_key} save_key={key} scene={scene}"
                )
                return jsonify({'error': 'Inventory not found'}), 404

            db_execute(
                'DELETE FROM inventory WHERE id = ?',
                (existing['id'],),
                commit=True
            )
            app.logger.info(
                f"[{now_utc}] [InvDelete] Deleted inventory id={existing['id']} "
                f"user_id={user_id} world_key={world_key} save_key={key} scene={scene}"
            )
            return jsonify({'message': 'Inventory deleted successfully'}), 200

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [InvDelete] Error deleting inventory for user_id={user_id} "
                f"world_key={world_key} save_key={key} scene={scene}: {e}"
            )
            return jsonify({'error': 'Failed to delete inventory due to a database error'}), 500


    # ──────────────────────────────────────────────────────────────────────────────
    # DELETE: Remove stats by world and key (optional for DGV/Unity)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/stats/<world_key>/<key>', methods=['DELETE'])
    @token_required
    def delete_stats(world_key, key):
        user_id = g.user_id
        db_execute(
            'DELETE FROM stats WHERE user_id = ? AND world_key = ? AND save_key = ?',
            (user_id, world_key, key),
            commit=True
        )
        return jsonify({'message': 'Stats deleted successfully'}), 200

    # ──────────────────────────────────────────────────────────────────────────────
    # DELETE: Remove quests by world and key (optional for DGV/Unity)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/quests/<world_key>/<key>', methods=['DELETE'])
    @token_required
    def delete_quests(world_key, key):
        """
        Delete all quest entries for the authenticated user under world_key and save_key.
        """
        user_id = g.user_id
        now_utc = datetime.utcnow().isoformat() + "Z"

        app.logger.info(
            f"[{now_utc}] [QuestsDelete] user_id={user_id} world_key={world_key} save_key={key}"
        )

        try:
            existing = db_execute(
                'SELECT id FROM quests WHERE user_id = ? AND world_key = ? AND save_key = ?',
                (user_id, world_key, key),
                fetchone=True
            )
            if not existing:
                app.logger.warning(
                    f"[{now_utc}] [QuestsDelete] No quest row found for user_id={user_id} "
                    f"world_key={world_key} save_key={key}"
                )
                return jsonify({'error': 'Quests not found'}), 404

            db_execute(
                'DELETE FROM quests WHERE id = ?',
                (existing['id'],),
                commit=True
            )
            app.logger.info(
                f"[{now_utc}] [QuestsDelete] Deleted quest id={existing['id']} "
                f"user_id={user_id} world_key={world_key} save_key={key}"
            )
            return jsonify({'message': 'Quests deleted successfully'}), 200

        except Exception as e:
            app.logger.error(
                f"[{now_utc}] [QuestsDelete] Error deleting quests for user_id={user_id} "
                f"world_key={world_key} save_key={key}: {e}"
            )
            return jsonify({'error': 'Failed to delete quests due to a database error'}), 500


    # ──────────────────────────────────────────────────────────────────────────────
    # (Optional) DELETE: Remove a character directly by CharacterId (as an alternative to /characters/delete POST)
    # ──────────────────────────────────────────────────────────────────────────────
    @app.route('/characters/<world_key>/<character_id>', methods=['DELETE'])
    @token_required
    def delete_character_by_id(world_key, character_id):
        """
        Delete a character for the authenticated user by world_key and CharacterId.
        """
        user_id = g.user_id
        # Check the character exists
        row = db_execute(
            'SELECT id FROM characters WHERE user_id = ? AND world_key = ? AND character_id = ?',
            (user_id, world_key, character_id),
            fetchone=True
        )
        if not row:
            return jsonify({'error': 'Character not found or access denied'}), 404

        db_execute(
            'DELETE FROM characters WHERE id = ?',
            (row['id'],),
            commit=True
        )
        return jsonify({'message': 'Character deleted successfully'}), 200


    @app.route('/join_world', methods=['POST'])
    @token_required
    def join_world():
        """
        Sets the current world_key in the user's session and
        activates the specified character in that world.
        Body must include:
          {
            "world_key": "<world>",
            "character_id": "<UUID>"
          }
        Logs both user_id and character_name when joining.
        """
        user_id = g.user_id
        data    = sanitize_input(request.json or {})
        now_utc = datetime.utcnow().isoformat() + "Z"
        current_ts = int(time.time())

        world_key     = data.get('world_key')
        character_id  = data.get('character_id')

        if not world_key or not character_id:
            return jsonify({'error': 'world_key and character_id are required'}), 400

        # 1) Verify that the character exists and belongs to this user in that world
        char_row = db_execute(
            '''
            SELECT character_name
              FROM characters
             WHERE user_id = ?
               AND world_key = ?
               AND character_id = ?
            ''',
            (user_id, world_key, character_id),
            fetchone=True
        )
        if not char_row:
            return jsonify({'error': 'Character not found or access denied'}), 404

        character_name = char_row['character_name']

        # 2) Deactivate any previously active character in this world for this user
        db_execute(
            '''
            UPDATE characters
               SET is_active = 0
             WHERE user_id = ?
               AND world_key = ?
               AND is_active = 1
            ''',
            (user_id, world_key),
            commit=True
        )

        # 3) Activate the new character
        db_execute(
            '''
            UPDATE characters
               SET is_active = 1
             WHERE user_id = ?
               AND world_key = ?
               AND character_id = ?
            ''',
            (user_id, world_key, character_id),
            commit=True
        )

        # 4) Log who (user_id + character_name) joined which world
        app.logger.info(
            f"[{now_utc}] [JoinWorld] user_id={user_id} "
            f"character_id={character_id} "
            f"character_name={character_name} "
            f"joined world_key={world_key}"
        )

        # 5) Update the user_sessions table to set new world_key
        db_execute(
            '''
            UPDATE user_sessions
               SET world_key = ?
             WHERE user_id = ?
               AND is_valid = 1
               AND expires_at > ?
            ''',
            (world_key, user_id, current_ts),
            commit=True
        )

        return jsonify({'message': f'Joined world {world_key} as {character_name}'}), 200


    # Helper to identify table and column from the save_key
    def _get_table_column(save_key: str):
        if save_key.endswith(".Stats"):
            return "stats", "stats_json"
        elif save_key == "StatSystemSavedKeys":
            return "character_data", "saved_keys"
        elif save_key.endswith(".ActiveQuests"):
            return "quests", "active_quests"
        elif save_key.endswith(".CompletedQuests"):
            return "quests", "completed_quests"
        elif save_key.endswith(".FailedQuests"):
            return "quests", "failed_quests"
        elif save_key.endswith(".UI"):
            return "inventory", "ui_data"
        elif "." in save_key:
            return "inventory", "scene_data"
        elif save_key == "":
            return None, None  # For dynamic key listing
        else:
            return None, None  # Invalid key




    @app.route("/data/<world_key>/<path:save_key>", methods=["GET", "POST"])
    def handle_data(world_key, save_key):
        user_id = get_current_user_id()
        table, column = _get_table_column(save_key)

        if save_key == "":
            # List all save keys for this user/world
            results = db_query_all(
                """
                SELECT save_key FROM stats WHERE user_id = ? AND world_key = ?
                UNION
                SELECT save_key FROM quests WHERE user_id = ? AND world_key = ?
                UNION
                SELECT save_key FROM inventory WHERE user_id = ? AND world_key = ?
                """,
                (user_id, world_key, user_id, world_key, user_id, world_key)
            )
            keys = [r["save_key"] for r in results] if results else []
            return jsonify(keys)

        if table is None:
            logging.warning(f"Invalid save_key received: {save_key}")
            abort(404)

        if request.method == "POST":
            payload = request.get_data(as_text=True) or ""
            now = int(time.time())

            if table == "character_data":
                character_id = save_key
                db_execute(
                    """
                    INSERT OR REPLACE INTO character_data (world_key, character_id, character_data)
                    VALUES (?, ?, ?)
                    """,
                    (world_key, character_id, payload),
                    commit=True
                )
            elif table == "inventory":
                scene = (
                    "UI" if save_key.endswith(".UI") else
                    (save_key.split(".", 1)[1] if "." in save_key else "default")
                )

                if column == "ui_data":
                    db_execute(
                        """
                        INSERT OR IGNORE INTO inventory 
                        (user_id, world_key, save_key, scene, ui_data, scene_data, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, '', ?, ?)
                        """,
                        (user_id, world_key, save_key, scene, payload, now, now),
                        commit=False
                    )
                    db_execute(
                        """
                        UPDATE inventory 
                        SET ui_data = ?, updated_at = ?
                        WHERE user_id = ? AND world_key = ? AND save_key = ? AND scene = ?
                        """,
                        (payload, now, user_id, world_key, save_key, scene),
                        commit=True
                    )
                else:  # scene_data
                    db_execute(
                        """
                        INSERT OR IGNORE INTO inventory 
                        (user_id, world_key, save_key, scene, ui_data, scene_data, created_at, updated_at)
                        VALUES (?, ?, ?, ?, '', ?, ?, ?)
                        """,
                        (user_id, world_key, save_key, scene, payload, now, now),
                        commit=False
                    )
                    db_execute(
                        """
                        UPDATE inventory 
                        SET scene_data = ?, updated_at = ?
                        WHERE user_id = ? AND world_key = ? AND save_key = ? AND scene = ?
                        """,
                        (payload, now, user_id, world_key, save_key, scene),
                        commit=True
                    )
            else:
                db_execute(
                    f"""
                    INSERT OR IGNORE INTO {table}
                    (user_id, world_key, save_key, {column}, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, world_key, save_key, payload, now, now),
                    commit=False
                )
                db_execute(
                    f"""
                    UPDATE {table}
                    SET {column} = ?, updated_at = ?
                    WHERE user_id = ? AND world_key = ? AND save_key = ?
                    """,
                    (payload, now, user_id, world_key, save_key),
                    commit=True
                )

            return ("", 200)

        # GET branch
        if table == "character_data":
            character_id = save_key
            row = db_query_one(
                "SELECT character_data FROM character_data WHERE world_key = ? AND character_id = ?",
                (world_key, character_id)
            )
        elif table == "inventory":
            scene = (
                "UI" if save_key.endswith(".UI") else
                (save_key.split(".", 1)[1] if "." in save_key else "default")
            )
            row = db_query_one(
                f"""
                SELECT {column} FROM inventory
                WHERE user_id = ? AND world_key = ? AND save_key = ? AND scene = ?
                """,
                (user_id, world_key, save_key, scene)
            )
        else:
            row = db_query_one(
                f"""
                SELECT {column} FROM {table}
                WHERE user_id = ? AND world_key = ? AND save_key = ?
                """,
                (user_id, world_key, save_key)
            )

        if not row:
            empty = "[]" if column in ("stats_json", "active_quests", "completed_quests", "failed_quests") else ""
            return empty, 200, {"Content-Type": "application/json"}

        return row[column], 200, {"Content-Type": "application/json"}








    return app
    
    

# Instantiate the app
app = create_app()

if __name__ == '__main__':
    if config.get("DEBUG_MODE", False):
        app.run(
            host=config["HOST"],
            port=config["PORT"],
            debug=True,
            use_reloader=True
        )
    else:
        try:
            import gunicorn.app.base
            class StandaloneApplication(gunicorn.app.base.BaseApplication):
                def __init__(self, app, options=None):
                    self.options = options or {}
                    self.application = app
                    super().__init__()
                def load_config(self):
                    for key, value in self.options.items():
                        self.cfg.set(key.lower(), value)
                def load(self):
                    return self.application

            options = {
                'bind': f"{config['HOST']}:{config['PORT']}",
                'workers': config.get("WORKERS", 1),
                'worker_class': 'sync',
                'timeout': 60,
                'reload': False,
                'loglevel': config.get("LOG_LEVEL", "info").lower(),
                'accesslog': os.path.join(os.getcwd(), 'logs', 'gunicorn_access.log'),
                'errorlog': os.path.join(os.getcwd(), 'logs', 'gunicorn_error.log'),
            }
            StandaloneApplication(app, options).run()
        except ImportError:
            print("Gunicorn not available. Falling back to Flask dev server.")
            app.run(
                host=config["HOST"],
                port=config["PORT"],
                debug=False,
                use_reloader=False,
                threaded=True
            )