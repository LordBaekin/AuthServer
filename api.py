# api.py - Flask routes and API
import logging
import time
import bcrypt
import uuid
from datetime import datetime
import os
import signal
import threading

from redis_service import get_redis_client

# Flask imports
from flask import Flask, request, jsonify, g, redirect
from werkzeug.middleware.proxy_fix import ProxyFix

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# CORS support
from flask_cors import CORS

# Import our modules
from config import config, APP_VERSION
from db import (
    db_execute,
    log_security_event,
    close_db_connections,
    get_connection_pool_stats
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
    CORS(app, resources={r"/auth/*": {"origins": origins}})

    # Rate limiter
    if config.get("REDIS_ENABLED", False):
        redis_client = get_redis_client('rate_limit')
        if redis_client:
            try:
                from flask_limiter.storage import RedisStorage
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
            data = sanitize_input(request.json or {})
            ip, ua = get_client_info()
            for k in ('username', 'email', 'password'):
                if k not in data:
                    return jsonify({'error': f'{k} required'}), 400
            if not is_valid_username(data['username']):
                return jsonify({'error': 'Invalid username format.'}), 400
            if not is_valid_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400
            valid, msg = check_password_strength(data['password'])
            if not valid:
                return jsonify({'error': msg}), 400

            hashed = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt())
            user_id = str(uuid.uuid4())
            ts = int(time.time())

            try:
                db_execute(
                    'INSERT INTO users '
                    '(id, username, email, password, created_at, last_password_change) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (user_id, data['username'], data['email'], hashed, ts, ts),
                    commit=True
                )
            except Exception:
                existing = db_execute(
                    'SELECT username, email FROM users WHERE username=? OR email=?',
                    (data['username'], data['email']),
                    fetchone=True
                )
                if existing and existing['username'] == data['username']:
                    return jsonify({'error': 'Username already exists'}), 409
                if existing and existing['email'] == data['email']:
                    return jsonify({'error': 'Email already exists'}), 409
                return jsonify({'error': 'Registration failed'}), 500

            loggers['app'].info(f"New user registered: {data['username']} ({user_id})")
            log_security_event(user_id, 'USER_CREATED',
                               f"New user account created: {data['username']}", ip)

            if config.get("ENABLE_WELCOME_EMAIL", True):
                send_template_email(
                    data['email'],
                    'welcome',
                    f"Welcome to {config['APP_NAME']}",
                    {'username': data['username'], 'login_link': config['LOGIN_URL']}
                )

            token = create_access_token(user_id)
            refresh = create_refresh_token(user_id)
            expiry = ts + config["JWT_EXPIRATION"]

            db_execute(
                'INSERT INTO user_sessions '
                '(token, user_id, created_at, expires_at, ip_address, user_agent, last_active) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (token, user_id, ts, expiry, ip, ua, ts),
                commit=True
            )

            return jsonify({
                'id': user_id,
                'username': data['username'],
                'access_token': token,
                'refresh_token': refresh,
                'expires_in': config["JWT_EXPIRATION"],
                'message': 'Registration successful'
            }), 201

        except Exception as e:
            loggers['app'].error(f"Registration error: {e}")
            return jsonify({'error': 'Server error during registration'}), 500

    @app.route('/auth/login', methods=['POST'])
    @limiter.limit(config["RATE_LIMIT_LOGIN"])
    def login():
        try:
            data = sanitize_input(request.json or {})
            ip, ua = get_client_info()

            # Required fields
            for k in ('username', 'password'):
                if k not in data:
                    return jsonify({'error': f'{k} required'}), 400
            if not isinstance(data['username'], str) or not isinstance(data['password'], str):
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

            # Verify it’s a proper refresh token
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
                'expires_in':    config["JWT_EXPIRATION"]
            }), 200

        except Exception as e:
            loggers['app'].error(f"Token refresh error: {e}")
            return jsonify({'error': 'Server error during token refresh'}), 500


    @app.route('/auth/logout', methods=['POST'])
    @token_required
    def logout():
        try:
            user_id = g.user_id
            ip, _ = get_client_info()
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]
                db_execute(
                    'UPDATE user_sessions SET is_valid=0 WHERE user_id=? AND token=?',
                    (user_id, token), commit=True
                )
            log_security_event(user_id, 'USER_LOGOUT',
                               f"User logged out from {ip}", ip)
            return jsonify({'message': 'Successfully logged out'}), 200

        except Exception as e:
            loggers['app'].error(f"Logout error: {e}")
            return jsonify({'error': 'Server error during logout'}), 500

    @app.route('/auth/request-password-reset', methods=['POST'])
    @limiter.limit(config["RATE_LIMIT_RESET"])
    def request_reset():
        try:
            data = sanitize_input(request.json or {})
            ip, _ = get_client_info()
            if 'email' not in data:
                return jsonify({'error': 'email required'}), 400
            if not is_valid_email(data['email']):
                return jsonify({'error': 'Invalid email format'}), 400

            user = db_execute(
                'SELECT id, username FROM users WHERE email=?',
                (data['email'],), fetchone=True
            )
            if not user:
                loggers['app'].info(f"Password reset requested for non-existent email: {data['email']}")
                return jsonify({'message': 'If your email is registered, you will receive reset instructions'}), 200

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
            send_template_email(
                data['email'],
                'reset_password',
                f"Reset your {config['APP_NAME']} password",
                {'username': user['username'], 'reset_link': reset_link}
            )

            loggers['app'].info(f"Password reset email sent to: {data['email']} for user: {user['username']}")
            log_security_event(user['id'], 'PASSWORD_RESET_REQUEST',
                               f"Password reset requested from {ip}", ip)

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
                'bind': f"{config["HOST"]}:{config["PORT"]}",
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
