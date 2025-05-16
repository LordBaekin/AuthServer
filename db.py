# db.py - Database functions with enhanced connection pooling and security
import os
import time
import sqlite3
import logging
from contextlib import contextmanager
import threading
import random
from flask import request
from config import config, BACKUP_DIR

# Thread local storage for database connections
_thread_local = threading.local()

# Connection pool metrics
_pool_metrics = {
    'created': 0,
    'reused': 0,
    'peak_used': 0,
    'errors': 0,
    'timeouts': 0,
    'last_reset': time.time()
}

# Connection pool settings
CONNECTION_TIMEOUT = 5      # Seconds to wait for a connection before timing out
MAX_CONNECTION_AGE = 3600   # Maximum time to keep a connection open (1 hour)
CONNECTION_CHECK_INTERVAL = 300  # How often to check connection health (5 minutes)

# Database schema for SQLite
DB_SCHEMA_SQLITE = '''
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password TEXT,
  created_at INTEGER,
  last_login INTEGER,
  login_count INTEGER DEFAULT 0,
  account_status TEXT DEFAULT 'active',
  failed_login_count INTEGER DEFAULT 0,
  last_password_change INTEGER
);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  expires_at INTEGER,
  created_at INTEGER,
  used INTEGER DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  ip_address TEXT,
  user_agent TEXT,
  success INTEGER,
  timestamp INTEGER
);

CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  event_type TEXT,
  description TEXT,
  ip_address TEXT,
  timestamp INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  created_at INTEGER,
  expires_at INTEGER,
  ip_address TEXT,
  user_agent TEXT,
  last_active INTEGER,
  is_valid INTEGER DEFAULT 1,
  token_type TEXT DEFAULT 'access',
  additional_data TEXT DEFAULT NULL,
  device_fingerprint TEXT DEFAULT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE,
  count INTEGER DEFAULT 0,
  reset_at INTEGER,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS security_events_extended (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  event_type TEXT,
  description TEXT,
  ip_address TEXT,
  user_agent TEXT,
  timestamp INTEGER,
  risk_level TEXT DEFAULT 'low',
  metadata TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions (token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_is_valid ON user_sessions (is_valid);
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts (username);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events (user_id);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON reset_tokens (user_id);
'''

# MySQL schema with appropriate types
DB_SCHEMA_MYSQL = '''
CREATE TABLE IF NOT EXISTS schema_version (
  version INT PRIMARY KEY,
  applied_at BIGINT
);

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(30) UNIQUE,
  email VARCHAR(100) UNIQUE,
  password VARCHAR(255),
  created_at BIGINT,
  last_login BIGINT,
  login_count INT DEFAULT 0,
  account_status VARCHAR(20) DEFAULT 'active',
  failed_login_count INT DEFAULT 0,
  last_password_change BIGINT
);

CREATE TABLE IF NOT EXISTS reset_tokens (
  token VARCHAR(100) PRIMARY KEY,
  user_id VARCHAR(36),
  expires_at BIGINT,
  created_at BIGINT,
  used TINYINT DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(30),
  ip_address VARCHAR(45),
  user_agent VARCHAR(255),
  success TINYINT,
  timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS security_events (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36),
  event_type VARCHAR(50),
  description TEXT,
  ip_address VARCHAR(45),
  timestamp BIGINT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(36),
  created_at BIGINT,
  expires_at BIGINT,
  ip_address VARCHAR(45),
  user_agent VARCHAR(255),
  last_active BIGINT,
  is_valid TINYINT DEFAULT 1,
  token_type VARCHAR(20) DEFAULT 'access',
  additional_data TEXT DEFAULT NULL,
  device_fingerprint VARCHAR(64) DEFAULT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS rate_limits (
  id INT AUTO_INCREMENT PRIMARY KEY,
  `key` VARCHAR(255) UNIQUE,
  count INT DEFAULT 0,
  reset_at BIGINT,
  created_at BIGINT
);

CREATE TABLE IF NOT EXISTS security_events_extended (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36),
  event_type VARCHAR(50),
  description TEXT,
  ip_address VARCHAR(45),
  user_agent VARCHAR(255),
  timestamp BIGINT,
  risk_level VARCHAR(10) DEFAULT 'low',
  metadata TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes for faster lookups
CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX idx_user_sessions_token ON user_sessions (token);
CREATE INDEX idx_user_sessions_is_valid ON user_sessions (is_valid);
CREATE INDEX idx_login_attempts_username ON login_attempts (username);
CREATE INDEX idx_security_events_user_id ON security_events (user_id);
CREATE INDEX idx_reset_tokens_user_id ON reset_tokens (user_id);
'''

# Global variable to hold the connection pool for MySQL
_mysql_pool = None

# Flag to track if PyMySQL is available
_has_mysql = False

# Try to import PyMySQL and adapt it to MySQLdb API
try:
    import pymysql
    pymysql.install_as_MySQLdb()
    from pymysql.cursors import DictCursor
    _has_mysql = True
    logging.info("PyMySQL detected: MySQL support enabled")
except ImportError:
    logging.warning("PyMySQL not found; falling back to SQLite only")

class SQLiteConnectionPool:
    def __init__(self, max_connections=10, min_connections=5):
        # ensure config values (which may be strings) become ints
        self.max_connections = int(max_connections)
        self.min_connections = int(min_connections)
        self.connections = []
        self.in_use = set()
        self.lock = threading.RLock()
        self.last_connection_check = time.time()

    def get_connection(self, timeout=5.0):
        """Get a connection with timeout
        
        Args:
            timeout (float): Maximum time to wait for a connection in seconds
        
        Returns:
            sqlite3.Connection: A database connection
            
        Raises:
            Exception: If no connection could be acquired within the timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            with self.lock:
                # periodically prune idle connections
                now = time.time()
                if now - self.last_connection_check > 300:  # Every 5 minutes
                    self._cleanup_old_connections()
                    self.last_connection_check = now

                # try re‐using an idle connection
                for conn in list(self.connections):
                    if conn not in self.in_use:
                        try:
                            cur = conn.cursor()
                            cur.execute("SELECT 1")
                            cur.close()
                            self.in_use.add(conn)
                            
                            # Update last used time
                            if hasattr(conn, '_last_used'):
                                conn._last_used = time.time()
                                
                            return conn
                        except sqlite3.Error:
                            self.connections.remove(conn)
                            logging.warning("Removed bad SQLite connection from pool")

                # create a new one if we haven't hit max
                if len(self.connections) < self.max_connections:
                    conn = self._create_new_connection()
                    self.connections.append(conn)
                    self.in_use.add(conn)
                    return conn
                    
            # If we get here, wait a bit before trying again
            time.sleep(0.1)
            
        # Timeout occurred, log some diagnostic information
        with self.lock:
            total = len(self.connections)
            used = len(self.in_use)
            logging.error(f"SQLite connection pool exhausted after {timeout}s wait. Total: {total}, In use: {used}, Max: {self.max_connections}")
            
        # Try to cleanup old connections one last time
        self._cleanup_old_connections()
        
        # Give up
        raise Exception(f"SQLite connection pool exhausted (timeout: {timeout}s)")

    def release_connection(self, conn):
        """Return a connection to the pool"""
        with self.lock:
            if conn in self.in_use:
                self.in_use.discard(conn)
                # Update last used time
                conn_id = id(conn)
                if hasattr(self, '_connection_metadata') and conn_id in self._connection_metadata:
                    self._connection_metadata[conn_id]['last_used'] = time.time()
            else:
                logging.warning("Released a connection that wasn't marked as in-use")

    def _create_new_connection(self):
        """Create a new SQLite connection with metadata for tracking"""
        conn = sqlite3.connect(
            config.get("DB_PATH", "auth.db"),
            timeout=30.0,
            isolation_level=None
        )
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=10000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.row_factory = sqlite3.Row
    
        # Store metadata in a dictionary instead of trying to add attributes directly
        # to the connection object
        self._connection_metadata = getattr(self, '_connection_metadata', {})
        conn_id = id(conn)  # Use the object id as a unique key
        self._connection_metadata[conn_id] = {
            'created_time': time.time(),
            'last_used': time.time()
        }
    
        return conn

    def _cleanup_old_connections(self):
        """Clean up old and idle connections"""
        current_time = time.time()
        with self.lock:
            # Make sure we have the metadata dictionary
            self._connection_metadata = getattr(self, '_connection_metadata', {})
        
            # First, find connections that are too old
            for conn in list(self.connections):
                conn_id = id(conn)
                # If connection has been around for too long, close it
                if conn_id in self._connection_metadata:
                    created_time = self._connection_metadata[conn_id]['created_time']
                    if current_time - created_time > MAX_CONNECTION_AGE:
                        if conn not in self.in_use:
                            try:
                                conn.close()
                                self.connections.remove(conn)
                                # Remove from metadata
                                if conn_id in self._connection_metadata:
                                    del self._connection_metadata[conn_id]
                                logging.info(f"Closed old SQLite connection (age: {current_time - created_time:.1f}s)")
                            except:
                                pass
        
            # Then handle idle connections
            idle = [c for c in self.connections if c not in self.in_use]
            excess = len(idle) - self.min_connections
            for c in idle[:excess]:
                conn_id = id(c)
                try:
                    c.close()
                except:
                    pass
                self.connections.remove(c)
                # Remove from metadata
                if conn_id in self._connection_metadata:
                    del self._connection_metadata[conn_id]
            
            logging.debug(
                f"SQLite pool stats: active={len(self.in_use)}, "
                f"idle={len(self.connections)-len(self.in_use)}, "
                f"total={len(self.connections)}"
            )

    def get_pool_stats(self):
        """Get statistics about the connection pool"""
        with self.lock:
            total = len(self.connections)
            in_use = len(self.in_use)
            idle = total - in_use
        
            # Calculate age statistics
            now = time.time()
            self._connection_metadata = getattr(self, '_connection_metadata', {})
        
            ages = []
            for conn in self.connections:
                conn_id = id(conn)
                if conn_id in self._connection_metadata:
                    ages.append(now - self._connection_metadata[conn_id]['created_time'])
        
            avg_age = sum(ages) / len(ages) if ages else 0
        
            return {
                'total': total,
                'in_use': in_use,
                'idle': idle,
                'max': self.max_connections,
                'avg_age_seconds': avg_age
            }

    def validate_connections(self):
        """Periodically validate all connections in the pool"""
        with self.lock:
            for conn in list(self.connections):
                if conn not in self.in_use:
                    try:
                        cursor = conn.cursor()
                        cursor.execute("SELECT 1")
                        cursor.close()
                    except sqlite3.Error:
                        logging.warning("Removing invalid connection from pool")
                        try:
                            conn.close()
                        except:
                            pass
                        self.connections.remove(conn)

def get_sqlite_connection():
    """Get a SQLite connection from the connection pool"""
    global _sqlite_pool
    if _sqlite_pool is None:
        _sqlite_pool = SQLiteConnectionPool(
            max_connections=int(config.get("DB_POOL_SIZE", 20)),
            min_connections=int(config.get("DB_MIN_POOL_SIZE", 5))
        )
    return _sqlite_pool.get_connection()


# Initialize SQLite pool to None
_sqlite_pool = None
_mysql_pool = None

# Branch between MySQL and SQLite based on config and availability
if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
    logging.info("Using MySQL database backend")

    # ---------- PyMySQL connection pool ----------
    class PyMySQLConnectionPool:
        def __init__(self, host, port, user, password, database,
                     charset='utf8mb4', connect_timeout=CONNECTION_TIMEOUT,
                     pool_size=None, min_connections=None):
            self.max_connections = pool_size or config.get("DB_POOL_SIZE", 20)
            self.min_connections = min_connections or config.get("DB_MIN_POOL_SIZE", 5)
            self.host, self.port = host, port
            self.user, self.password = user, password
            self.database, self.charset = database, charset
            self.timeout = connect_timeout
            self.connections = []
            self.in_use = set()
            self.lock = threading.RLock()
            self.last_check = time.time()

        def get_connection(self):
            with self.lock:
                now = time.time()
                if now - self.last_check > CONNECTION_CHECK_INTERVAL:
                    self._cleanup_old()
                    self.last_check = now

                # Reuse healthy connection
                for conn in list(self.connections):
                    try:
                        conn.ping(reconnect=True)
                        if conn not in self.in_use:
                            self.in_use.add(conn)
                            _pool_metrics['reused'] += 1
                            return conn
                    except Exception:
                        self.connections.remove(conn)

                # Create new if under max
                if len(self.connections) < self.max_connections:
                    conn = self._new_conn()
                    self.connections.append(conn)
                    self.in_use.add(conn)
                    _pool_metrics['created'] += 1
                    return conn

                # Pool exhausted
                _pool_metrics['timeouts'] += 1
                logging.error("MySQL connection pool exhausted")
                raise Exception("MySQL connection pool exhausted")

        def release(self, conn):
            with self.lock:
                self.in_use.discard(conn)

        def _new_conn(self):
            return pymysql.connect(
                host=self.host, port=self.port,
                user=self.user, password=self.password,
                database=self.database, charset=self.charset,
                cursorclass=DictCursor, connect_timeout=self.timeout
            )

        def _cleanup_old(self):
            idle = [c for c in self.connections if c not in self.in_use]
            excess = len(idle) - self.min_connections
            for c in idle[:excess]:
                try:
                    c.close()
                except:
                    pass
                self.connections.remove(c)

    def init_mysql_pool():
        global _mysql_pool
        if _mysql_pool is None:
            _mysql_pool = PyMySQLConnectionPool(
                host=config.get("DB_HOST", "localhost"),
                port=config.get("DB_PORT", 3306),
                user=config.get("DB_USER", ""),
                password=config.get("DB_PASSWORD", ""),
                database=config.get("DB_NAME", "vespeyr_auth"),
                pool_size=config.get("DB_POOL_SIZE", 20),
                min_connections=config.get("DB_MIN_POOL_SIZE", 5)
            )
            logging.info("Initialized PyMySQLConnectionPool")

@contextmanager
def get_db_connection():
        """Get a database connection with context manager for auto-close"""
        if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
            # For MySQL databases
            if _mysql_pool is None:
                init_mysql_pool()
            
            conn = None
            cursor = None
            try:
                conn = _mysql_pool.get_connection()
                cursor = conn.cursor(dictionary=True)  # Similar to sqlite Row factory
                yield cursor
                conn.commit()
            except Exception as e:
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                raise e
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if conn:
                    try:
                        _mysql_pool.release(conn)  # Release back to the pool
                    except:
                        pass
        else:
            # For SQLite databases
            conn = None
            cursor = None
            try:
                conn = get_sqlite_connection()
                cursor = conn.cursor()
                yield cursor
                # SQLite in autocommit mode doesn't need explicit commit
            except Exception as e:
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                raise e
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if conn:
                    try:
                        # This is the important part - make sure to release the connection back to the pool
                        _sqlite_pool.release_connection(conn)
                    except:
                        pass        

# ----------------------------------------------------------------------------
# Core helpers and utilities
# ----------------------------------------------------------------------------
def ensure_parameterized_query(query, params):
    """
    Verify query placeholders match params count to reduce SQL injection risk.
    """
    # Only count question marks outside of string literals
    placeholder_count = 0
    in_string = False
    string_delimiter = None
    
    for char in query:
        if char in "\"'":
            if not in_string:
                in_string = True
                string_delimiter = char
            elif char == string_delimiter:
                in_string = False
        elif char == '?' and not in_string:
            placeholder_count += 1
    
    # For MySQL, we'll count %s placeholders instead
    if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
        placeholder_count = 0
        i = 0
        while i < len(query):
            if query[i:i+2] == '%s' and not in_string:
                placeholder_count += 1
                i += 2
            else:
                i += 1
    
    if placeholder_count != len(params):
        logging.warning(
            f"SQL parameter count mismatch: expected {placeholder_count}, got {len(params)}"
        )
    
    return query, params


def db_execute(query, params=(), commit=False, fetchone=False, fetchall=False):
    """Helper for database operations with automatic connection management"""
    try:
        # Make a copy of the original query
        adjusted_query = query
        
        # Only adjust for MySQL if we're actually using MySQL
        if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
            # Replace ? with %s for MySQL, but only if not in a string literal
            # This is a simple approach - a full parser would be more robust
            adjusted_query = ""
            in_string = False
            for char in query:
                if char == "'" or char == '"':
                    in_string = not in_string
                if char == '?' and not in_string:
                    adjusted_query += '%s'
                else:
                    adjusted_query += char
        
        with get_db_connection() as cursor:
            cursor.execute(adjusted_query, params)
            
            result = None
            if fetchone:
                result = cursor.fetchone()
            elif fetchall:
                result = cursor.fetchall()
            
            return result
    except Exception as e:
        logging.error(f"Database error in query '{query}': {e}")
        raise


def init_db():
    """Initialize the database with schema"""
    # Ensure backup directory exists
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        
    if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
        # For MySQL - ensure database exists and create schema
        try:
            # First connect to MySQL without specifying database to create if needed
            cnx = None
            cur = None
            try:
                cnx = pymysql.connect(
                    host=config.get("DB_HOST", "localhost"),
                    port=int(config.get("DB_PORT", 3306)),
                    user=config.get("DB_USER", ""),
                    password=config.get("DB_PASSWORD", ""),
                    charset='utf8mb4',
                    cursorclass=pymysql.cursors.DictCursor,
                    connect_timeout=int(config.get("CONNECTION_TIMEOUT", 5))
                )
                
                cur = cnx.cursor()
                
                # Create database if it doesn't exist
                db_name = config.get("DB_NAME", "vespeyr_auth")
                cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
                
                # Switch to the database
                cur.execute(f"USE `{db_name}`")
                
                # Create schema tables
                for stmt in DB_SCHEMA_MYSQL.strip().split(';'):
                    if stmt.strip():
                        cur.execute(stmt)
                
                # Check if schema_version table is empty
                cur.execute('SELECT COUNT(*) as count FROM schema_version')
                result = cur.fetchone()
                if result['count'] == 0:
                    # Insert initial schema version
                    cur.execute(
                        'INSERT INTO schema_version VALUES (%s, %s)',
                        (1, int(time.time()))
                    )
                    
                cnx.commit()
                
                # Initialize connection pool after database is created
                init_mysql_pool()
                
                logging.info(f"MySQL database '{db_name}' initialized successfully")
                
            except Exception as e:
                logging.error(f"Failed to initialize MySQL database: {e}")
                # Fall back to SQLite if configured
                if config.get("FALLBACK_TO_SQLITE", True):
                    logging.warning("Falling back to SQLite database")
                    config["DB_TYPE"] = "sqlite"
                else:
                    raise
            finally:
                if cur:
                    cur.close()
                if cnx:
                    cnx.close()
                
        except Exception as e:
            logging.error(f"Failed to initialize MySQL database: {e}")
            # Fall back to SQLite if configured
            if config.get("FALLBACK_TO_SQLITE", True):
                logging.warning("Falling back to SQLite database")
                config["DB_TYPE"] = "sqlite"
            else:
                raise
    
    # Initialize SQLite if that's what we're using (either by default or fallback)
    if config.get("DB_TYPE", "sqlite") == "sqlite":
        conn = None
        cursor = None
        try:
            conn = sqlite3.connect(config.get("DB_PATH", "auth.db"))
            cursor = conn.cursor()
            
            # Execute schema creation
            for stmt in DB_SCHEMA_SQLITE.strip().split(';'):
                if stmt.strip():
                    cursor.execute(stmt)
            
            # Check if schema_version table is empty
            cursor.execute('SELECT COUNT(*) FROM schema_version')
            result = cursor.fetchone()
            if result[0] == 0:
                # Insert initial schema version
                cursor.execute(
                    'INSERT INTO schema_version VALUES (?, ?)',
                    (1, int(time.time()))
                )
            
            conn.commit()
            logging.info("SQLite database initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize SQLite database: {e}")
            raise
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()


def backup_database():
    """Create a timestamped backup of the current database."""
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Ensure backup directory exists
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        
    if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
        backup_path = os.path.join(BACKUP_DIR, f"auth_db_backup_{timestamp}.sql")
        cmd = [
            "mysqldump",
            f"--host={config.get('DB_HOST','localhost')}",
            f"--port={int(config.get('DB_PORT',3306))}",  # Convert to int
            f"--user={config.get('DB_USER','')}"
        ]
        if config.get("DB_PASSWORD"): cmd.append(f"--password={config.get('DB_PASSWORD')}")
        cmd.append(config.get("DB_NAME","vespeyr_auth"))
        try:
            import subprocess
            with open(backup_path,'w') as f:
                res = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
            if res.returncode != 0:
                logging.error(f"MySQL backup failed: {res.stderr.decode()}")
                return False
            cleanup_old_backups(extension=".sql")
            logging.info(f"MySQL database backup created: {backup_path}")
            return True
        except Exception as e:
            logging.error(f"MySQL backup error: {e}")
            return False
    else:
        backup_path = os.path.join(BACKUP_DIR, f"auth_db_backup_{timestamp}.db")
        try:
            src = sqlite3.connect(config.get("DB_PATH","auth.db"))
            dest = sqlite3.connect(backup_path)
            src.backup(dest)
            src.close()
            dest.close()
            cleanup_old_backups()
            logging.info(f"SQLite backup created: {backup_path}")
            return True
        except Exception as e:
            logging.error(f"SQLite backup error: {e}")
            return False


def cleanup_old_backups(extension=".db"):
    """Prune backups to keep only the newest MAX_BACKUPS."""
    if not os.path.exists(BACKUP_DIR): 
        return
        
    files = [os.path.join(BACKUP_DIR,f) for f in os.listdir(BACKUP_DIR)
             if f.startswith("auth_db_backup_") and f.endswith(extension)]
    files.sort(key=lambda p: os.path.getmtime(p))
    
    # Convert to integer to avoid type error
    maxb = int(config.get("MAX_BACKUPS", 30))
    
    if len(files) > maxb:
        for old in files[:-maxb]:
            try: 
                os.remove(old)
                logging.info(f"Removed old backup: {old}")
            except Exception as e: 
                logging.error(f"Failed to remove old backup {old}: {e}")


def log_security_event(user_id, event_type, description,
                       ip_address=None, user_agent=None,
                       risk_level='low', metadata=None):
    """
    Log security activity. Always store user_agent as text.
    """
    try:
        ts = int(time.time())
        
        # If caller supplied user_agent, use it; otherwise fall back to header string
        if user_agent is None:
            ua_str = request.headers.get('User-Agent', '')
        else:
            ua_str = str(user_agent)
        
        # Try extended table first
        try:
            db_execute(
                '''INSERT INTO security_events_extended
                   (user_id, event_type, description, ip_address,
                    user_agent, timestamp, risk_level, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (user_id, event_type, description,
                 ip_address, ua_str, ts,
                 risk_level, metadata),
                commit=True
            )
        except Exception:
            # Fallback to basic table
            logging.warning("Extended security_events failed, falling back")
            db_execute(
                'INSERT INTO security_events '
                '(user_id, event_type, description, ip_address, timestamp) '
                'VALUES (?, ?, ?, ?, ?)',
                (user_id, event_type, description, ip_address, ts),
                commit=True
            )
        
        logging.getLogger('vespeyr.security').info(
            f"USER:{user_id} EVENT:{event_type} "
            f"IP:{ip_address} UA:{ua_str} RISK:{risk_level} - {description}"
        )
        return True

    except Exception as e:
        logging.error(f"Failed to log security event: {e}")
        return False



def get_connection_pool_stats():
    """Return current metrics and pool sizes."""
    stats = _pool_metrics.copy()
    if config.get("DB_TYPE","sqlite")=="mysql" and _has_mysql and _mysql_pool:
        stats['total'] = len(_mysql_pool.connections)
        stats['in_use'] = len(_mysql_pool.in_use)
    elif _sqlite_pool:
        stats['total'] = len(_sqlite_pool.connections)
        stats['in_use'] = len(_sqlite_pool.in_use)
    stats['uptime'] = time.time()-stats['last_reset']
    return stats


def reset_connection_pool():
    """Reinitialize pools and reset metrics."""
    global _mysql_pool, _sqlite_pool
    _pool_metrics.update({k:0 for k in ['created','reused','errors','timeouts']})
    _pool_metrics['last_reset'] = time.time()
    if config.get("DB_TYPE","sqlite")=="mysql" and _has_mysql:
        _mysql_pool = None
        init_mysql_pool()
    else:
        if _sqlite_pool:
            for c in _sqlite_pool.connections:
                try: c.close()
                except: pass
            _sqlite_pool = None

def close_db_connections():
    """Close all database connections at the end of a request"""
    if hasattr(_thread_local, 'db_connections'):
        for conn in _thread_local.db_connections:
            try:
                conn.close()
            except:
                pass
        _thread_local.db_connections = []

def execute_script(script, params=()):
    """Execute multiple SQL statements as a script"""
    try:
        if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
            # MySQL doesn't support script execution via cursor directly
            # Execute each statement separately
            conn = None
            cursor = None
            try:
                if _mysql_pool is None:
                    init_mysql_pool()
                conn = _mysql_pool.get_connection()
                cursor = conn.cursor(dictionary=True)
                
                # Split by semicolons but respect string literals
                statements = []
                current = []
                in_string = False
                string_delimiter = None
                
                for char in script:
                    if char in "\"'":
                        if not in_string:
                            in_string = True
                            string_delimiter = char
                        elif char == string_delimiter:
                            in_string = False
                    
                    current.append(char)
                    
                    if char == ';' and not in_string:
                        statements.append(''.join(current))
                        current = []
                
                # Add the last statement if there is one
                if current:
                    statements.append(''.join(current))
                
                # Execute each statement
                for stmt in statements:
                    if stmt.strip():
                        cursor.execute(stmt, params)
                
                conn.commit()
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if conn:
                    try:
                        _mysql_pool.release(conn)
                    except:
                        pass
                        
        else:
            # SQLite supports script execution
            conn = None
            try:
                conn = get_sqlite_connection()
                conn.executescript(script)
            finally:
                if conn:
                    try:
                        _sqlite_pool.release_connection(conn)
                    except:
                        pass
        return True
    except Exception as e:
        logging.error(f"Failed to execute script: {e}")
        return False

def get_db_size():
    """Get the current database file size in bytes (SQLite only)"""
    if config.get("DB_TYPE", "sqlite") == "sqlite":
        db_path = config.get("DB_PATH", "auth.db")
        try:
            return os.path.getsize(db_path)
        except:
            return 0
    return None

def get_table_row_counts():
    """Get row counts for all tables in the database"""
    counts = {}
    if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
        # For MySQL databases
        try:
            with get_db_connection() as cursor:
                # Get table list
                cursor.execute("SHOW TABLES")
                tables = cursor.fetchall()
                
                for table_data in tables:
                    table_name = list(table_data.values())[0]  # Get first value in the dictionary
                    
                    # Count rows
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
                    result = cursor.fetchone()
                    
                    if result and 'count' in result:
                        counts[table_name] = result['count']
                    else:
                        counts[table_name] = 0
        except Exception as e:
            logging.error(f"Failed to get MySQL table row counts: {e}")
    else:
        # For SQLite databases
        try:
            tables = db_execute(
                "SELECT name FROM sqlite_master WHERE type='table'",
                fetchall=True
            )
            
            for table in tables:
                try:
                    table_name = table['name']
                    result = db_execute(
                        f"SELECT COUNT(*) as count FROM {table_name}",
                        fetchone=True
                    )
                    
                    if result:
                        counts[table_name] = result['count']
                    else:
                        counts[table_name] = 0
                except:
                    # Skip tables that can't be counted
                    pass
        except Exception as e:
            logging.error(f"Failed to get SQLite table row counts: {e}")
    
    return counts

def vacuum_database():
    """Run VACUUM on SQLite database to optimize and reclaim space"""
    if config.get("DB_TYPE", "sqlite") == "sqlite":
        try:
            # Create a direct connection (not through the pool) for vacuum
            conn = sqlite3.connect(config.get("DB_PATH", "auth.db"))
            conn.execute("VACUUM")
            conn.close()
            logging.info("Database vacuum completed successfully")
            return True
        except Exception as e:
            logging.error(f"Database vacuum failed: {e}")
            return False
    else:
        # MySQL equivalent is OPTIMIZE TABLE
        try:
            with get_db_connection() as cursor:
                # Get table list
                tables = db_execute(
                    "SHOW TABLES",
                    fetchall=True
                )
                
                table_names = []
                for table_data in tables:
                    table_names.append(list(table_data.values())[0])
                
                if table_names:
                    # Optimize tables
                    table_list = ", ".join(table_names)
                    cursor.execute(f"OPTIMIZE TABLE {table_list}")
                    
                logging.info("Database optimization completed successfully")
                return True
        except Exception as e:
            logging.error(f"Database optimization failed: {e}")
            return False