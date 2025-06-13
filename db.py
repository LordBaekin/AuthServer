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

# Extended Database Schema for SQLite
DB_SCHEMA_SQLITE = '''
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  email TEXT,
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

CREATE TABLE IF NOT EXISTS user_preferences (
  user_id              TEXT PRIMARY KEY,
  remember_me          INTEGER DEFAULT 0,
  auto_login_server    INTEGER DEFAULT 0,
  auto_login_character INTEGER DEFAULT 0,
  last_server_id       TEXT,
  last_character_name  TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  created_at INTEGER,
  expires_at INTEGER,
  ip_address TEXT,

  world_key TEXT DEFAULT NULL,
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

-- Game Data Tables for Persistence

CREATE TABLE IF NOT EXISTS inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  world_key TEXT NOT NULL,
  save_key TEXT NOT NULL,
  scene TEXT NOT NULL,
  ui_data TEXT,
  scene_data TEXT,
  created_at INTEGER,
  updated_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT uq_inventory_user_world_save UNIQUE (user_id, world_key, save_key)
);


CREATE TABLE IF NOT EXISTS quests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  world_key TEXT NOT NULL,
  save_key TEXT NOT NULL,
  active_quests TEXT,
  completed_quests TEXT,
  failed_quests TEXT,
  created_at INTEGER,
  updated_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT uq_quests_user_world_save UNIQUE (user_id, world_key, save_key)
);


CREATE TABLE IF NOT EXISTS stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  world_key TEXT NOT NULL,
  save_key TEXT NOT NULL,
  stats_json TEXT,
  stat_values_json TEXT,
  attribute_values_json TEXT,
  created_at INTEGER,
  updated_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT uq_stats_user_world_save UNIQUE (user_id, world_key, save_key)
);


CREATE TABLE IF NOT EXISTS characters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  world_key TEXT NOT NULL,
  character_name TEXT NOT NULL,
  character_id TEXT UNIQUE,
  character_data TEXT,
  is_active INTEGER DEFAULT 0,
  created_at INTEGER,
  updated_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  CONSTRAINT uq_user_world_character UNIQUE (user_id, world_key, character_name)
);



CREATE TABLE IF NOT EXISTS character_data (
  world_key TEXT NOT NULL,
  character_id TEXT NOT NULL,
  character_data TEXT,
  PRIMARY KEY (world_key, character_id)
);

-- CHAT SYSTEM TABLES
CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  player_name TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  message TEXT NOT NULL,
  world_key TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  target_player TEXT DEFAULT NULL,
  message_type TEXT DEFAULT 'normal',
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id TEXT UNIQUE NOT NULL,
  channel_name TEXT NOT NULL,
  channel_type TEXT NOT NULL,
  world_key TEXT,
  created_at INTEGER,
  is_active INTEGER DEFAULT 1
);

-- GUILD SYSTEM TABLES
CREATE TABLE IF NOT EXISTS guilds (
  guild_id TEXT PRIMARY KEY,
  guild_name TEXT NOT NULL,
  leader_id TEXT NOT NULL,
  created_at INTEGER,
  guild_level INTEGER DEFAULT 1,
  guild_xp INTEGER DEFAULT 0,
  FOREIGN KEY (leader_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS guild_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  rank_name TEXT DEFAULT 'Member',
  joined_date INTEGER,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS guild_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id TEXT NOT NULL,
  item_data TEXT,
  deposited_by TEXT,
  deposited_at INTEGER,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id),
  FOREIGN KEY (deposited_by) REFERENCES users(id)
);

-- GROUP SYSTEM TABLES
CREATE TABLE IF NOT EXISTS groups (
  group_id TEXT PRIMARY KEY,
  leader_id TEXT NOT NULL,
  created_at INTEGER,
  max_members INTEGER DEFAULT 5,
  FOREIGN KEY (leader_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS group_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_date INTEGER,
  FOREIGN KEY (group_id) REFERENCES groups(group_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(group_id, user_id)
);

-- RAID SYSTEM TABLES  
CREATE TABLE IF NOT EXISTS raids (
  raid_id TEXT PRIMARY KEY,
  leader_id TEXT NOT NULL,
  created_at INTEGER,
  max_members INTEGER DEFAULT 40,
  FOREIGN KEY (leader_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS raid_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  raid_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  subgroup_id TEXT DEFAULT NULL,
  joined_date INTEGER,
  FOREIGN KEY (raid_id) REFERENCES raids(raid_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(raid_id, user_id)
);

CREATE TABLE IF NOT EXISTS raid_lockouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  boss_id TEXT NOT NULL,
  locked_until INTEGER NOT NULL,
  world_key TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(user_id, boss_id, world_key)
);

-- FRIENDS SYSTEM TABLE
CREATE TABLE IF NOT EXISTS friends (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  friend_user_id TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (friend_user_id) REFERENCES users(id),
  UNIQUE(user_id, friend_user_id)
);

-- Chat system indexes
CREATE INDEX IF NOT EXISTS idx_chat_messages_world_channel ON chat_messages (world_key, channel_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_chat_messages_target ON chat_messages (target_player, timestamp);

-- Social system indexes
CREATE INDEX IF NOT EXISTS idx_guild_members_user ON guild_members (user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members (user_id);
CREATE INDEX IF NOT EXISTS idx_raid_members_user ON raid_members (user_id);
CREATE INDEX IF NOT EXISTS idx_friends_user ON friends (user_id);
CREATE INDEX IF NOT EXISTS idx_raid_lockouts_user_boss ON raid_lockouts (user_id, boss_id);

-- Create indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions (token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_is_valid ON user_sessions (is_valid);
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts (username);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events (user_id);
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON reset_tokens (user_id);

-- Indexes for game data tables
CREATE INDEX IF NOT EXISTS idx_inventory_user_world_scene ON inventory (user_id, world_key, save_key, scene);
CREATE INDEX IF NOT EXISTS idx_quests_user_world_key ON quests (user_id, world_key, save_key);
CREATE INDEX IF NOT EXISTS idx_stats_user_world_key ON stats (user_id, world_key, save_key);
CREATE INDEX IF NOT EXISTS idx_characters_user_world_name ON characters (user_id, world_key, character_name);
'''

DB_SCHEMA_MYSQL = '''
CREATE TABLE IF NOT EXISTS schema_version (
  version INT PRIMARY KEY,
  applied_at BIGINT
);

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
  username VARCHAR(30) UNIQUE,
  email VARCHAR(100),
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

CREATE TABLE IF NOT EXISTS user_preferences (
  user_id              TEXT PRIMARY KEY,
  remember_me          INTEGER DEFAULT 0,
  auto_login_server    INTEGER DEFAULT 0,
  auto_login_character INTEGER DEFAULT 0,
  last_server_id       TEXT,
  last_character_name  TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  token VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(36),
  created_at BIGINT,
  expires_at BIGINT,
  ip_address VARCHAR(45),

  world_key  VARCHAR(128)  DEFAULT NULL,
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

-- Game Data Tables for Persistence

CREATE TABLE IF NOT EXISTS inventory (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  world_key VARCHAR(100) NOT NULL,
  save_key VARCHAR(100) NOT NULL,
  scene VARCHAR(100) NOT NULL,
  ui_data MEDIUMTEXT,
  scene_data MEDIUMTEXT,
  created_at BIGINT,
  updated_at BIGINT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS quests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  world_key VARCHAR(100) NOT NULL,
  save_key VARCHAR(100) NOT NULL,
  active_quests MEDIUMTEXT,
  completed_quests MEDIUMTEXT,
  failed_quests MEDIUMTEXT,
  created_at BIGINT,
  updated_at BIGINT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS stats (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  world_key VARCHAR(100) NOT NULL,
  save_key VARCHAR(100) NOT NULL,
  stats_json MEDIUMTEXT,
  stat_values_json MEDIUMTEXT,
  attribute_values_json MEDIUMTEXT,
  created_at BIGINT,
  updated_at BIGINT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS characters (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(36) NOT NULL,
  world_key VARCHAR(100) NOT NULL,
  character_id TEXT UNIQUE,
  character_name VARCHAR(100) NOT NULL,
  character_data MEDIUMTEXT,
  is_active TINYINT DEFAULT 0,
  created_at BIGINT,
  updated_at BIGINT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE KEY uq_characters_user_world_name (user_id, world_key, character_name)
);


CREATE TABLE IF NOT EXISTS character_data (
  world_key VARCHAR(100) NOT NULL,
  character_id VARCHAR(100) NOT NULL,
  character_data MEDIUMTEXT,
  PRIMARY KEY (world_key, character_id)
);

-- CHAT SYSTEM TABLES
CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  player_name TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  message TEXT NOT NULL,
  world_key TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  target_player TEXT DEFAULT NULL,
  message_type TEXT DEFAULT 'normal',
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chat_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id TEXT UNIQUE NOT NULL,
  channel_name TEXT NOT NULL,
  channel_type TEXT NOT NULL,
  world_key TEXT,
  created_at INTEGER,
  is_active INTEGER DEFAULT 1
);

-- GUILD SYSTEM TABLES
CREATE TABLE IF NOT EXISTS guilds (
  guild_id TEXT PRIMARY KEY,
  guild_name TEXT NOT NULL,
  leader_id TEXT NOT NULL,
  created_at INTEGER,
  guild_level INTEGER DEFAULT 1,
  guild_xp INTEGER DEFAULT 0,
  FOREIGN KEY (leader_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS guild_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  rank_name TEXT DEFAULT 'Member',
  joined_date INTEGER,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(guild_id, user_id)
);

CREATE TABLE IF NOT EXISTS guild_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guild_id TEXT NOT NULL,
  item_data TEXT,
  deposited_by TEXT,
  deposited_at INTEGER,
  FOREIGN KEY (guild_id) REFERENCES guilds(guild_id),
  FOREIGN KEY (deposited_by) REFERENCES users(id)
);

-- GROUP SYSTEM TABLES
CREATE TABLE IF NOT EXISTS groups (
  group_id TEXT PRIMARY KEY,
  leader_id TEXT NOT NULL,
  created_at INTEGER,
  max_members INTEGER DEFAULT 5,
  FOREIGN KEY (leader_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS group_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  joined_date INTEGER,
  FOREIGN KEY (group_id) REFERENCES groups(group_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(group_id, user_id)
);

-- RAID SYSTEM TABLES  
CREATE TABLE IF NOT EXISTS raids (
  raid_id TEXT PRIMARY KEY,
  leader_id TEXT NOT NULL,
  created_at INTEGER,
  max_members INTEGER DEFAULT 40,
  FOREIGN KEY (leader_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS raid_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  raid_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  subgroup_id TEXT DEFAULT NULL,
  joined_date INTEGER,
  FOREIGN KEY (raid_id) REFERENCES raids(raid_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(raid_id, user_id)
);

CREATE TABLE IF NOT EXISTS raid_lockouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  boss_id TEXT NOT NULL,
  locked_until INTEGER NOT NULL,
  world_key TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE(user_id, boss_id, world_key)
);

-- FRIENDS SYSTEM TABLE
CREATE TABLE IF NOT EXISTS friends (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  friend_user_id TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (friend_user_id) REFERENCES users(id),
  UNIQUE(user_id, friend_user_id)
);


-- Chat system indexes
CREATE INDEX IF NOT EXISTS idx_chat_messages_world_channel ON chat_messages (world_key, channel_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_chat_messages_target ON chat_messages (target_player, timestamp);

-- Social system indexes
CREATE INDEX IF NOT EXISTS idx_guild_members_user ON guild_members (user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members (user_id);
CREATE INDEX IF NOT EXISTS idx_raid_members_user ON raid_members (user_id);
CREATE INDEX IF NOT EXISTS idx_friends_user ON friends (user_id);
CREATE INDEX IF NOT EXISTS idx_raid_lockouts_user_boss ON raid_lockouts (user_id, boss_id);


-- Create indexes for faster lookups
CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX idx_user_sessions_token ON user_sessions (token);
CREATE INDEX idx_user_sessions_is_valid ON user_sessions (is_valid);
CREATE INDEX idx_login_attempts_username ON login_attempts (username);
CREATE INDEX idx_security_events_user_id ON security_events (user_id);
CREATE INDEX idx_reset_tokens_user_id ON reset_tokens (user_id);

-- Indexes for game data tables
CREATE INDEX idx_inventory_user_world_scene ON inventory (user_id, world_key, save_key, scene);
CREATE INDEX idx_quests_user_world_key ON quests (user_id, world_key, save_key);
CREATE INDEX idx_stats_user_world_key ON stats (user_id, world_key, save_key);
CREATE INDEX idx_characters_user_world_name ON characters (user_id, world_key, character_name);
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
        except Exception:
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise  # Just use raise without e to preserve exception type
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
        except Exception:
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise  # Just use raise without e to preserve exception type
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
# Helper functions for SQLite migrations (PLACE THESE HERE - MODULE LEVEL)
# ----------------------------------------------------------------------------

def is_safe_for_alter_table(col_def):
    """Check if a column definition is safe for ALTER TABLE ADD COLUMN in SQLite"""
    col_def_upper = col_def.upper()

    # Skip if it contains constraints that ALTER TABLE ADD COLUMN can't handle
    unsafe_keywords = [
        'PRIMARY KEY',
        'UNIQUE',
        'FOREIGN KEY', 
        'REFERENCES',
        'CHECK',
        'CONSTRAINT'
    ]

    for keyword in unsafe_keywords:
        if keyword in col_def_upper:
            return False
        
    return True

def clean_column_definition(col_def):
    """Clean column definition to make it safe for ALTER TABLE ADD COLUMN"""
    # Remove everything after FOREIGN KEY, REFERENCES, etc.
    import re
    patterns_to_remove = [
        r',?\s*FOREIGN KEY.*',
        r',?\s*REFERENCES.*',
        r',?\s*CONSTRAINT.*',
        r',?\s*PRIMARY KEY.*',
        r',?\s*UNIQUE.*',
        r',?\s*CHECK.*'
    ]

    cleaned = col_def
    for pattern in patterns_to_remove:
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE)

    return cleaned.strip().rstrip(',')

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
        db_type = config.get("DB_TYPE", "sqlite").lower()
        adjusted_query = query

        # Adjust placeholders for MySQL if needed
        if db_type == "mysql" and _has_mysql:
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
            # Special handling for SQLite multi-statement schema
            if db_type == "sqlite" and ";" in query and not params:
                cursor.executescript(adjusted_query)
                return None

            cursor.execute(adjusted_query, params)

            if commit:
                cursor.connection.commit()

            if fetchone:
                return cursor.fetchone()
            elif fetchall:
                return cursor.fetchall()

            return None

    except Exception as e:
        logging.error(f"Database error in query '{query}': {e}")
        raise


def init_db():
    """Initialize the database with schema & auto-migrations."""
    # Ensure backup directory exists
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    # ────────────────────────────────────────────────────────────────────────────
    # MySQL branch
    # ────────────────────────────────────────────────────────────────────────────
    if config.get("DB_TYPE", "sqlite") == "mysql" and _has_mysql:
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

            # 1) Create database if missing, then USE it
            db_name = config.get("DB_NAME", "vespeyr_auth")
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
            cur.execute(f"USE `{db_name}`")

            # 2) Create all base tables
            for stmt in DB_SCHEMA_MYSQL.strip().split(';'):
                if stmt.strip():
                    cur.execute(stmt)

            # 3) Seed schema_version if empty
            cur.execute("SELECT COUNT(*) as count FROM schema_version")
            if cur.fetchone()['count'] == 0:
                cur.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (%s, %s)",
                    (1, int(time.time()))
                )

            # ─────────────────────────────────────────────────────────────
            # AUTO-MIGRATE MISSING TABLES & COLUMNS (MySQL)
            # ─────────────────────────────────────────────────────────────
            import re

            # fetch existing tables
            cur.execute(
                "SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = %s",
                (db_name,)
            )
            existing_tables = {row['TABLE_NAME'] for row in cur.fetchall()}

            # pull each CREATE TABLE stmt from master schema
            mysql_stmts = re.findall(
                r'CREATE TABLE IF NOT EXISTS [\s\S]+?\);',
                DB_SCHEMA_MYSQL,
                flags=re.IGNORECASE
            )

            for stmt in mysql_stmts:
                m = re.match(
                    r'CREATE TABLE IF NOT EXISTS\s+`?(\w+)`?\s*\(([\s\S]+)\)\s*;',
                    stmt,
                    flags=re.IGNORECASE
                )
                if not m:
                    continue
                table, cols_block = m.group(1), m.group(2)

                if table not in existing_tables:
                    # brand-new table
                    cur.execute(stmt)
                    continue

                # fetch existing columns
                cur.execute(
                    "SELECT COLUMN_NAME FROM information_schema.columns "
                    "WHERE table_schema = %s AND table_name = %s",
                    (db_name, table)
                )
                existing_cols = {r['COLUMN_NAME'] for r in cur.fetchall()}

                # for each declared column, add if missing
                for col_line in cols_block.split(','):
                    col_def = col_line.strip()
                    nm = re.match(r'`?([A-Za-z0-9_]+)`?\s+(.+)', col_def)
                    if not nm:
                        continue
                    col_name, col_body = nm.group(1), nm.group(2)
                    if col_name not in existing_cols:
                        cur.execute(f"ALTER TABLE `{table}` ADD COLUMN {col_body};")
            # ─────────────────────────────────────────────────────────────

            cnx.commit()
            init_mysql_pool()
            logging.info(f"MySQL database '{db_name}' initialized successfully")

        except Exception as e:
            logging.error(f"Failed to initialize MySQL database: {e}")
            if config.get("FALLBACK_TO_SQLITE", True):
                logging.warning("Falling back to SQLite database")
                config["DB_TYPE"] = "sqlite"
            else:
                raise
        finally:
            try:
                if cur: cur.close()
                if cnx: cnx.close()
            except:
                pass

    # ────────────────────────────────────────────────────────────────────────────
    # SQLite branch
    # ────────────────────────────────────────────────────────────────────────────
    if config.get("DB_TYPE", "sqlite") == "sqlite":
        conn = None
        cursor = None
        try:
            # 1) Open connection & create base tables
            conn = sqlite3.connect(config.get("DB_PATH", "auth.db"))
            cursor = conn.cursor()
            for stmt in DB_SCHEMA_SQLITE.strip().split(';'):
                if stmt.strip():
                    cursor.execute(stmt)

            # 2) Seed schema_version if empty
            cursor.execute("SELECT COUNT(*) FROM schema_version")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (1, int(time.time()))
                )

            # ─────────────────────────────────────────────────────────────
            # AUTO-MIGRATE MISSING TABLES & COLUMNS (SQLite) - IMPROVED VERSION
            # ─────────────────────────────────────────────────────────────
            import re, sqlite3 as _sqlite3

            # Use a direct connection for migrations to avoid interfering with WAL
            _conn = _sqlite3.connect(config.get("DB_PATH", "auth.db"))
            _cur  = _conn.cursor()

            # Get list of existing tables first
            _cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            existing_tables = {row[0] for row in _cur.fetchall()}

            # pull each CREATE TABLE stmt
            stmts = re.findall(
                r'CREATE TABLE IF NOT EXISTS [\s\S]+?\);',
                DB_SCHEMA_SQLITE,
                flags=re.IGNORECASE
            )

            for stmt in stmts:
                m = re.match(
                    r'CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\(([\s\S]+)\)\s*;',
                    stmt,
                    flags=re.IGNORECASE
                )
                if not m:
                    continue
                table, cols_block = m.group(1), m.group(2)

                if table not in existing_tables:
                    # table missing -> create it
                    logging.info(f"Creating missing table: {table}")
                    _cur.execute(stmt)
                    continue

                # fetch existing columns
                _cur.execute(f"PRAGMA table_info({table});")
                existing_cols = {r[1] for r in _cur.fetchall()}
    
                logging.info(f"Table {table} has columns: {existing_cols}")

                # Parse column definitions more carefully
                column_definitions = []
    
                # Split by commas, but handle nested parentheses and quotes
                current_def = ""
                paren_depth = 0
                in_quote = False
                quote_char = None
    
                for char in cols_block:
                    if char in ('"', "'") and not in_quote:
                        in_quote = True
                        quote_char = char
                    elif char == quote_char and in_quote:
                        in_quote = False
                        quote_char = None
                    elif char == '(' and not in_quote:
                        paren_depth += 1
                    elif char == ')' and not in_quote:
                        paren_depth -= 1
                    elif char == ',' and not in_quote and paren_depth == 0:
                        column_definitions.append(current_def.strip())
                        current_def = ""
                        continue
            
                    current_def += char
    
                # Add the last definition
                if current_def.strip():
                    column_definitions.append(current_def.strip())

                # Process each column definition
                for col_def in column_definitions:
                    col_def = col_def.strip()
        
                    # Skip empty lines and constraint definitions
                    if not col_def or col_def.upper().startswith(('FOREIGN KEY', 'CONSTRAINT', 'PRIMARY KEY', 'UNIQUE KEY')):
                        continue

                    # Extract column name - be more flexible with the regex
                    nm = re.match(r'([A-Za-z0-9_]+)\s+(.+)', col_def)
                    if not nm:
                        logging.warning(f"Could not parse column definition: {col_def}")
                        continue

                    col_name = nm.group(1)
                    col_definition = nm.group(2)

                    if col_name not in existing_cols:
                        logging.info(f"Adding missing column {col_name} to table {table}")
            
                        if is_safe_for_alter_table(col_def):
                            try:
                                # Clean the definition to remove unsafe parts
                                safe_col_def = clean_column_definition(col_def)
                                if safe_col_def:  # Only add if there's something left after cleaning
                                    alter_sql = f"ALTER TABLE {table} ADD COLUMN {safe_col_def};"
                                    logging.info(f"Executing: {alter_sql}")
                                    _cur.execute(alter_sql)
                                    logging.info(f"Successfully added column {col_name} to table {table}")
                            except Exception as e:
                                logging.error(f"Failed to add column {col_name} to table {table}: {e}")
                        else:
                            logging.info(f"Skipped column {col_name} (contains unsupported constraints for ALTER TABLE)")

            _conn.commit()
            _cur.close()
            _conn.close()

            conn.commit()
            logging.info("SQLite database initialized successfully")

        except Exception as e:
            logging.error(f"Failed to initialize SQLite database: {e}")
            raise
        finally:
            try:
                if cursor: cursor.close()
                if conn: conn.close()
            except:
                pass

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

def db_query_one(query, params=()):
    """
    Execute `query` with `params` and return a single row (or None).
    """
    return db_execute(query, params, fetchone=True)

def db_query_all(query, params=()):
    """
    Execute `query` with `params` and return all rows (possibly an empty list).
    """
    return db_execute(query, params, fetchall=True)
