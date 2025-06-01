# config.py - Configuration management
import os
import json
import secrets
import logging
import sys
from pathlib import Path

# ---- Paths & Constants ----
CONFIG_PATH = 'config.json'
BACKUP_DIR = 'backups'
LOG_DIR = 'logs'
APP_VERSION = '1.0.3'
DATABASE_VERSION = 1

# Default configuration settings
DEFAULT_CONFIG = {
    # Database settings
    "DB_TYPE": "sqlite",  # Options: sqlite, postgresql, mysql
    "DB_PATH": "auth.db",  # Used for SQLite
    "DB_HOST": "localhost",  # Used for PostgreSQL/MySQL
    "DB_PORT": 5432,  # Used for PostgreSQL/MySQL
    "DB_NAME": "vespeyr_auth",  # Used for PostgreSQL/MySQL
    "DB_USER": "",  # Used for PostgreSQL/MySQL
    "DB_PASSWORD": "",  # Used for PostgreSQL/MySQL
    "DB_POOL_SIZE": 10,  # Connection pool size
    "JWT_ALGORITHM": "RS256",  # Default to RS256
    "JWT_ISSUER": "vespeyr-auth-server",
    "JWT_AUDIENCE": "coherence-cloud-api",
    "FORCE_JWT_ALGORITHM": "RS256",         # Can be "RS256", "HS256" or None (auto-detect)
    
    # Server settings
    "HOST": "0.0.0.0",
    "PORT": 5000,
    "WORKERS": 1,  # Number of worker processes for production server
    "SERVER_TYPE": "development",  # Options: development, production
    
    # SMTP settings
    "SMTP_HOST": "smtp.ionos.com",
    "SMTP_PORT": 587,
    "SMTP_USER": "no-reply@vespeyr.com",
    "SMTP_PASS": "",
    "RESET_URL_BASE": "https://api.vespeyr.com/auth/reset-password?token=",
    "LOGIN_URL": "https://vespeyr.com/login",
    
    # Redis settings
    "REDIS_ENABLED": False,  # Set to True to enable Redis
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_PASSWORD": "",
    "REDIS_RATELIMIT_DB": 0,
    "REDIS_TOKEN_DB": 1,

    # Security settings
    "JWT_SECRET": "",  # Will prompt if empty
    "JWT_ISSUER": "vespeyr-auth-server",  # Issuer claim for JWT tokens
    "JWT_AUDIENCE": "coherence-cloud",    # Audience claim for JWT tokens
    "JWT_EXPIRATION": 86400,  # 24 hours
    "REFRESH_TOKEN_EXPIRATION": 2592000,  # 30 days
    "ALLOWED_ORIGINS": "http://localhost:3000,https://vespeyr.com",
    "PASSWORD_MIN_LENGTH": 8,
    "PASSWORD_REQUIRE_MIXED_CASE": True,
    "PASSWORD_REQUIRE_DIGIT": True,
    "PASSWORD_REQUIRE_SPECIAL": True,
    "PASSWORD_HISTORY_COUNT": 3,  # Remember previous passwords to prevent reuse
    "ACCOUNT_LOCKOUT_THRESHOLD": 5,  # Failed attempts before lockout
    "ACCOUNT_LOCKOUT_DURATION": 900,  # 15 minutes lockout in seconds
    "RATE_LIMIT_DEFAULT": "200 per day, 50 per hour",
    "RATE_LIMIT_LOGIN": "5 per minute",
    "RATE_LIMIT_RESET": "3 per hour",
    "SESSION_TIMEOUT": 1800,  # 30 minutes of inactivity
    "ENABLE_HTTPS_REDIRECT": False,
    "ENABLE_WELCOME_EMAIL": True,
    "SECURE_COOKIES": True,
    "DEBUG_MODE": False,
    
    # Logging settings
    "LOG_LEVEL": "DEBUG",
    "LOG_FORMAT": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    "LOG_MAX_SIZE": 10485760,  # 10MB
    "LOG_BACKUP_COUNT": 10,
    
    # Backup settings
    "BACKUP_INTERVAL": 86400,  # Daily backups (in seconds)
    "MAX_BACKUPS": 30,  # Keep a month of backups
    
    # Admin settings
    "ADMIN_USERNAME": "",  # Set during first run
    "ADMIN_EMAIL": "",  # Set during first run
    
    # Application settings
    "APP_NAME": "Vespeyr Authentication",
    "COMPANY_NAME": "Vespeyr Games",
    
    # Update settings
    "UPDATE_MANIFEST_URL": "https://dl.dropboxusercontent.com/scl/fi/pb05brur6fwvk18m7pj94/manifest.json?rlkey=d31bc51w1zfbtyajm7tq8p96y&dl=1",
    "CHECK_UPDATES_ON_STARTUP": True
}

def load_config():
    """Load config from file or create with defaults"""
    # First check for environment variables
    env_config = {}
    for key in DEFAULT_CONFIG.keys():
        env_var = f"VESPEYR_AUTH_{key}"
        if env_var in os.environ:
            env_val = os.environ[env_var]
            
            # Type conversion
            if isinstance(DEFAULT_CONFIG[key], bool):
                env_config[key] = env_val.lower() in ('true', 'yes', '1')
            elif isinstance(DEFAULT_CONFIG[key], int):
                try:
                    env_config[key] = int(env_val)
                except ValueError:
                    pass
            else:
                env_config[key] = env_val
                
    # Then check config file
    file_config = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                file_config = json.load(f)
        except json.JSONDecodeError:
            logging.error(f"Error: Invalid config file format. Creating backup and using defaults.")
            # Backup corrupted config
            if not os.path.exists(BACKUP_DIR):
                os.makedirs(BACKUP_DIR)
            import time
            backup_path = os.path.join(BACKUP_DIR, f"config_backup_{int(time.time())}.json")
            try:
                os.rename(CONFIG_PATH, backup_path)
            except:
                pass
    
    # Merge configs with priority: env vars > file > defaults
    cfg = DEFAULT_CONFIG.copy()
    cfg.update(file_config)  # File config overrides defaults
    cfg.update(env_config)   # Environment variables override file config
    
    # Ensure JWT_SECRET is set
    if not cfg["JWT_SECRET"]:
        # In interactive terminal, prompt for secret only if stdin exists and is a TTY
        if getattr(sys, "stdin", None) and sys.stdin.isatty() and 'pytest' not in sys.modules:
            print("\n⚠️  WARNING: No JWT_SECRET configured!")
            print("A secure JWT_SECRET is required for token signing.")
            print("Options: ")
            print("1. Set in config.json")
            print("2. Set VESPEYR_AUTH_JWT_SECRET environment variable")
            print("3. Generate random secret now (tokens will be invalidated if server restarts)\n")
            
            choice = input("Choose option (1-3) or press Enter to generate random secret: ")
            if choice.strip() == '1':
                secret = input("Enter your JWT_SECRET: ").strip()
                if secret:
                    cfg["JWT_SECRET"] = secret
                else:
                    cfg["JWT_SECRET"] = secrets.token_hex(32)
            elif choice.strip() == '2':
                print("Please set VESPEYR_AUTH_JWT_SECRET environment variable and restart.")
                sys.exit(1)
            else:
                logging.warning("Generating random JWT_SECRET. ALL TOKENS WILL BE INVALIDATED when server restarts!")
                cfg["JWT_SECRET"] = secrets.token_hex(32)
        else:
            # In non-interactive or no stdin mode, generate random secret but warn
            logging.warning("No JWT_SECRET configured. Using random secret. ALL TOKENS WILL BE INVALIDATED when server restarts!")
            cfg["JWT_SECRET"] = secrets.token_hex(32)
    
    # Create directories if they don't exist
    for directory in [os.path.dirname(CONFIG_PATH), BACKUP_DIR, LOG_DIR]:
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
    
    # Save config with any updates
    save_config(cfg)
    return cfg



def save_config(cfg):
    """Save config to file, omitting any sensitive values"""
    # Create a copy to avoid modifying the original
    save_cfg = cfg.copy()
    
    # Redact sensitive values when saving to file
    # They'll still be in memory and env vars can override
    sensitive_keys = ["JWT_SECRET", "SMTP_PASS", "DB_PASSWORD", "REDIS_PASSWORD"]
    for key in sensitive_keys:
        if key in save_cfg and save_cfg[key]:
            # If value exists in config file, keep it
            if os.path.exists(CONFIG_PATH):
                try:
                    with open(CONFIG_PATH, 'r') as f:
                        current_cfg = json.load(f)
                        if key in current_cfg and current_cfg[key] == save_cfg[key]:
                            # Keep the value, it's unchanged
                            pass
                        elif key in current_cfg and current_cfg[key] and current_cfg[key] != save_cfg[key]:
                            # Value changed, save new value
                            pass
                        else:
                            # Value is new, save it
                            pass
                except:
                    # On error, redact for safety
                    save_cfg[key] = "********" if save_cfg[key] else ""
            else:
                # New config file, save securely
                pass
    
    with open(CONFIG_PATH, 'w') as f:
        json.dump(save_cfg, f, indent=2)

# Initialize config
config = load_config()