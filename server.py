# server.py - Main application entry point
import os
import sys
import time
import threading
import signal
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Import our modules
from config import config, APP_VERSION, LOG_DIR
from db import init_db
from gui import create_gui, task_manager

# Setup signal handlers
def signal_handler(sig, frame):
    logging.info('Received shutdown signal, exiting...')
    # Stop task manager if running
    if task_manager:
        task_manager.stop()
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def setup_logging():
    """Set up application logging"""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    
    # Set log level from config
    log_level_str = config.get("LOG_LEVEL", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # File handler for all logs
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'auth_server.log'),
        maxBytes=1024 * 1024 * 5,  # 5MB
        backupCount=20
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(log_level)
    root_logger.addHandler(file_handler)
    
    # Error-specific log
    error_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'error.log'),
        maxBytes=1024 * 1024 * 5,  # 5MB
        backupCount=20
    )
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)
    
    # Access log for all API requests
    access_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'access.log'),
        maxBytes=1024 * 1024 * 5,  # 5MB
        backupCount=10
    )
    access_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(message)s'
    ))
    access_logger = logging.getLogger('vespeyr.access')
    access_logger.setLevel(logging.INFO)
    access_logger.addHandler(access_handler)
    
    # Security log for authentication and security events
    security_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'security.log'),
        maxBytes=1024 * 1024 * 5,  # 5MB
        backupCount=30
    )
    security_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(message)s'
    ))
    security_logger = logging.getLogger('vespeyr.security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)
    
    # Also add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    console_handler.setLevel(log_level)     # <-- changed from INFO to use configured level
    root_logger.addHandler(console_handler)
    
    logging.info(f'Auth server v{APP_VERSION} logging initialized')
    return {
        'root': root_logger,
        'access': access_logger,
        'security': security_logger
    }

# Main entry point
if __name__ == "__main__":
    try:
        # Setup logging
        loggers = setup_logging()
        
        # Initialize the database
        init_db()
        
        logging.info(f"Starting Vespeyr Auth Server v{APP_VERSION}")
        
        # Create and start the GUI
        root = create_gui()
        root.mainloop()
        
    except Exception as e:
        print(f"Critical error: {str(e)}")
        logging.critical(f"Application failed to start: {str(e)}")
        sys.exit(1)
