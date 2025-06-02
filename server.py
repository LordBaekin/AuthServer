# server.py - Main application entry point
import os
import sys
import signal
import logging
import sqlite3
import time
from logging.handlers import RotatingFileHandler

# Import our modules
from config import config, APP_VERSION, LOG_DIR
from db import init_db, execute_script, DB_SCHEMA_SQLITE, DB_SCHEMA_MYSQL, db_execute
from gui import create_gui, task_manager

# Setup signal handlers
def signal_handler(sig, frame):
    logging.info('Received shutdown signal, exiting...')
    if task_manager:
        task_manager.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def setup_logging():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    log_level_str = config.get("LOG_LEVEL", "INFO")
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'auth_server.log'),
        maxBytes=1024 * 1024 * 5,
        backupCount=20
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(log_level)
    root_logger.addHandler(file_handler)

    error_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'error.log'),
        maxBytes=1024 * 1024 * 5,
        backupCount=20
    )
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    error_handler.setLevel(logging.ERROR)
    root_logger.addHandler(error_handler)

    access_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'access.log'),
        maxBytes=1024 * 1024 * 5,
        backupCount=10
    )
    access_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    access_logger = logging.getLogger('vespeyr.access')
    access_logger.setLevel(logging.INFO)
    access_logger.addHandler(access_handler)

    security_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, 'security.log'),
        maxBytes=1024 * 1024 * 5,
        backupCount=30
    )
    security_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    security_logger = logging.getLogger('vespeyr.security')
    security_logger.setLevel(logging.INFO)
    security_logger.addHandler(security_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    console_handler.setLevel(log_level)
    root_logger.addHandler(console_handler)

    logging.info(f'Auth server v{APP_VERSION} logging initialized')
    return {
        'root': root_logger,
        'access': access_logger,
        'security': security_logger
    }

def fix_database_constraints():
    """
    Fix the database schema constraints to resolve ON CONFLICT issues
    """
    try:
        # Check if we're using SQLite
        if config.get("DB_TYPE", "sqlite") == "sqlite":
            logging.info("Checking and fixing database constraints...")
            
            conn = sqlite3.connect(config.get("DB_PATH", "auth.db"))
            cursor = conn.cursor()
            
            # Track if any changes were made
            changes_made = False
            
            # Check current schema for inventory table
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='inventory'")
            result = cursor.fetchone()
            
            if result:
                table_sql = result[0]
                logging.debug(f"Current inventory table schema: {table_sql}")
                
                # Check if the constraint includes scene properly
                if "CONSTRAINT uq_inventory" in table_sql or ("UNIQUE" in table_sql and "scene" not in table_sql.split("UNIQUE")[1].split(")")[0]):
                    logging.info("Fixing inventory table constraint to include scene column...")
                    
                    try:
                        # Backup existing data
                        cursor.execute("SELECT * FROM inventory")
                        inventory_data = cursor.fetchall()
                        
                        # Get column info to preserve structure
                        cursor.execute("PRAGMA table_info(inventory)")
                        columns = cursor.fetchall()
                        
                        # Drop and recreate table with correct constraint
                        cursor.execute("DROP TABLE IF EXISTS inventory_backup")
                        cursor.execute("ALTER TABLE inventory RENAME TO inventory_backup")
                        
                        # Create new table with proper constraint
                        cursor.execute("""
                            CREATE TABLE inventory (
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
                                UNIQUE (user_id, world_key, save_key, scene)
                            )
                        """)
                        
                        # Restore data if it exists
                        if inventory_data:
                            # Handle missing scene data by setting default
                            fixed_data = []
                            for row in inventory_data:
                                row_list = list(row)
                                # If scene column is missing or empty, set default
                                if len(row_list) < 5 or not row_list[4]:
                                    row_list[4] = "default"
                                fixed_data.append(tuple(row_list))
                            
                            cursor.executemany(
                                """
                                INSERT INTO inventory 
                                (id, user_id, world_key, save_key, scene, ui_data, scene_data, created_at, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                fixed_data
                            )
                        
                        # Drop backup table
                        cursor.execute("DROP TABLE inventory_backup")
                        logging.info("Inventory table constraint fixed successfully")
                        changes_made = True
                    
                    except Exception as e:
                        logging.error(f"Failed to fix inventory table: {e}")
                        # Try to restore from backup if it exists
                        try:
                            cursor.execute("DROP TABLE IF EXISTS inventory")
                            cursor.execute("ALTER TABLE inventory_backup RENAME TO inventory")
                            logging.info("Restored inventory table from backup")
                        except:
                            pass
            
            # Fix other tables to use unnamed constraints for better ON CONFLICT support
            for table_name in ["quests", "stats"]:
                cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='table' AND name='{table_name}'")
                result = cursor.fetchone()
                
                if result:
                    table_sql = result[0]
                    if f"CONSTRAINT uq_{table_name}" in table_sql:
                        logging.info(f"Fixing {table_name} table to use unnamed unique constraint...")
                        
                        try:
                            # Backup data
                            cursor.execute(f"SELECT * FROM {table_name}")
                            table_data = cursor.fetchall()
                            
                            # Get column info
                            cursor.execute(f"PRAGMA table_info({table_name})")
                            columns = cursor.fetchall()
                            
                            # Drop and recreate
                            cursor.execute(f"ALTER TABLE {table_name} RENAME TO {table_name}_backup")
                            
                            if table_name == "quests":
                                cursor.execute("""
                                    CREATE TABLE quests (
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
                                        UNIQUE (user_id, world_key, save_key)
                                    )
                                """)
                            elif table_name == "stats":
                                cursor.execute("""
                                    CREATE TABLE stats (
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
                                        UNIQUE (user_id, world_key, save_key)
                                    )
                                """)
                            
                            # Restore data
                            if table_data:
                                column_names = ", ".join([col[1] for col in columns])
                                placeholders = ", ".join(["?" for _ in columns])
                                cursor.executemany(
                                    f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders})",
                                    table_data
                                )
                            
                            cursor.execute(f"DROP TABLE {table_name}_backup")
                            logging.info(f"{table_name} table constraint fixed successfully")
                            changes_made = True
                            
                        except Exception as e:
                            logging.error(f"Failed to fix {table_name} table: {e}")
                            # Try to restore from backup
                            try:
                                cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
                                cursor.execute(f"ALTER TABLE {table_name}_backup RENAME TO {table_name}")
                                logging.info(f"Restored {table_name} table from backup")
                            except:
                                pass
            
            # Recreate indexes after table changes
            if changes_made:
                logging.info("Recreating database indexes...")
                try:
                    # Indexes for game data tables
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_inventory_user_world_scene ON inventory (user_id, world_key, save_key, scene)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_quests_user_world_key ON quests (user_id, world_key, save_key)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_stats_user_world_key ON stats (user_id, world_key, save_key)")
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_characters_user_world_name ON characters (user_id, world_key, character_name)")
                    logging.info("Database indexes recreated successfully")
                except Exception as e:
                    logging.warning(f"Some indexes may not have been created: {e}")
            
            conn.commit()
            conn.close()
            
            if changes_made:
                logging.info("Database constraint fixes completed successfully")
            else:
                logging.info("Database constraints are already correct, no changes needed")
            
            return True
            
        else:
            # For MySQL, the constraints should work correctly with ON CONFLICT equivalents
            logging.info("MySQL database detected - constraint fixes not needed")
            return True
            
    except Exception as e:
        logging.error(f"Failed to fix database constraints: {e}")
        return False

def run_initial_migration():
    """
    Run initial database schema migration and constraint fixes
    """
    try:
        db_type = config.get("DB_TYPE", "sqlite").lower()
        if db_type == 'sqlite':
            logging.info("Running SQLite schema migration...")
            execute_script(DB_SCHEMA_SQLITE)
        elif db_type == 'mysql':
            logging.info("Running MySQL schema migration...")
            execute_script(DB_SCHEMA_MYSQL)
        else:
            logging.warning(f"⚠️ Unknown database type '{db_type}'; skipping migration.")
            
        # After basic schema is in place, fix any constraint issues
        logging.info("Running database constraint fixes...")
        constraint_fix_success = fix_database_constraints()
        
        if not constraint_fix_success:
            logging.warning("⚠️ Database constraint fixes failed, but continuing startup...")
        
    except Exception as e:
        logging.critical(f"Schema migration failed: {str(e)}")
        # Don't exit here, let the application try to continue
        logging.warning("Continuing startup despite migration errors...")

def check_database_health():
    """
    Perform basic database health checks on startup
    """
    try:
        logging.info("Performing database health check...")
        
        # Test basic connectivity
        result = db_execute('SELECT 1', fetchone=True)
        if not result:
            raise Exception("Database connectivity test failed")
        
        # Check if required tables exist
        required_tables = ['users', 'user_sessions', 'inventory', 'quests', 'stats', 'characters']
        
        if config.get("DB_TYPE", "sqlite") == "sqlite":
            existing_tables = db_execute(
                "SELECT name FROM sqlite_master WHERE type='table'",
                fetchall=True
            )
            table_names = {row['name'] for row in existing_tables} if existing_tables else set()
        else:
            # MySQL
            existing_tables = db_execute("SHOW TABLES", fetchall=True)
            table_names = {list(row.values())[0] for row in existing_tables} if existing_tables else set()
        
        missing_tables = [table for table in required_tables if table not in table_names]
        
        if missing_tables:
            logging.warning(f"Missing database tables: {missing_tables}")
        else:
            logging.info("[OK] All required database tables present")
        
        # Test table operations
        try:
            # Test users table
            user_count = db_execute('SELECT COUNT(*) as count FROM users', fetchone=True)
            logging.info(f"[OK] Database health check passed - {user_count['count'] if user_count else 0} users registered")
        except Exception as e:
            logging.warning(f"Database table operation test failed: {e}")
        
        return True
        
    except Exception as e:
        logging.error(f"Database health check failed: {e}")
        return False

if __name__ == "__main__":
    try:
        # Setup logging first
        loggers = setup_logging()
        
        # Initialize database
        logging.info("Initializing database...")
        init_db()
        
        # Run migrations and fixes
        run_initial_migration()
        
        # Perform health check
        health_ok = check_database_health()
        if not health_ok:
            logging.warning("⚠️ Database health check failed, but continuing startup...")
        
        # Start the main application
        logging.info(f"Starting Vespeyr Auth Server v{APP_VERSION}")
        logging.info("=" * 50)
        
        # Create and run GUI
        root = create_gui()
        root.mainloop()
        
    except KeyboardInterrupt:
        logging.info("Received keyboard interrupt, shutting down...")
        sys.exit(0)
    except Exception as e:
        error_msg = f"Critical error during startup: {str(e)}"
        print(error_msg)
        logging.critical(error_msg)
        logging.exception("Full exception details:")
        sys.exit(1)
    finally:
        # Cleanup on exit
        if 'task_manager' in globals() and task_manager:
            try:
                task_manager.stop()
            except:
                pass
        logging.info("Auth server shutdown complete")