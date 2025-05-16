# gui/scheduled_tasks.py - Background task manager
import threading
import time
import logging
from db import db_execute, backup_database

class ScheduledTasksManager:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread = None
        
    def start(self):
        if self.thread is None or not self.thread.is_alive():
            self.stop_event.clear()
            self.thread = threading.Thread(target=self._run_tasks, daemon=True)
            self.thread.start()
            logging.info("Scheduled tasks manager started")
            
    def stop(self):
        if self.thread and self.thread.is_alive():
            self.stop_event.set()
            self.thread.join(timeout=5)
            logging.info("Scheduled tasks manager stopped")
            
    def _run_tasks(self):
        # Track last run time for each task
        last_backup = 0
        last_session_cleanup = 0

        while not self.stop_event.is_set():
            current_time = int(time.time())

            # Database backup (ensure interval is an int)
            try:
                from config import config
                backup_interval = int(config.get("BACKUP_INTERVAL", 86400))
            except (TypeError, ValueError):
                backup_interval = 86400

            if current_time - last_backup >= backup_interval:
                try:
                    if backup_database():
                        last_backup = current_time
                except Exception as e:
                    logging.error(f"Scheduled backup failed: {e}")

            # Session cleanup - every hour
            if current_time - last_session_cleanup >= 3600:
                try:
                    # Remove expired sessions
                    db_execute(
                        'UPDATE user_sessions SET is_valid = 0 WHERE expires_at < ?',
                        (current_time,),
                        commit=True
                    )
                    last_session_cleanup = current_time
                except Exception as e:
                    logging.error(f"Session cleanup failed: {e}")

            # Sleep for a minute before checking again
            for _ in range(60):
                if self.stop_event.is_set():
                    break
                time.sleep(1)
