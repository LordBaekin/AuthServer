# gui/app_controller.py - Central controller for the application
import logging
import time
import threading
from config import config

class AppController:
    """Central controller for the application."""
    
    def __init__(self):
        self.config = config
        self.server_running = False
        self.server_thread = None
        self.task_manager = None
        self.start_time = 0
        self.tabs = {}
        self._flask_server_instance = None
        
    def register_tab(self, name, tab_instance):
        """Register a tab with the controller."""
        self.tabs[name] = tab_instance
        
    def get_tab(self, name):
        """Get a tab by name."""
        return self.tabs.get(name)
        
    def update_config(self, new_config):
        """Update configuration and notify all tabs."""
        self.config = new_config
        for tab in self.tabs.values():
            if hasattr(tab, 'on_config_updated'):
                tab.on_config_updated(new_config)
                
    def set_server_status(self, running, thread=None):
        """Update server status and notify tabs."""
        self.server_running = running
        self.server_thread = thread
        if running and thread:
            self.start_time = thread.start_time if hasattr(thread, 'start_time') else int(time.time())
        else:
            self.start_time = 0
            
        for tab in self.tabs.values():
            if hasattr(tab, 'on_server_status_changed'):
                tab.on_server_status_changed(running)
    
    def get_uptime_string(self):
        """Get formatted uptime string."""
        if self.start_time <= 0:
            return "0h 0m 0s"
            
        uptime_seconds = int(time.time()) - self.start_time
        hours = uptime_seconds // 3600
        minutes = (uptime_seconds % 3600) // 60
        seconds = uptime_seconds % 60
        return f"{hours}h {minutes}m {seconds}s"
    
    def shutdown_server(self):
        """Shut down the server gracefully."""
        if not self.server_running or not self.server_thread:
            return False
            
        # Try to use stop_event if available
        if hasattr(self.server_thread, 'stop_event') and self.server_thread.stop_event:
            logging.info("Shutting down server gracefully via stop_event...")
            self.server_thread.stop_event.set()
            return True
            
        # Try to directly shutdown server instance
        if self._flask_server_instance:
            try:
                if hasattr(self._flask_server_instance, 'shutdown'):
                    self._flask_server_instance.shutdown()
                elif hasattr(self._flask_server_instance, 'terminate'):
                    self._flask_server_instance.terminate()
                logging.info("Server instance shutdown requested")
                return True
            except Exception as e:
                logging.error(f"Error shutting down server instance: {e}")
        
        # Fall back to platform-specific termination methods
        import platform
        import os
        
        if platform.system() == "Windows":
            # On Windows, try to find and kill the process by port
            port = self.config.get("PORT", 5000)
            try:
                os.system(f"FOR /F \"tokens=5\" %P IN ('netstat -ano ^| findstr :{port} ^| findstr LISTENING') DO taskkill /F /PID %P")
                logging.info(f"Terminated process using port {port}")
                return True
            except Exception as e:
                logging.error(f"Failed to terminate server process: {e}")
        else:
            # On Unix-like systems, try to use signals
            try:
                # Try to find PID of server process
                import signal
                import psutil
                
                # Find and kill Python processes listening on our port
                port = self.config.get("PORT", 5000)
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if proc.info['name'] == 'python' or proc.info['name'] == 'gunicorn':
                        for connection in proc.connections():
                            if connection.laddr.port == port:
                                os.kill(proc.info['pid'], signal.SIGTERM)
                                logging.info(f"Sent SIGTERM to process {proc.info['pid']}")
                                return True
            except Exception as e:
                logging.error(f"Failed to terminate server process: {e}")
                
        return False
        
    def set_flask_server_instance(self, instance):
        """Store reference to Flask server instance for shutdown."""
        self._flask_server_instance = instance
