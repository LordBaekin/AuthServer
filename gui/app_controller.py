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
        """Shut down the server gracefully - Enhanced to handle WebSocket server too."""
        if not self.server_running or not self.server_thread:
            return False
    
        try:
            logging.info("Initiating server shutdown...")
        
            # NEW: Try to stop WebSocket server if it exists on the thread
            if hasattr(self.server_thread, 'websocket_process'):
                try:
                    websocket_process = self.server_thread.websocket_process
                    if websocket_process and websocket_process.poll() is None:
                        logging.info("Stopping WebSocket chat server...")
                        websocket_process.terminate()
                        try:
                            websocket_process.wait(timeout=5)
                            logging.info("WebSocket chat server stopped")
                        except subprocess.TimeoutExpired:
                            logging.warning("WebSocket server didn't stop gracefully, killing...")
                            websocket_process.kill()
                            websocket_process.wait()
                            logging.info("WebSocket chat server killed")
                except Exception as e:
                    logging.error(f"Error stopping WebSocket server: {e}")
        
            # EXISTING LOGIC - unchanged
            # Try to use stop_event if available
            if hasattr(self.server_thread, 'stop_event') and self.server_thread.stop_event:
                logging.info("Shutting down Flask server gracefully via stop_event...")
                self.server_thread.stop_event.set()
            
                # Wait for the server thread to finish (with timeout)
                if self.server_thread.is_alive():
                    self.server_thread.join(timeout=10)  # Wait up to 10 seconds
                
                    if self.server_thread.is_alive():
                        logging.warning("Server thread did not stop within timeout period")
                    else:
                        logging.info("Flask server stopped successfully via stop_event")
                        # Stop task manager
                        if self.task_manager:
                            self.task_manager.stop()
                    
                        # Reset server state
                        self.server_running = False
                        self.server_thread = None
                        return True
            
            # Try to directly shutdown server instance
            if self._flask_server_instance:
                try:
                    if hasattr(self._flask_server_instance, 'shutdown'):
                        self._flask_server_instance.shutdown()
                    elif hasattr(self._flask_server_instance, 'terminate'):
                        self._flask_server_instance.terminate()
                    logging.info("Flask server instance shutdown requested")
                except Exception as e:
                    logging.error(f"Error shutting down Flask server instance: {e}")
        
            # Fall back to platform-specific termination methods
            import platform
            import os
        
            flask_port = self.config.get("PORT", 5000)
            websocket_port = flask_port + 1
            ports_to_kill = [flask_port, websocket_port]  # NEW: Kill both ports
        
            termination_success = False
        
            if platform.system() == "Windows":
                # On Windows, try to find and kill processes by port
                for port in ports_to_kill:  # NEW: Handle both ports
                    try:
                        result = os.system(f"FOR /F \"tokens=5\" %P IN ('netstat -ano ^| findstr :{port} ^| findstr LISTENING') DO taskkill /F /PID %P")
                        if result == 0:
                            logging.info(f"Terminated processes using port {port}")
                            termination_success = True
                        else:
                            logging.warning(f"No processes found using port {port} or termination failed")
                    except Exception as e:
                        logging.error(f"Failed to terminate server process on port {port}: {e}")
            else:
                # On Unix-like systems, try to use signals
                try:
                    # Try to find PID of server process
                    import signal
                    import psutil
                
                    killed_processes = []
                
                    # Find and kill Python processes listening on our ports
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                        try:
                            if proc.info['name'] in ['python', 'python3', 'gunicorn']:  # NEW: Also check for python3
                                for connection in proc.connections():
                                    if hasattr(connection, 'laddr') and connection.laddr.port in ports_to_kill:  # NEW: Check both ports
                                        if proc.info['pid'] not in killed_processes:
                                            os.kill(proc.info['pid'], signal.SIGTERM)
                                            killed_processes.append(proc.info['pid'])
                                            logging.info(f"Sent SIGTERM to process {proc.info['pid']} using port {connection.laddr.port}")
                                            termination_success = True
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            # Process may have died or we don't have permission
                            continue
                        except Exception as e:
                            logging.error(f"Error checking process {proc.info.get('pid', 'unknown')}: {e}")
                            continue
                
                    # NEW: Give processes time to shut down gracefully, then force kill if needed
                    if killed_processes:
                        import time
                        time.sleep(2)
                    
                        for pid in killed_processes:
                            try:
                                # Check if process still exists
                                proc = psutil.Process(pid)
                                if proc.is_running():
                                    logging.warning(f"Process {pid} still running, sending SIGKILL")
                                    os.kill(pid, signal.SIGKILL)
                            except (psutil.NoSuchProcess, ProcessLookupError):
                                # Process already terminated
                                continue
                            except Exception as e:
                                logging.error(f"Error force-killing process {pid}: {e}")
                            
                except ImportError:
                    logging.error("psutil not available, cannot terminate server processes by PID")
                except Exception as e:
                    logging.error(f"Failed to terminate server processes: {e}")
        
            # Stop task manager regardless of how we shut down
            if self.task_manager:
                try:
                    self.task_manager.stop()
                    logging.info("Task manager stopped")
                except Exception as e:
                    logging.error(f"Error stopping task manager: {e}")
        
            # Reset server state
            self.server_running = False
            self.server_thread = None
        
            logging.info("Server shutdown completed")
            return True
        
        except Exception as e:
            logging.error(f"Error during server shutdown: {e}")
        
            # Even if there was an error, reset the state
            try:
                if self.task_manager:
                    self.task_manager.stop()
            except:
                pass
            
            self.server_running = False
            self.server_thread = None
            return False
        
    def set_flask_server_instance(self, instance):
        """Store reference to Flask server instance for shutdown."""
        self._flask_server_instance = instance
