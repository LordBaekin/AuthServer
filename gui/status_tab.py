# gui/status_tab.py - Server status tab implementation
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import logging
import platform
import time
import os

from .base import BaseTab
from .utils import ConsoleRedirector
from .help_dialog import HelpDialog
from db import db_execute

class StatusTab(BaseTab):
    def __init__(self, parent, app_controller):
        self.status_var = None
        self.db_status_var = None
        self.email_status_var = None
        self.redis_status_var = None
        self.uptime_var = None
        self.user_count_var = None
        self.system_info_var = None
        self.db_type_var = None
        self.server_mode_var = None
        self.console_output = None
        self.status_indicator = None
        self.redis_indicator = None
        self.db_status_label = None  # Track the status label
        self.email_status_label = None  # Track the status label
        self.btn_toggle_server = None
        self.console_redirector = None
        self.update_timer = None
        self.status_indicators = None  # Keep reference to the frame
        super().__init__(parent, app_controller)
        
    def setup_ui(self):
        """Set up the server status tab UI."""
        # Header
        status_label = ttk.Label(self, text="Server Status", style='Header.TLabel')
        status_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
        
        # Status indicators frame
        self.status_indicators = ttk.LabelFrame(self, text="System Status")
        self.status_indicators.grid(column=0, row=1, sticky='ew', padx=5, pady=5, columnspan=2)
        
        # Server status indicator
        ttk.Label(self.status_indicators, text="Server:").grid(column=0, row=0, sticky='e', padx=(10, 5), pady=5)
        self.status_var = tk.StringVar(value="Stopped")
        self.status_indicator = ttk.Label(self.status_indicators, textvariable=self.status_var, 
                                        foreground='red', font=('Helvetica', 10, 'bold'))
        self.status_indicator.grid(column=1, row=0, sticky='w', pady=5)
        
        # Database status
        ttk.Label(self.status_indicators, text="Database:").grid(column=0, row=1, sticky='e', padx=(10, 5), pady=5)
        self.db_status_var = tk.StringVar(value="Not Connected")
        self.db_status_label = ttk.Label(self.status_indicators, textvariable=self.db_status_var, foreground='orange')
        self.db_status_label.grid(column=1, row=1, sticky='w', pady=5)
        
        # Email status
        ttk.Label(self.status_indicators, text="Email:").grid(column=0, row=2, sticky='e', padx=(10, 5), pady=5)
        self.email_status_var = tk.StringVar(value="Not Configured")
        self.email_status_label = ttk.Label(self.status_indicators, textvariable=self.email_status_var, foreground='orange')
        self.email_status_label.grid(column=1, row=2, sticky='w', pady=5)

        # Redis status
        ttk.Label(self.status_indicators, text="Redis:").grid(column=0, row=3, sticky='e', padx=(10, 5), pady=5)
        self.redis_status_var = tk.StringVar(value="Disabled")
        self.redis_indicator = ttk.Label(self.status_indicators, textvariable=self.redis_status_var, foreground='gray')
        self.redis_indicator.grid(column=1, row=3, sticky='w', pady=5)
        
        # Uptime
        ttk.Label(self.status_indicators, text="Uptime:").grid(column=2, row=0, sticky='e', padx=(20, 5), pady=5)
        self.uptime_var = tk.StringVar(value="0h 0m 0s")
        ttk.Label(self.status_indicators, textvariable=self.uptime_var).grid(column=3, row=0, sticky='w', pady=5)
        
        # User count
        ttk.Label(self.status_indicators, text="Users:").grid(column=2, row=1, sticky='e', padx=(20, 5), pady=5)
        self.user_count_var = tk.StringVar(value="0")
        ttk.Label(self.status_indicators, textvariable=self.user_count_var).grid(column=3, row=1, sticky='w', pady=5)
        
        # System info
        ttk.Label(self.status_indicators, text="System:").grid(column=2, row=2, sticky='e', padx=(20, 5), pady=5)
        self.system_info_var = tk.StringVar(value=f"{platform.system()} {platform.release()}")
        ttk.Label(self.status_indicators, textvariable=self.system_info_var).grid(column=3, row=2, sticky='w', pady=5)
        
        # Database type
        ttk.Label(self.status_indicators, text="DB Type:").grid(column=4, row=0, sticky='e', padx=(20, 5), pady=5)
        self.db_type_var = tk.StringVar(value=self.app_controller.config.get("DB_TYPE", "sqlite"))
        ttk.Label(self.status_indicators, textvariable=self.db_type_var).grid(column=5, row=0, sticky='w', pady=5)
        
        # Server mode
        ttk.Label(self.status_indicators, text="Server Mode:").grid(column=4, row=1, sticky='e', padx=(20, 5), pady=5)
        self.server_mode_var = tk.StringVar(value=self.app_controller.config.get("SERVER_TYPE", "development"))
        ttk.Label(self.status_indicators, textvariable=self.server_mode_var).grid(column=5, row=1, sticky='w', pady=5)
        
        # Server console output section
        console_frame = ttk.LabelFrame(self, text="Server Console")
        console_frame.grid(column=0, row=3, sticky='nsew', padx=5, pady=5, columnspan=2)
        self.rowconfigure(3, weight=1)
        
        self.console_output = scrolledtext.ScrolledText(console_frame, height=15, bg='black', fg='white', wrap=tk.NONE)
        self.console_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.console_output.config(state=tk.DISABLED)
        
        # Redirect console output
        self.console_redirector = ConsoleRedirector(self.console_output)
        
        # Control buttons
        controls_frame = ttk.Frame(self)
        controls_frame.grid(column=0, row=4, columnspan=2, sticky='ew', padx=5, pady=10)
        
        self.btn_toggle_server = ttk.Button(controls_frame, text="Start Server", command=self.toggle_server_state)
        self.btn_toggle_server.grid(column=0, row=0, padx=5, pady=5)
        
        ttk.Button(controls_frame, text="Clear Console", command=self.clear_console).grid(
            column=1, row=0, padx=5, pady=5
        )
        
        ttk.Button(controls_frame, text="Help", command=self.open_help_dialog).grid(
            column=2, row=0, padx=5, pady=5
        )
    
    def toggle_server_state(self):
        """Toggle the server state (start/stop)."""
        if not self.app_controller.server_running:
            # Start server
            # Save config changes first
            from .config_tab import ConfigTab
            config_tab = self.app_controller.get_tab('config')
            if config_tab:
                config_tab.save_config_changes()
            
            # Update display values
            self.db_type_var.set(self.app_controller.config.get("DB_TYPE", "sqlite"))
            self.server_mode_var.set(self.app_controller.config.get("SERVER_TYPE", "development"))
            
            try:
                # Import run_server from the server_runner in this package
                from .server_runner import run_server
                
                # Create a stop event for graceful shutdown
                stop_event = threading.Event()
                
                server_thread = threading.Thread(
                    target=run_server,
                    args=(
                        self.app_controller.config["HOST"], 
                        self.app_controller.config["PORT"],
                        self.app_controller.config.get("DEBUG_MODE", False), 
                        stop_event
                    ),
                    daemon=True
                )
                server_thread.start_time = int(time.time())
                server_thread.stop_event = stop_event  # Store the stop event on the thread
                server_thread.start()
                
                # Start task manager
                self.app_controller.task_manager.start()
                
                # Update app controller state
                self.app_controller.set_server_status(True, server_thread)
                
                self.status_var.set(
                    f"Running on {self.app_controller.config['HOST']}:{self.app_controller.config['PORT']}"
                )
                self.status_indicator.config(foreground='green')
                self.btn_toggle_server.config(text='Stop Server')
                
                # Log startup
                self.console_output.config(state=tk.NORMAL)
                self.console_output.insert(
                    tk.END, 
                    f"Server started on {self.app_controller.config['HOST']}:{self.app_controller.config['PORT']}\n"
                )
                if self.app_controller.config.get("SERVER_TYPE") == "production":
                    self.console_output.insert(tk.END, "Running in PRODUCTION mode with Gunicorn\n")
                else:
                    self.console_output.insert(tk.END, "Running in DEVELOPMENT mode with Flask\n")
                
                self.console_output.see(tk.END)
                self.console_output.config(state=tk.DISABLED)
                
                # Update status indicators
                self.update_status_indicators()
            
            except Exception as e:
                messagebox.showerror("Server Error", f"Failed to start server: {str(e)}")
                logging.error(f"Failed to start server: {str(e)}")
        else:
            # Stop server
            if self.app_controller.shutdown_server():
                # Show message to user
                self.console_output.config(state=tk.NORMAL)
                self.console_output.insert(tk.END, "Server shutdown initiated. Please wait...\n")
                self.console_output.see(tk.END)
                self.console_output.config(state=tk.DISABLED)
                
                # Wait a moment to let the server start shutting down
                self.update()
                time.sleep(0.5)
                
                # Update UI
                self.status_var.set("Stopped")
                self.status_indicator.config(foreground='red')
                self.btn_toggle_server.config(text='Start Server')
                
                # Update app controller state
                self.app_controller.set_server_status(False, None)
                
                # Show success message
                self.console_output.config(state=tk.NORMAL)
                self.console_output.insert(tk.END, "Server has been stopped.\n")
                self.console_output.see(tk.END)
                self.console_output.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", "Failed to stop server gracefully.")
    
    def clear_console(self):
        """Clear the console output."""
        self.console_output.config(state=tk.NORMAL)
        self.console_output.delete(1.0, tk.END)
        self.console_output.config(state=tk.DISABLED)
    
    def open_help_dialog(self):
        """Open the help dialog."""
        HelpDialog(self.winfo_toplevel())
    
    def update_status_indicators(self):
        """Update status indicators with current state."""
        if not self.app_controller.server_running:
            return
        
        try:
            # Check database
            db_ok = False
            try:
                db_execute('SELECT 1', fetchone=True)
                self.db_status_var.set("Connected")
                self.db_status_label.config(foreground='green')
                db_ok = True
            except:
                self.db_status_var.set("Error")
                self.db_status_label.config(foreground='red')
        
            # Check email
            smtp_ok = False
            if self.app_controller.config["SMTP_HOST"] and self.app_controller.config["SMTP_USER"] and self.app_controller.config["SMTP_PASS"]:
                try:
                    import smtplib
                    with smtplib.SMTP(self.app_controller.config["SMTP_HOST"], 
                                     self.app_controller.config["SMTP_PORT"], timeout=3) as smtp:
                        smtp.starttls()
                        smtp.login(self.app_controller.config["SMTP_USER"], 
                                  self.app_controller.config["SMTP_PASS"])
                        smtp_ok = True
                        self.email_status_var.set("Configured")
                        self.email_status_label.config(foreground='green')
                except:
                    self.email_status_var.set("Error")
                    self.email_status_label.config(foreground='red')
            else:
                self.email_status_var.set("Not Configured")
                self.email_status_label.config(foreground='orange')
        
            # Check Redis if enabled
            if self.app_controller.config.get("REDIS_ENABLED", False):
                try:
                    # Import redis_service dynamically to avoid importing if not needed
                    import importlib
                    try:
                        redis_service = importlib.import_module('redis_service')
                        redis_status = redis_service.check_redis_connection()
                    
                        if redis_status['overall']:
                            self.redis_status_var.set("Connected")
                            self.redis_indicator.config(foreground='green')
                        else:
                            if redis_status['rate_limit'] and not redis_status['token']:
                                self.redis_status_var.set("Partial (Rate limiting only)")
                                self.redis_indicator.config(foreground='orange')
                            elif not redis_status['rate_limit'] and redis_status['token']:
                                self.redis_status_var.set("Partial (Token only)")
                                self.redis_indicator.config(foreground='orange')
                            else:
                                self.redis_status_var.set("Error")
                                self.redis_indicator.config(foreground='red')
                    except ImportError:
                        self.redis_status_var.set("Module Error")
                        self.redis_indicator.config(foreground='red')
                        logging.error("redis_service module not found")
                except Exception as e:
                    self.redis_status_var.set("Error")
                    self.redis_indicator.config(foreground='red')
                    logging.error(f"Redis status check failed: {e}")
            else:
                self.redis_status_var.set("Disabled")
                self.redis_indicator.config(foreground='gray')
                        
            # Update uptime
            self.uptime_var.set(self.app_controller.get_uptime_string())
            
            # Update user count
            try:
                users = db_execute('SELECT COUNT(*) as count FROM users', fetchone=True)
                if users:
                    self.user_count_var.set(str(users['count']))
            except:
                pass
                
        except Exception as e:
            logging.error(f"Status update error: {str(e)}")
        
        # Schedule next update
        self.update_timer = self.after(5000, self.update_status_indicators)
        
    def on_tab_selected(self):
        """Called when this tab is selected."""
        # Start periodic updates
        self.update_status_indicators()
        
    def on_tab_deselected(self):
        """Called when this tab is deselected."""
        # Cancel pending timer
        if self.update_timer:
            self.after_cancel(self.update_timer)
            self.update_timer = None
            
    def on_server_status_changed(self, running):
        """Called when server status changes."""
        if running:
            self.status_var.set(
                f"Running on {self.app_controller.config['HOST']}:{self.app_controller.config['PORT']}"
            )
            self.status_indicator.config(foreground='green')
            self.btn_toggle_server.config(text='Stop Server')
        else:
            self.status_var.set("Stopped")
            self.status_indicator.config(foreground='red')
            self.btn_toggle_server.config(text='Start Server')