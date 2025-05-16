# gui.py - GUI interface for the authentication server
import os
import sys
import time
import platform
import threading
import logging
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime
import subprocess
import shutil

# Import modules
from config import config, save_config, DEFAULT_CONFIG, BACKUP_DIR, APP_VERSION, LOG_DIR
from db import db_execute, init_db, backup_database
from api_console import ApiConsoleFrame

# Global variables
server_running = False
server_thread = None
start_time = 0
task_manager = None


def check_db_pool_status():
    """Check status of database connection pool and display diagnostic information"""
    try:
        # Import needed modules
        from db import _sqlite_pool, _mysql_pool
        
        # For SQLite
        if config.get("DB_TYPE", "sqlite") == "sqlite" and _sqlite_pool:
            with _sqlite_pool.lock:
                total = len(_sqlite_pool.connections)
                in_use = len(_sqlite_pool.in_use)
                max_conns = _sqlite_pool.max_connections
                
                # Access connection metadata from the pool
                _connection_metadata = getattr(_sqlite_pool, '_connection_metadata', {})
                
                # Calculate ages
                now = time.time()
                ages = []
                for conn in _sqlite_pool.connections:
                    conn_id = id(conn)
                    if conn_id in _connection_metadata:
                        ages.append(now - _connection_metadata[conn_id]['created_time'])
                
                avg_age = sum(ages) / len(ages) if ages else 0
                
                message = (f"SQLite Connection Pool Status:\n\n"
                          f"Total connections: {total}/{max_conns}\n"
                          f"In use: {in_use}\n"
                          f"Idle: {total - in_use}\n"
                          f"Average connection age: {avg_age:.1f}s\n\n")
                
                # Add detailed connection info
                message += "Connection Details:\n"
                for i, conn in enumerate(_sqlite_pool.connections):
                    conn_id = id(conn)
                    if conn_id in _connection_metadata:
                        age = now - _connection_metadata[conn_id]['created_time']
                    else:
                        age = 0
                    status = "IN USE" if conn in _sqlite_pool.in_use else "idle"
                    message += f"Conn #{i+1}: {status}, Age: {age:.1f}s\n"
            
            messagebox.showinfo("Connection Pool Status", message)
            
            # Warn if running low on connections
            if in_use >= max_conns * 0.8:
                messagebox.showwarning("Connection Pool Warning", 
                                      f"Connection pool is at {in_use}/{max_conns} capacity.\n"
                                      f"Consider increasing DB_POOL_SIZE in config.json or check for connection leaks.")
                
        # For MySQL
        elif config.get("DB_TYPE", "sqlite") == "mysql" and _mysql_pool:
            with _mysql_pool.lock:
                total = len(_mysql_pool.connections)
                in_use = len(_mysql_pool.in_use)
                max_conns = _mysql_pool.max_connections
            
            message = (f"MySQL Connection Pool Status:\n\n"
                      f"Total connections: {total}/{max_conns}\n"
                      f"In use: {in_use}\n"
                      f"Idle: {total - in_use}")
                      
            messagebox.showinfo("Connection Pool Status", message)
            
            # Warn if running low on connections
            if in_use >= max_conns * 0.8:
                messagebox.showwarning("Connection Pool Warning", 
                                      f"Connection pool is at {in_use}/{max_conns} capacity.\n"
                                      f"Consider increasing DB_POOL_SIZE in config.json or check for connection leaks.")
        else:
            messagebox.showinfo("Connection Pool Status", "No active database connection pool found.")
    except Exception as e:
        logging.error(f"Failed to check pool status: {str(e)}")
        messagebox.showerror("Error", f"Failed to check connection pool status: {str(e)}")

def force_db_connection_cleanup():
    """Force cleanup of all idle database connections"""
    try:
        # Import needed modules
        from db import _sqlite_pool
        
        # For SQLite
        if config.get("DB_TYPE", "sqlite") == "sqlite" and _sqlite_pool:
            # Get stats before cleanup
            with _sqlite_pool.lock:
                before_total = len(_sqlite_pool.connections)
                before_in_use = len(_sqlite_pool.in_use)
                
            # Force cleanup
            _sqlite_pool._cleanup_old_connections()
            
            # Get stats after cleanup
            with _sqlite_pool.lock:
                after_total = len(_sqlite_pool.connections)
                after_in_use = len(_sqlite_pool.in_use)
                
            # Calculate differences
            closed = before_total - after_total
            
            message = (f"Connection Cleanup Results:\n\n"
                      f"Connections before: {before_total} (in use: {before_in_use})\n"
                      f"Connections after: {after_total} (in use: {after_in_use})\n"
                      f"Connections closed: {closed}")
                      
            messagebox.showinfo("Connection Cleanup", message)
            
            # Log the action
            logging.info(f"Manual connection cleanup: {closed} connections closed")
        else:
            messagebox.showinfo("Connection Cleanup", "No active SQLite connection pool found or using MySQL.")
    except Exception as e:
        logging.error(f"Failed to cleanup connections: {str(e)}")
        messagebox.showerror("Error", f"Failed to cleanup connections: {str(e)}")

def reset_db_connection_pool():
    """Reset the database connection pool completely"""
    if messagebox.askyesno("Reset Connection Pool", 
                          "Are you sure you want to reset the connection pool?\n"
                          "This will close all existing database connections."):
        try:
            # Import reset function
            from db import reset_connection_pool
            
            # Reset the pool
            reset_connection_pool()
            
            messagebox.showinfo("Success", "Database connection pool has been reset.")
            logging.info("Manual connection pool reset performed")
        except Exception as e:
            logging.error(f"Failed to reset connection pool: {str(e)}")
            messagebox.showerror("Error", f"Failed to reset connection pool: {str(e)}")

# Console output redirector
class ConsoleRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
        
    def write(self, message):
        # Convert bytes to string if necessary
        if isinstance(message, bytes):
            try:
                message = message.decode('utf-8')
            except UnicodeDecodeError:
                message = str(message)
        
        # Write to original stdout
        self.stdout.write(message)
        
        # Update text widget in GUI
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)
        self.text_widget.config(state=tk.DISABLED)
        
    def flush(self):
        self.stdout.flush()

# Help dialog
class HelpDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Vespeyr Auth Server Help")
        self.dialog.geometry("800x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Create notebook for help tabs
        self.notebook = ttk.Notebook(self.dialog)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General overview tab
        general_frame = ttk.Frame(self.notebook)
        self.notebook.add(general_frame, text="Overview")
        
        general_text = scrolledtext.ScrolledText(general_frame, wrap=tk.WORD)
        general_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        general_text.insert(tk.END, f"""
        This application provides a complete authentication system for your 
        Vespeyr game with user registration, login, password management, and 
        session tracking.
        
        Key features:
        - Secure user authentication with bcrypt password hashing
        - JWT token-based authentication
        - Password reset via email
        - Session management
        - Account security protections (rate limiting, lockouts)
        - Admin interface for user management
        - Security event logging
        - Automated backups
        
        Getting Started:
        1. Configure your settings in the Configuration tab
        2. Start the server using the "Start Server" button
        3. Your authentication APIs will be available at:
           http://{config["HOST"]}:{config["PORT"]}/auth/
        
        For more details about specific API endpoints, see the API tab.
        """)
        general_text.config(state=tk.DISABLED)
        
        # API Documentation tab
        api_frame = ttk.Frame(self.notebook)
        self.notebook.add(api_frame, text="API Endpoints")
        
        api_text = scrolledtext.ScrolledText(api_frame, wrap=tk.WORD)
        api_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        api_text.insert(tk.END, """
        Available API Endpoints:
        
        Public Endpoints:
        ------------------------
        GET /health
          Check server health
          
        POST /auth/register
          Register a new user
          Body: {"username": "user", "email": "user@example.com", "password": "secure_password"}
          
        POST /auth/login
          Authenticate a user
          Body: {"username": "user", "password": "secure_password"}
          
        POST /auth/request-password-reset
          Request a password reset link
          Body: {"email": "user@example.com"}
          
        POST /auth/reset-password
          Reset password using a token
          Body: {"token": "reset_token", "new_password": "new_secure_password"}
        
        Protected Endpoints (require Bearer token):
        ------------------------
        GET /auth/profile
          Get user profile information
          Header: Authorization: Bearer <token>
          
        POST /auth/change-password
          Change password
          Header: Authorization: Bearer <token>
          Body: {"current_password": "old_password", "new_password": "new_password"}
          
        POST /auth/logout
          Logout (invalidate token)
          Header: Authorization: Bearer <token>
          
        POST /auth/refresh
          Refresh an access token
          Body: {"refresh_token": "refresh_token"}
          
        GET /auth/sessions
          List all active sessions
          Header: Authorization: Bearer <token>
          
        POST /auth/sessions/revoke
          Revoke sessions
          Header: Authorization: Bearer <token>
          Body: {"all_except_current": true} or {"token": "session_token"}
          
        Admin Endpoints (require admin privileges):
        ------------------------
        GET /auth/admin/users
          List all users
          Header: Authorization: Bearer <admin_token>
          
        PUT /auth/admin/users/<user_id>
          Update user status
          Header: Authorization: Bearer <admin_token>
          Body: {"account_status": "active|locked|suspended"}
          
        GET /auth/admin/security-log
          View security logs
          Header: Authorization: Bearer <admin_token>
          
        GET /auth/admin/stats
          Get system statistics
          Header: Authorization: Bearer <admin_token>
        """)
        api_text.config(state=tk.DISABLED)
        
        # Security tab
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="Security")
        
        security_text = scrolledtext.ScrolledText(security_frame, wrap=tk.WORD)
        security_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        security_text.insert(tk.END, """
        Security Features:
        
        Password Security:
        - Passwords are hashed using bcrypt with per-password salts
        - Configurable password strength requirements
        - Password history to prevent reuse
        - Secure password reset flow
        
        Account Protection:
        - Rate limiting on login and password reset endpoints
        - Account lockout after configurable number of failed attempts
        - Security event logging for audit trails
        - Email notifications for sensitive actions
        
        API Security:
        - JWT token-based authentication with configurable expiration
        - HTTPS redirection
        - CORS protection
        - Security headers (HSTS, CSP, XSS, etc.)
        - Input sanitization
        
        Data Protection:
        - Automated database backups
        - Session monitoring and management
        - No sensitive data exposure in logs or responses
        
        Best Practices:
        - Always use HTTPS in production
        - Regularly rotate JWT secrets
        - Keep the server updated
        - Monitor security logs for suspicious activity
        - Configure email notifications for important events
        - Implement frontend security as well (CSRF, XSS protection)
        """)
        security_text.config(state=tk.DISABLED)
        
        # Production Deployment tab (new)
        deploy_frame = ttk.Frame(self.notebook)
        self.notebook.add(deploy_frame, text="Production")
        
        deploy_text = scrolledtext.ScrolledText(deploy_frame, wrap=tk.WORD)
        deploy_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        deploy_text.insert(tk.END, """
        Production Deployment Recommendations:
        
        Database:
        - Use MySQL or PostgreSQL instead of SQLite for production
        - Set DB_TYPE="mysql" in configuration
        - Configure proper database credentials
        - Enable regular automated backups
        
        Web Server:
        - Use a proper WSGI server (Gunicorn) for production
        - Set SERVER_TYPE="production" in configuration 
        - Run behind a reverse proxy like Nginx or Apache for TLS termination
        - Enable HTTPS with proper certificates
        
        Scaling:
        - Increase worker count (WORKERS setting) based on CPU cores
        - Use multiple app instances behind a load balancer for horizontal scaling
        - Move session management to Redis for better performance
        
        Security:
        - Store sensitive credentials in environment variables
        - Regularly rotate JWT secrets
        - Use proper network security (firewalls, etc.)
        - Run the service with limited privileges
        
        Monitoring:
        - Set up proper logging and log rotation
        - Implement health checks and monitoring
        - Set up alerts for suspicious activities
        
        Example Nginx configuration:
        ```
        server {
            listen 443 ssl;
            server_name auth.yourdomain.com;
            
            ssl_certificate /path/to/cert.pem;
            ssl_certificate_key /path/to/key.pem;
            
            location / {
                proxy_pass http://127.0.0.1:5000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
            }
        }
        ```
        """)
        deploy_text.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(self.dialog, text="Close", command=self.dialog.destroy).pack(pady=10)
        
        # Center the dialog on the parent window
        self.dialog.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.dialog.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.dialog.winfo_height()) // 2
        self.dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")

# Scheduled tasks manager
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


# Server control functions
def run_server(host, port, debug=False, stop_event=None):
    """Run the server - production or development based on config"""
    global server_running
    server_running = True
    logging.info(f"Starting server on {host}:{port}")
    
    # Store start time for uptime calculations
    if hasattr(threading.current_thread(), 'start_time'):
        threading.current_thread().start_time = int(time.time())
    
    # Get current directory for log paths
    current_dir = os.getcwd()
    
    # Use a global variable to hold the server instance (for development mode)
    global _flask_server_instance
    
    try:
        # Check if we should use production server
        if config.get("SERVER_TYPE", "development") == "production":
            # Check for Gunicorn
            gunicorn_path = shutil.which("gunicorn")
            
            if gunicorn_path:
                # Build command line for Gunicorn
                cmd = [
                    gunicorn_path,
                    "--bind", f"{host}:{port}",
                    "--workers", str(config.get("WORKERS", 1)),
                    "--timeout", "60",
                    "--log-level", config.get("LOG_LEVEL", "info").lower(),
                    "--access-logfile", os.path.join(current_dir, LOG_DIR, "gunicorn_access.log"),
                    "--error-logfile", os.path.join(current_dir, LOG_DIR, "gunicorn_error.log"),
                    "api:app"
                ]
                
                # Start Gunicorn as subprocess
                proc = subprocess.Popen(cmd)
                _flask_server_instance = proc
                
                # Wait for process to exit or stop_event
                while proc.poll() is None:
                    if stop_event and stop_event.is_set():
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()  # Force kill if it doesn't terminate
                        break
                    time.sleep(0.1)
                
                logging.info("Gunicorn server has stopped")
            else:
                logging.warning("Gunicorn not found. Install with: pip install gunicorn")
                logging.warning("Falling back to Flask development server")
                
                # Import Flask app
                from api import app
                import werkzeug.serving
                
                # Create and start werkzeug server
                server = werkzeug.serving.make_server(host, port, app, threaded=True)
                _flask_server_instance = server
                
                # Run server in a separate thread so we can monitor stop_event
                def server_thread():
                    server.serve_forever()
                
                server_thread = threading.Thread(target=server_thread)
                server_thread.daemon = True
                server_thread.start()
                
                # Monitor for shutdown
                while not (stop_event and stop_event.is_set()):
                    time.sleep(0.1)
                
                # Shutdown the server when stop_event is set
                server.shutdown()
                logging.info("Flask development server has stopped")
        else:
            # Development mode - use werkzeug server with serve_forever pattern
            from api import app
            import werkzeug.serving
            
            # Create the server
            server = werkzeug.serving.make_server(host, port, app, threaded=True)
            _flask_server_instance = server
            
            # Run server in a separate thread so we can monitor stop_event
            def server_thread():
                server.serve_forever()
            
            server_thread = threading.Thread(target=server_thread)
            server_thread.daemon = True
            server_thread.start()
            
            # Monitor for shutdown
            while not (stop_event and stop_event.is_set()):
                time.sleep(0.1)
            
            # Shutdown the server when stop_event is set
            server.shutdown()
            logging.info("Flask development server has stopped")
    
    except Exception as e:
        logging.error(f"Error running server: {e}")
    finally:
        server_running = False
        logging.info("Server thread has exited")

def shutdown_server():
    """Shut down the server"""
    global server_running, server_thread
    if server_running and server_thread:
        logging.info("Shutting down server...")
        
        # Try to find and kill the Flask or Gunicorn process
        if platform.system() == "Windows":
            # On Windows, we need to use a different approach
            port = config.get("PORT", 5000)
            try:
                # Find process using the port
                os.system(f"FOR /F \"tokens=5\" %P IN ('netstat -ano ^| findstr :{port} ^| findstr LISTENING') DO taskkill /F /PID %P")
                logging.info(f"Terminated process using port {port}")
            except Exception as e:
                logging.error(f"Failed to terminate server process: {e}")
        else:
            # On Unix-like systems, we can use signals
            try:
                # Try to find PID of server process
                import signal
                import psutil
                
                # Find and kill Python processes listening on our port
                port = config.get("PORT", 5000)
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    if proc.info['name'] == 'python' or proc.info['name'] == 'gunicorn':
                        for connection in proc.connections():
                            if connection.laddr.port == port:
                                os.kill(proc.info['pid'], signal.SIGTERM)
                                logging.info(f"Sent SIGTERM to process {proc.info['pid']}")
            except Exception as e:
                logging.error(f"Failed to terminate server process: {e}")
        
        # Show message to user
        messagebox.showinfo(
            'Server Shutdown',
            'Server shutdown initiated. Check the console for shutdown progress.'
        )

# Password entry with toggle
class PasswordEntry(ttk.Frame):
    def __init__(self, parent, textvariable, width=40, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.var = textvariable
        self.showing = False
        
        # Create entry widget
        self.entry = ttk.Entry(self, textvariable=self.var, width=width, show='*')
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Create toggle button
        self.toggle_btn = ttk.Button(self, text="👁️", width=3, command=self.toggle_show)
        self.toggle_btn.pack(side=tk.RIGHT, padx=(2, 0))
    
    def toggle_show(self):
        """Toggle password visibility"""
        self.showing = not self.showing
        self.entry.configure(show='' if self.showing else '*')
        
        # Auto-hide after a few seconds
        if self.showing:
            self.after(3000, self.auto_hide)
    
    def auto_hide(self):
        """Automatically hide password after timeout"""
        if self.showing:
            self.showing = False
            self.entry.configure(show='*')

# Main GUI creation function
def create_gui():
    global task_manager
    
    # Initialize DB before GUI
    init_db()
    
    # Create task manager
    task_manager = ScheduledTasksManager()
    
    # Check if admin is configured
    first_run = not config.get("ADMIN_USERNAME") or not config.get("ADMIN_EMAIL")
    
    # Create main window
    root = tk.Tk()
    root.title(f'Vespeyr Auth Server Console v{APP_VERSION}')
    root.geometry('900x650')
    root.minsize(800, 600)
    
    # Set app icon (if exists)
    try:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')
        if os.path.exists(icon_path):
            root.iconbitmap(icon_path)
    except:
        pass
    
    # Create styles
    style = ttk.Style()
    style.configure('TButton', font=('Helvetica', 10))
    style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
    style.configure('Success.TLabel', foreground='green')
    style.configure('Error.TLabel', foreground='red')
    style.configure('Warning.TLabel', foreground='orange')
    
    # Create notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Tab 1: Configuration
    config_frame = ttk.Frame(notebook, padding=10)
    notebook.add(config_frame, text='Configuration')
    
    # Tab 2: Logs
    logs_frame = ttk.Frame(notebook, padding=10)
    notebook.add(logs_frame, text='Logs')
    
    # Tab 3: Server Status
    status_frame = ttk.Frame(notebook, padding=10)
    notebook.add(status_frame, text='Server Status')
    
    
    # Tab 4: Database
    db_frame = ttk.Frame(notebook, padding=10)
    notebook.add(db_frame, text='Database')

    # Tab 5: API Console
    api_frame = ApiConsoleFrame(notebook)
    notebook.add(api_frame, text='API Console')

    # ----- Config Tab -----
    config_label = ttk.Label(config_frame, text="Server Configuration", style='Header.TLabel')
    config_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
    
    # Create frame with scrollbar
    config_container = ttk.Frame(config_frame)
    config_container.grid(column=0, row=1, sticky="nsew", padx=5, pady=5)
    config_container.columnconfigure(0, weight=1)
    config_container.rowconfigure(0, weight=1)
    
    config_canvas = tk.Canvas(config_container)
    config_scrollbar = ttk.Scrollbar(config_container, orient="vertical", command=config_canvas.yview)
    
    config_scrollable_frame = ttk.Frame(config_canvas)
    config_scrollable_frame.bind(
        "<Configure>",
        lambda e: config_canvas.configure(scrollregion=config_canvas.bbox("all"))
    )
    
    config_canvas.create_window((0, 0), window=config_scrollable_frame, anchor="nw")
    config_canvas.configure(yscrollcommand=config_scrollbar.set)
    
    config_canvas.pack(side="left", fill="both", expand=True)
    config_scrollbar.pack(side="right", fill="y")
    
    # Enable mousewheel scrolling for the canvas
    def _on_mousewheel(event):
        config_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    config_canvas.bind_all("<MouseWheel>", _on_mousewheel)
    
    # Set grid weights to make config area expandable
    config_frame.columnconfigure(0, weight=1)
    config_frame.rowconfigure(1, weight=1)
    
    # Add environment variable indicators
    env_vars_label = ttk.Label(config_frame, text="Note: Settings with 🔒 are loaded from environment variables", 
                              foreground="blue", font=('Helvetica', 9))
    env_vars_label.grid(column=0, row=2, columnspan=2, sticky='w', padx=5, pady=(5, 0))
    
    # Group config settings into categories
    config_sections = {
        'Server': ['DB_TYPE', 'HOST', 'PORT', 'SERVER_TYPE', 'WORKERS', 'DEBUG_MODE', 'ENABLE_HTTPS_REDIRECT', 'ALLOWED_ORIGINS', 'APP_NAME', 'COMPANY_NAME'],
        'Security': ['JWT_SECRET', 'JWT_EXPIRATION', 'REFRESH_TOKEN_EXPIRATION', 'SECURE_COOKIES', 'SESSION_TIMEOUT'],
        'Passwords': ['PASSWORD_MIN_LENGTH', 'PASSWORD_REQUIRE_MIXED_CASE', 'PASSWORD_REQUIRE_DIGIT', 'PASSWORD_REQUIRE_SPECIAL', 'PASSWORD_HISTORY_COUNT'],
        'Account': ['ACCOUNT_LOCKOUT_THRESHOLD', 'ACCOUNT_LOCKOUT_DURATION', 'RATE_LIMIT_DEFAULT', 'RATE_LIMIT_LOGIN', 'RATE_LIMIT_RESET'],
        'Email': ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'RESET_URL_BASE', 'LOGIN_URL', 'ENABLE_WELCOME_EMAIL'],
        'Database': ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_PATH', 'DB_POOL_SIZE', 'BACKUP_INTERVAL', 'MAX_BACKUPS'],
        'Redis': ['REDIS_ENABLED', 'REDIS_HOST', 'REDIS_PORT', 'REDIS_PASSWORD', 'REDIS_RATELIMIT_DB', 'REDIS_TOKEN_DB'],
        'Admin': ['ADMIN_USERNAME', 'ADMIN_EMAIL'],
        'Logging': ['LOG_LEVEL', 'LOG_FORMAT', 'LOG_MAX_SIZE', 'LOG_BACKUP_COUNT']
    }
    
    # Add config entries to scrollable frame by category
    gui_vars = {}
    
    current_row = 0
    for section, keys in config_sections.items():
        # Section header
        ttk.Label(config_scrollable_frame, text=section, font=('Helvetica', 11, 'bold')).grid(
            column=0, row=current_row, columnspan=2, sticky='w', padx=5, pady=(15, 5)
        )
        current_row += 1
        
        # Section frame with slight indent
        section_frame = ttk.Frame(config_scrollable_frame)
        section_frame.grid(column=0, row=current_row, padx=(15, 0), sticky='ew')
        current_row += 1
        
        # Add each key in this section
        for i, key in enumerate(keys):
            if key in config:
                val = config[key]
                
                # Check if value is from environment variable
                env_var = f"VESPEYR_AUTH_{key}"
                from_env = env_var in os.environ
                
                # Create label with environment indicator if needed
                label_text = f"{key}:" + (" 🔒" if from_env else "")
                ttk.Label(section_frame, text=label_text).grid(
                    column=0, row=i, sticky='e', padx=(0, 10), pady=2
                )
                
                # Different widgets based on value type
                if isinstance(val, bool):
                    var = tk.BooleanVar(value=val)
                    chk = ttk.Checkbutton(section_frame, variable=var)
                    chk.grid(column=1, row=i, sticky='w', pady=2)
                    if from_env:
                        chk.configure(state='disabled')  # Disable if from env var
                        
                elif key == 'LOG_LEVEL':
                    var = tk.StringVar(value=str(val))
                    combo = ttk.Combobox(section_frame, textvariable=var, values=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
                    combo.grid(column=1, row=i, sticky='w', pady=2)
                    if from_env:
                        combo.configure(state='disabled')
                        
                elif key == 'DB_TYPE':
                    var = tk.StringVar(value=str(val))
                    combo = ttk.Combobox(section_frame, textvariable=var, values=['sqlite', 'mysql'])
                    combo.grid(column=1, row=i, sticky='w', pady=2)
                    if from_env:
                        combo.configure(state='disabled')
                        
                elif key == 'SERVER_TYPE':
                    var = tk.StringVar(value=str(val))
                    combo = ttk.Combobox(section_frame, textvariable=var, values=['development', 'production'])
                    combo.grid(column=1, row=i, sticky='w', pady=2)
                    if from_env:
                        combo.configure(state='disabled')
                        
                elif key in ['PASSWORD_MIN_LENGTH', 'JWT_EXPIRATION', 'REFRESH_TOKEN_EXPIRATION', 'BACKUP_INTERVAL', 
                           'MAX_BACKUPS', 'ACCOUNT_LOCKOUT_THRESHOLD', 'ACCOUNT_LOCKOUT_DURATION', 'PORT', 
                           'SMTP_PORT', 'DB_PORT', 'WORKERS', 'DB_POOL_SIZE', 'LOG_MAX_SIZE', 'LOG_BACKUP_COUNT']:
                    var = tk.StringVar(value=str(val))
                    spin = ttk.Spinbox(section_frame, from_=0, to=10000000, textvariable=var, width=10)
                    spin.grid(column=1, row=i, sticky='w', pady=2)
                    if from_env:
                        spin.configure(state='disabled')
                        
                else:
                    var = tk.StringVar(value=str(val))
                    
                    # Use Password entry for sensitive fields
                    if 'PASS' in key or 'SECRET' in key or key == 'DB_PASSWORD':
                        entry_container = PasswordEntry(section_frame, textvariable=var, width=40)
                        entry_container.grid(column=1, row=i, sticky='w', pady=2)
                        if from_env:
                            entry_container.entry.configure(state='disabled')
                            entry_container.toggle_btn.configure(state='disabled')
                    else:
                        entry = ttk.Entry(section_frame, textvariable=var, width=40)
                        entry.grid(column=1, row=i, sticky='w', pady=2)
                        if from_env:
                            entry.configure(state='disabled')
                
                gui_vars[key] = var
    
    # Control buttons
    cfg_buttons_frame = ttk.Frame(config_frame)
    cfg_buttons_frame.grid(column=0, row=3, sticky='ew', padx=5, pady=10)
    
    def save_config_changes():
        """Save changes to configuration"""
        updated = False
        updates = {}
        
        for key, var in gui_vars.items():
            # Skip environment variable settings
            env_var = f"VESPEYR_AUTH_{key}"
            if env_var in os.environ:
                continue
                
            val = var.get()
            
            # Convert types as needed
            if key in ["PORT", "SMTP_PORT", "JWT_EXPIRATION", "REFRESH_TOKEN_EXPIRATION", 
                       "PASSWORD_MIN_LENGTH", "ACCOUNT_LOCKOUT_THRESHOLD", 
                       "ACCOUNT_LOCKOUT_DURATION", "BACKUP_INTERVAL", "MAX_BACKUPS",
                       "DB_PORT", "WORKERS", "DB_POOL_SIZE", "LOG_MAX_SIZE", "LOG_BACKUP_COUNT"]:
                try:
                    val = int(val)
                except ValueError:
                    messagebox.showerror("Invalid Value", f"{key} must be a number")
                    return
            
            if config[key] != val:
                config[key] = val
                updates[key] = val
                updated = True
        
        if updated:
            save_config(config)
            messagebox.showinfo("Success", "Configuration saved successfully")
            
            # Log configuration changes if server is running
            if server_running:
                admin_user = config.get("ADMIN_USERNAME", "admin")
                admin_id = db_execute(
                    'SELECT id FROM users WHERE username = ?',
                    (admin_user,),
                    fetchone=True
                )
                
                if admin_id:
                    from db import log_security_event
                    log_security_event(
                        admin_id['id'],
                        'CONFIG_UPDATED',
                        f"Configuration updated: {', '.join(updates.keys())}",
                        "127.0.0.1"
                    )
        else:
            messagebox.showinfo("Info", "No changes to save")
            
    def reset_config_to_defaults():
        """Reset all configuration to defaults"""
        if messagebox.askyesno("Reset Configuration", 
                              "Are you sure you want to reset all settings to defaults? This will not affect the database."):
            # Keep admin settings
            admin_username = config.get("ADMIN_USERNAME", "")
            admin_email = config.get("ADMIN_EMAIL", "")
            
            # Reset config
            for key, val in DEFAULT_CONFIG.items():
                # Skip environment variable settings
                env_var = f"VESPEYR_AUTH_{key}"
                if env_var in os.environ:
                    continue
                    
                config[key] = val
            
            # Restore admin settings
            if admin_username:
                config["ADMIN_USERNAME"] = admin_username
            if admin_email:
                config["ADMIN_EMAIL"] = admin_email
                
            save_config(config)
            
            # Update UI
            for key, var in gui_vars.items():
                # Skip environment variable settings
                env_var = f"VESPEYR_AUTH_{key}"
                if env_var in os.environ:
                    continue
                    
                val = config[key]
                if isinstance(var, tk.BooleanVar):
                    var.set(bool(val))
                else:
                    var.set(str(val))
                    
            messagebox.showinfo("Success", "Configuration reset to defaults")
            
    def generate_new_jwt_secret():
        """Generate a new random JWT secret"""
        # Check if JWT_SECRET is from environment variable
        if "VESPEYR_AUTH_JWT_SECRET" in os.environ:
            messagebox.showinfo("Environment Variable", 
                              "JWT_SECRET is set from environment variable. Please update the environment variable instead.")
            return
            
        if messagebox.askyesno("Generate JWT Secret", 
                              "Generate a new random JWT secret? This will invalidate all existing tokens."):
            import secrets
            new_secret = secrets.token_hex(32)
            gui_vars["JWT_SECRET"].set(new_secret)
            config["JWT_SECRET"] = new_secret
            save_config(config)
            messagebox.showinfo("Success", "Generated new JWT secret")
            
    def check_mysql_connection():
        """Test MySQL connection with current settings"""
        if config.get("DB_TYPE") != "mysql":
            messagebox.showinfo("Database Type", "Please set DB_TYPE to 'mysql' first")
            return
        
        try:
            import pymysql
        
            # Try to connect to MySQL
            conn = pymysql.connect(
                host=config.get("DB_HOST", "localhost"),
                port=int(config.get("DB_PORT", 3306)),
                user=config.get("DB_USER", ""),
                password=config.get("DB_PASSWORD", "")
            )
        
            # Try to create database if not exists
            cursor = conn.cursor()
            db_name = config.get("DB_NAME", "vespeyr_auth")
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        
            # Test using the database
            cursor.execute(f"USE {db_name}")
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
        
            cursor.close()
            conn.close()
        
            messagebox.showinfo("Success", "MySQL connection successful! Database is accessible.")
        except ImportError:
            messagebox.showerror("Missing Module", "PyMySQL not installed. Run: pip install pymysql")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to MySQL: {str(e)}")
    
    # Add config control buttons
    ttk.Button(cfg_buttons_frame, text="Save Changes", command=save_config_changes).grid(
        column=0, row=0, padx=5, pady=5
    )
    ttk.Button(cfg_buttons_frame, text="Reset to Defaults", command=reset_config_to_defaults).grid(
        column=1, row=0, padx=5, pady=5
    )
    ttk.Button(cfg_buttons_frame, text="Generate JWT Secret", command=generate_new_jwt_secret).grid(
        column=2, row=0, padx=5, pady=5
    )
    ttk.Button(cfg_buttons_frame, text="Test MySQL", command=check_mysql_connection).grid(
        column=3, row=0, padx=5, pady=5
    )
    
    # ----- Logs Tab -----
    logs_label = ttk.Label(logs_frame, text="Server Logs", style='Header.TLabel')
    logs_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
    
    # Log file selector
    log_selector_frame = ttk.Frame(logs_frame)
    log_selector_frame.grid(column=0, row=1, sticky='ew', padx=5, pady=5)
    
    ttk.Label(log_selector_frame, text="Log File:").grid(column=0, row=0, padx=(0, 5), sticky='w')
    
    # Get available log files
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        
    log_files = ["auth_server.log", "error.log", "access.log", "security.log", 
                "gunicorn_access.log", "gunicorn_error.log"]
    
    # Filter to only existing files
    available_logs = [f for f in log_files if os.path.exists(os.path.join(LOG_DIR, f))]
    if not available_logs:
        available_logs = log_files  # Default to all if none exist yet
    
    log_file_var = tk.StringVar(value=available_logs[0] if available_logs else "auth_server.log")
    log_file_combo = ttk.Combobox(log_selector_frame, textvariable=log_file_var, width=30, 
                                values=available_logs)
    log_file_combo.grid(column=1, row=0, padx=5, sticky='w')
    
    # Filter frame
    filter_frame = ttk.LabelFrame(log_selector_frame, text="Filter")
    filter_frame.grid(column=2, row=0, padx=10, sticky='w')
    
    filter_var = tk.StringVar(value="")
    ttk.Entry(filter_frame, textvariable=filter_var, width=20).grid(column=0, row=0, padx=5, pady=5)
    
    # Log viewer
    log_viewer = scrolledtext.ScrolledText(logs_frame, width=90, height=20, wrap=tk.NONE)
    log_viewer.grid(column=0, row=2, sticky='nsew', padx=5, pady=5)
    log_viewer.config(state=tk.DISABLED)
    logs_frame.columnconfigure(0, weight=1)
    logs_frame.rowconfigure(2, weight=1)
    
    # Log status bar
    log_status_var = tk.StringVar(value="")
    ttk.Label(logs_frame, textvariable=log_status_var).grid(column=0, row=3, sticky='w', padx=5)
    
    # Log controls
    log_controls = ttk.Frame(logs_frame)
    log_controls.grid(column=0, row=4, sticky='ew', padx=5, pady=5)
    
    def load_log_file():
        """Load and display selected log file"""
        filename = os.path.join(LOG_DIR, log_file_var.get())
        filter_text = filter_var.get().strip().lower()
        
        log_viewer.config(state=tk.NORMAL)
        log_viewer.delete(1.0, tk.END)
        
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()
                    
                    # Apply filter if provided
                    if filter_text:
                        lines = [line for line in lines if filter_text in line.lower()]
                    
                    # Get the last 1000 lines max
                    lines = lines[-1000:]
                    
                    for line in lines:
                        log_viewer.insert(tk.END, line)
                        
                    log_status_var.set(f"Loaded {len(lines)} lines from {os.path.basename(filename)}")
            else:
                log_viewer.insert(tk.END, f"Log file {filename} does not exist yet.")
                log_status_var.set("Log file not found")
        except Exception as e:
            log_viewer.insert(tk.END, f"Error loading log file: {str(e)}")
            log_status_var.set(f"Error: {str(e)}")
            
        log_viewer.see(tk.END)
        log_viewer.config(state=tk.DISABLED)
    
    def clear_log_file():
        """Clear the current log file"""
        filename = os.path.join(LOG_DIR, log_file_var.get())
        
        if messagebox.askyesno("Clear Log", f"Are you sure you want to clear {log_file_var.get()}?"):
            try:
                if os.path.exists(filename):
                    with open(filename, 'w') as f:
                        pass  # Just open and truncate
                    
                    log_viewer.config(state=tk.NORMAL)
                    log_viewer.delete(1.0, tk.END)
                    log_viewer.insert(tk.END, f"Log file {filename} has been cleared.")
                    log_viewer.config(state=tk.DISABLED)
                    
                    log_status_var.set(f"Cleared log file {os.path.basename(filename)}")
                else:
                    messagebox.showinfo("Log Not Found", f"Log file {filename} does not exist yet.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear log file: {str(e)}")
    
    # Bind events
    log_file_combo.bind('<<ComboboxSelected>>', lambda e: load_log_file())
    ttk.Button(filter_frame, text="Apply", command=load_log_file).grid(column=1, row=0, padx=5, pady=5)
    
    ttk.Button(log_controls, text="Refresh", command=load_log_file).grid(
        column=0, row=0, padx=5
    )
    ttk.Button(log_controls, text="Clear Log", command=clear_log_file).grid(
        column=1, row=0, padx=5
    )
    
    # Load initial log file
    load_log_file()

    # ----- Status Tab -----
    status_label = ttk.Label(status_frame, text="Server Status", style='Header.TLabel')
    status_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
    
    # Status indicators frame
    status_indicators = ttk.LabelFrame(status_frame, text="System Status")
    status_indicators.grid(column=0, row=1, sticky='ew', padx=5, pady=5, columnspan=2)
    
    # Server status indicator
    ttk.Label(status_indicators, text="Server:").grid(column=0, row=0, sticky='e', padx=(10, 5), pady=5)
    status_var = tk.StringVar(value="Stopped")
    status_indicator = ttk.Label(status_indicators, textvariable=status_var, foreground='red', font=('Helvetica', 10, 'bold'))
    status_indicator.grid(column=1, row=0, sticky='w', pady=5)
    
    # Database status
    ttk.Label(status_indicators, text="Database:").grid(column=0, row=1, sticky='e', padx=(10, 5), pady=5)
    db_status_var = tk.StringVar(value="Not Connected")
    ttk.Label(status_indicators, textvariable=db_status_var, foreground='orange').grid(column=1, row=1, sticky='w', pady=5)
    
    # Email status
    ttk.Label(status_indicators, text="Email:").grid(column=0, row=2, sticky='e', padx=(10, 5), pady=5)
    email_status_var = tk.StringVar(value="Not Configured")
    ttk.Label(status_indicators, textvariable=email_status_var, foreground='orange').grid(column=1, row=2, sticky='w', pady=5)

    # Redis status
    ttk.Label(status_indicators, text="Redis:").grid(column=0, row=3, sticky='e', padx=(10, 5), pady=5)
    redis_status_var = tk.StringVar(value="Disabled")
    redis_indicator = ttk.Label(status_indicators, textvariable=redis_status_var, foreground='gray')
    redis_indicator.grid(column=1, row=3, sticky='w', pady=5)
    
    # Uptime
    ttk.Label(status_indicators, text="Uptime:").grid(column=2, row=0, sticky='e', padx=(20, 5), pady=5)
    uptime_var = tk.StringVar(value="0h 0m 0s")
    ttk.Label(status_indicators, textvariable=uptime_var).grid(column=3, row=0, sticky='w', pady=5)
    
    # User count
    ttk.Label(status_indicators, text="Users:").grid(column=2, row=1, sticky='e', padx=(20, 5), pady=5)
    user_count_var = tk.StringVar(value="0")
    ttk.Label(status_indicators, textvariable=user_count_var).grid(column=3, row=1, sticky='w', pady=5)
    
    # System info
    ttk.Label(status_indicators, text="System:").grid(column=2, row=2, sticky='e', padx=(20, 5), pady=5)
    system_info_var = tk.StringVar(value=f"{platform.system()} {platform.release()}")
    ttk.Label(status_indicators, textvariable=system_info_var).grid(column=3, row=2, sticky='w', pady=5)
    
    # Database type
    ttk.Label(status_indicators, text="DB Type:").grid(column=4, row=0, sticky='e', padx=(20, 5), pady=5)
    db_type_var = tk.StringVar(value=config.get("DB_TYPE", "sqlite"))
    ttk.Label(status_indicators, textvariable=db_type_var).grid(column=5, row=0, sticky='w', pady=5)
    
    # Server mode
    ttk.Label(status_indicators, text="Server Mode:").grid(column=4, row=1, sticky='e', padx=(20, 5), pady=5)
    server_mode_var = tk.StringVar(value=config.get("SERVER_TYPE", "development"))
    ttk.Label(status_indicators, textvariable=server_mode_var).grid(column=5, row=1, sticky='w', pady=5)
    
    # Server console output section
    console_frame = ttk.LabelFrame(status_frame, text="Server Console")
    console_frame.grid(column=0, row=3, sticky='nsew', padx=5, pady=5, columnspan=2)
    status_frame.rowconfigure(3, weight=1)
    
    console_output = scrolledtext.ScrolledText(console_frame, height=15, bg='black', fg='white', wrap=tk.NONE)
    console_output.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    console_output.config(state=tk.DISABLED)
    
    # Redirect console output
    console_redirector = ConsoleRedirector(console_output)
    
    # Control buttons
    controls_frame = ttk.Frame(status_frame)
    controls_frame.grid(column=0, row=4, columnspan=2, sticky='ew', padx=5, pady=10)
    
    def toggle_server_state():
        global server_running, server_thread, start_time, _flask_server_instance
    
        if not server_running:
            # Start server
            # Save config changes first
            for key, var in gui_vars.items():
                # Skip environment variable settings
                env_var = f"VESPEYR_AUTH_{key}"
                if env_var in os.environ:
                    continue
                
                val = var.get()
                if key in ("PORT", "SMTP_PORT", "JWT_EXPIRATION", "REFRESH_TOKEN_EXPIRATION",
                          "DB_PORT", "WORKERS"):
                    try:
                        val = int(val)
                    except ValueError:
                        messagebox.showerror("Invalid Value", f"{key} must be a number")
                        return
                elif key == "DEBUG_MODE":
                    val = bool(val)
            
                config[key] = val
        
            save_config(config)
        
            # Update display values
            db_type_var.set(config.get("DB_TYPE", "sqlite"))
            server_mode_var.set(config.get("SERVER_TYPE", "development"))
        
            try:
                # Create a stop event for graceful shutdown
                stop_event = threading.Event()
            
                server_thread = threading.Thread(
                    target=run_server,
                    args=(config["HOST"], config["PORT"], config["DEBUG_MODE"], stop_event),
                    daemon=True
                )
                server_thread.start_time = int(time.time())
                server_thread.stop_event = stop_event  # Store the stop event on the thread
                start_time = server_thread.start_time
                server_thread.start()
            
                # Start task manager
                task_manager.start()
            
                status_var.set(f"Running on {config['HOST']}:{config['PORT']}")
                status_indicator.config(foreground='green')
                btn_toggle_server.config(text='Stop Server')
            
                # Log startup
                console_output.config(state=tk.NORMAL)
                console_output.insert(tk.END, f"Server started on {config['HOST']}:{config['PORT']}\n")
                if config.get("SERVER_TYPE") == "production":
                    console_output.insert(tk.END, "Running in PRODUCTION mode with Gunicorn\n")
                else:
                    console_output.insert(tk.END, "Running in DEVELOPMENT mode with Flask\n")
                
                console_output.see(tk.END)
                console_output.config(state=tk.DISABLED)
            
                # Update status indicators
                update_status_indicators()
            
            except Exception as e:
                messagebox.showerror("Server Error", f"Failed to start server: {str(e)}")
                logging.error(f"Failed to start server: {str(e)}")
        else:
            # Stop server gracefully using the stop_event
            if hasattr(server_thread, 'stop_event') and server_thread.stop_event:
                logging.info("Shutting down server gracefully...")
                server_thread.stop_event.set()
            
                # Show message to user
                console_output.config(state=tk.NORMAL)
                console_output.insert(tk.END, "Server shutdown initiated. Please wait...\n")
                console_output.see(tk.END)
                console_output.config(state=tk.DISABLED)
            
                # Wait a moment to let the server start shutting down
                root.update()
                time.sleep(0.5)
            
                # Update UI immediately - don't wait for server thread to fully exit
                status_var.set("Stopped")
                status_indicator.config(foreground='red')
                btn_toggle_server.config(text='Start Server')
                server_running = False
            
                # Show success message
                console_output.config(state=tk.NORMAL)
                console_output.insert(tk.END, "Server has been stopped.\n")
                console_output.see(tk.END)
                console_output.config(state=tk.DISABLED)
            else:
                # If no stop_event, resort to brute force shutdown of the server instance
                if _flask_server_instance:
                    try:
                        if hasattr(_flask_server_instance, 'shutdown'):
                            _flask_server_instance.shutdown()
                        elif hasattr(_flask_server_instance, 'terminate'):
                            _flask_server_instance.terminate()
                        logging.info("Server instance shutdown requested")
                    except Exception as e:
                        logging.error(f"Error shutting down server instance: {e}")
            
                # Fall back to the old shutdown method as a last resort
                shutdown_server()
    
    def update_status_indicators():
        if not server_running:
            return
        
        try:
            # Check database
            db_ok = False
            try:
                db_execute('SELECT 1', fetchone=True)
                db_status_var.set("Connected")
                db_ok = True
            except:
                db_status_var.set("Error")
            
            # Set color based on status
            for label in status_indicators.winfo_children():
                if isinstance(label, ttk.Label) and label.cget('textvariable') == str(db_status_var):
                    label.config(foreground='green' if db_ok else 'red')
        
            # Check email
            smtp_ok = False
            if config["SMTP_HOST"] and config["SMTP_USER"] and config["SMTP_PASS"]:
                try:
                    import smtplib
                    with smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"], timeout=3) as smtp:
                        smtp.starttls()
                        smtp.login(config["SMTP_USER"], config["SMTP_PASS"])
                        smtp_ok = True
                        email_status_var.set("Configured")
                except:
                    email_status_var.set("Error")
            else:
                email_status_var.set("Not Configured")
            
            # Set color based on status
            for label in status_indicators.winfo_children():
                if isinstance(label, ttk.Label) and label.cget('textvariable') == str(email_status_var):
                    if smtp_ok:
                        label.config(foreground='green')
                    elif config["SMTP_HOST"] and config["SMTP_USER"] and config["SMTP_PASS"]:
                        label.config(foreground='red')
                    else:
                        label.config(foreground='orange')
        
            # Check Redis if enabled
            if config.get("REDIS_ENABLED", False):
                try:
                    # Import redis_service dynamically to avoid importing if not needed
                    import importlib
                    try:
                        redis_service = importlib.import_module('redis_service')
                        redis_status = redis_service.check_redis_connection()
                    
                        if redis_status['overall']:
                            redis_status_var.set("Connected")
                            redis_indicator.config(foreground='green')
                        else:
                            if redis_status['rate_limit'] and not redis_status['token']:
                                redis_status_var.set("Partial (Rate limiting only)")
                                redis_indicator.config(foreground='orange')
                            elif not redis_status['rate_limit'] and redis_status['token']:
                                redis_status_var.set("Partial (Token only)")
                                redis_indicator.config(foreground='orange')
                            else:
                                redis_status_var.set("Error")
                                redis_indicator.config(foreground='red')
                    except ImportError:
                        redis_status_var.set("Module Error")
                        redis_indicator.config(foreground='red')
                        logging.error("redis_service module not found")
                except Exception as e:
                    redis_status_var.set("Error")
                    redis_indicator.config(foreground='red')
                    logging.error(f"Redis status check failed: {e}")
            else:
                redis_status_var.set("Disabled")
                redis_indicator.config(foreground='gray')
                        
            # Update uptime
            if start_time > 0:
                uptime_seconds = int(time.time()) - start_time
                hours = uptime_seconds // 3600
                minutes = (uptime_seconds % 3600) // 60
                seconds = uptime_seconds % 60
                uptime_var.set(f"{hours}h {minutes}m {seconds}s")
            
            # Update user count
            try:
                users = db_execute('SELECT COUNT(*) as count FROM users', fetchone=True)
                if users:
                    user_count_var.set(str(users['count']))
            except:
                pass
                
        except Exception as e:
            logging.error(f"Status update error: {str(e)}")
        
        # Schedule next update
        root.after(5000, update_status_indicators)
    
    def open_help_dialog():
        """Open the help dialog"""
        HelpDialog(root)
    
    # Add server control buttons
    btn_toggle_server = ttk.Button(controls_frame, text="Start Server", command=toggle_server_state)
    btn_toggle_server.grid(column=0, row=0, padx=5, pady=5)
    
    ttk.Button(controls_frame, text="Clear Console", 
              command=lambda: [console_output.config(state=tk.NORMAL), 
                              console_output.delete(1.0, tk.END), 
                              console_output.config(state=tk.DISABLED)]).grid(
        column=1, row=0, padx=5, pady=5
    )
    
    ttk.Button(controls_frame, text="Help", command=open_help_dialog).grid(
        column=2, row=0, padx=5, pady=5
    )

    # ----- Database Tab -----
    db_label = ttk.Label(db_frame, text="Database Management", style='Header.TLabel')
    db_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
    
    # Database info frame
    db_info_frame = ttk.LabelFrame(db_frame, text="Database Information")
    db_info_frame.grid(column=0, row=1, sticky='ew', padx=5, pady=5, columnspan=2)
    
    ttk.Label(db_info_frame, text="Database Type:").grid(column=0, row=0, sticky='e', padx=(10, 5), pady=5)
    db_type_info_var = tk.StringVar(value=config.get("DB_TYPE", "sqlite"))
    ttk.Label(db_info_frame, textvariable=db_type_info_var).grid(column=1, row=0, sticky='w', pady=5)
    
    ttk.Label(db_info_frame, text="Database Path:").grid(column=0, row=1, sticky='e', padx=(10, 5), pady=5)
    db_path_var = tk.StringVar(value=config["DB_PATH"] if config.get("DB_TYPE", "sqlite") == "sqlite" else 
                               f"{config.get('DB_HOST', 'localhost')}:{config.get('DB_PORT', 3306)}/{config.get('DB_NAME', 'vespeyr_auth')}")
    ttk.Label(db_info_frame, textvariable=db_path_var).grid(column=1, row=1, sticky='w', pady=5)
    
    ttk.Label(db_info_frame, text="Size:").grid(column=0, row=2, sticky='e', padx=(10, 5), pady=5)
    db_size_var = tk.StringVar(value="Unknown")
    ttk.Label(db_info_frame, textvariable=db_size_var).grid(column=1, row=2, sticky='w', pady=5)
    
    ttk.Label(db_info_frame, text="Users:").grid(column=0, row=3, sticky='e', padx=(10, 5), pady=5)
    db_users_var = tk.StringVar(value="0")
    ttk.Label(db_info_frame, textvariable=db_users_var).grid(column=1, row=3, sticky='w', pady=5)
    
    ttk.Label(db_info_frame, text="Last Backup:").grid(column=2, row=0, sticky='e', padx=(20, 5), pady=5)
    last_backup_var = tk.StringVar(value="Never")
    ttk.Label(db_info_frame, textvariable=last_backup_var).grid(column=3, row=0, sticky='w', pady=5)
    
    ttk.Label(db_info_frame, text="Backup Location:").grid(column=2, row=1, sticky='e', padx=(20, 5), pady=5)
    backup_loc_var = tk.StringVar(value=BACKUP_DIR)
    ttk.Label(db_info_frame, textvariable=backup_loc_var).grid(column=3, row=1, sticky='w', pady=5)
    
    ttk.Label(db_info_frame, text="Backups:").grid(column=2, row=2, sticky='e', padx=(20, 5), pady=5)
    backup_count_var = tk.StringVar(value="0")
    ttk.Label(db_info_frame, textvariable=backup_count_var).grid(column=3, row=2, sticky='w', pady=5)
    
    # Backup controls
    backup_frame = ttk.LabelFrame(db_frame, text="Backup Management")
    backup_frame.grid(column=0, row=2, sticky='ew', padx=5, pady=10, columnspan=2)
    
    def update_db_info():
        """Update database information"""
        try:
            # Update database type and path display
            db_type_info_var.set(config.get("DB_TYPE", "sqlite"))
            
            if config.get("DB_TYPE", "sqlite") == "sqlite":
                db_path_var.set(config["DB_PATH"])
                
                # Get database size
                if os.path.exists(config["DB_PATH"]):
                    size_bytes = os.path.getsize(config["DB_PATH"])
                    if size_bytes < 1024:
                        size_str = f"{size_bytes} bytes"
                    elif size_bytes < 1024 * 1024:
                        size_str = f"{size_bytes/1024:.2f} KB"
                    else:
                        size_str = f"{size_bytes/(1024*1024):.2f} MB"
                    db_size_var.set(size_str)
                else:
                    db_size_var.set("Not found")
            else:
                # For MySQL, show connection details
                db_path_var.set(f"{config.get('DB_HOST', 'localhost')}:{config.get('DB_PORT', 3306)}/{config.get('DB_NAME', 'vespeyr_auth')}")
                db_size_var.set("N/A (MySQL)")
            
            # Get user count
            try:
                users = db_execute('SELECT COUNT(*) as count FROM users', fetchone=True)
                if users:
                    db_users_var.set(str(users['count']))
            except:
                db_users_var.set("Error")
            
            # Get backup info
            if os.path.exists(BACKUP_DIR):
                # Determine file extension based on DB type
                ext = ".sql" if config.get("DB_TYPE", "sqlite") == "mysql" else ".db"
                
                backup_files = [f for f in os.listdir(BACKUP_DIR) if f.startswith("auth_db_backup_") and f.endswith(ext)]
                backup_count_var.set(str(len(backup_files)))
                
                if backup_files:
                    # Sort by modification time (newest first)
                    backup_files.sort(key=lambda x: os.path.getmtime(os.path.join(BACKUP_DIR, x)), reverse=True)
                    latest_backup = backup_files[0]
                    backup_time = os.path.getmtime(os.path.join(BACKUP_DIR, latest_backup))
                    last_backup_var.set(datetime.fromtimestamp(backup_time).strftime("%Y-%m-%d %H:%M:%S"))
            
        except Exception as e:
            logging.error(f"Error updating database info: {str(e)}")
            
        # Schedule next update
        root.after(30000, update_db_info)  # Update every 30 seconds
    
    def backup_now():
        """Trigger manual database backup"""
        try:
            if backup_database():
                messagebox.showinfo("Success", "Database backup created successfully")
                update_db_info()  # Update info immediately
            else:
                messagebox.showerror("Error", "Failed to create database backup")
        except Exception as e:
            messagebox.showerror("Error", f"Backup error: {str(e)}")
    
    def view_backups():
        """Open backup directory in file explorer"""
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
            
        if platform.system() == "Windows":
            os.startfile(os.path.abspath(BACKUP_DIR))
        elif platform.system() == "Darwin":  # macOS
            os.system(f"open {os.path.abspath(BACKUP_DIR)}")
        else:  # Linux
            os.system(f"xdg-open {os.path.abspath(BACKUP_DIR)}")
    
    ttk.Button(backup_frame, text="Backup Now", command=backup_now).grid(
        column=0, row=0, padx=5, pady=5
    )
    
    ttk.Button(backup_frame, text="View Backups", command=view_backups).grid(
        column=1, row=0, padx=5, pady=5
    )
    
    # Database tables
    tables_frame = ttk.LabelFrame(db_frame, text="Database Tables")
    tables_frame.grid(column=0, row=3, sticky='nsew', padx=5, pady=5, columnspan=2)
    db_frame.rowconfigure(3, weight=1)
    
    # Add connection pool management frame (after row 3)
    db_diag_frame = ttk.LabelFrame(db_frame, text="Connection Pool Management")
    db_diag_frame.grid(column=0, row=4, sticky='ew', padx=5, pady=10, columnspan=2)

    # Add diagnostic buttons
    ttk.Button(db_diag_frame, text="Check Connection Pool", command=check_db_pool_status).grid(
        column=0, row=0, padx=5, pady=5
    )

    ttk.Button(db_diag_frame, text="Force Connection Cleanup", command=force_db_connection_cleanup).grid(
        column=1, row=0, padx=5, pady=5
    )

    ttk.Button(db_diag_frame, text="Reset Connection Pool", command=reset_db_connection_pool).grid(
        column=2, row=0, padx=5, pady=5
    )







    # Table list
    tables_tree = ttk.Treeview(tables_frame, columns=('rows',), show='headings', height=10)
    tables_tree.heading('rows', text='Rows')
    tables_tree.column('rows', width=100, anchor='center')
    
    tables_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Scrollbar for table list
    tables_scroll = ttk.Scrollbar(tables_frame, orient="vertical", command=tables_tree.yview)
    tables_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    tables_tree.configure(yscrollcommand=tables_scroll.set)
    
    def update_table_list():
        """Update the table list"""
        try:
            # Clear existing items
            for item in tables_tree.get_children():
                tables_tree.delete(item)
        
            # Get table list and row counts
            if config.get("DB_TYPE", "sqlite") == "mysql":
                # For MySQL databases
                try:
                    import pymysql
                
                    # Connect to MySQL
                    conn = pymysql.connect(
                        host=config.get("DB_HOST", "localhost"),
                        port=int(config.get("DB_PORT", 3306)),
                        user=config.get("DB_USER", ""),
                        password=config.get("DB_PASSWORD", ""),
                        database=config.get("DB_NAME", "vespeyr_auth")
                    )
                
                    cursor = conn.cursor(pymysql.cursors.DictCursor)
                
                    # Get table list
                    cursor.execute("SHOW TABLES")
                    tables = cursor.fetchall()
                
                    for table in tables:
                        table_name = list(table.values())[0]  # Get first value in the dictionary
                    
                        # Get row count
                        try:
                            cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
                            row_count = cursor.fetchone()
                            count = row_count['count'] if row_count else 0
                        except:
                            count = "Error"
                    
                        tables_tree.insert('', tk.END, text=table_name, values=(count,), iid=table_name)
                    
                    cursor.close()
                    conn.close()
                
                except ImportError:
                    tables_tree.insert('', tk.END, text="PyMySQL not installed", values=("N/A",), iid="error")
                    tables_tree.insert('', tk.END, text="Install with: pip install pymysql", values=("N/A",), iid="hint")
                except Exception as e:
                    tables_tree.insert('', tk.END, text=f"MySQL Error: {str(e)}", values=("N/A",), iid="error")
            else:
                # For SQLite databases
                tables = db_execute(
                    "SELECT name FROM sqlite_master WHERE type='table'",
                    fetchall=True
                )
            
                for table in tables:
                    table_name = table['name']
                    # Get row count
                    try:
                        row_count = db_execute(
                            f"SELECT COUNT(*) as count FROM {table_name}",
                            fetchone=True
                        )
                        count = row_count['count'] if row_count else 0
                    except:
                        count = "Error"
                
                    tables_tree.insert('', tk.END, text=table_name, values=(count,), iid=table_name)
            
        except Exception as e:
            logging.error(f"Error updating table list: {str(e)}")
            tables_tree.insert('', tk.END, text=f"Error: {str(e)}", values=("N/A",), iid="error")
    
    # Refresh button for tables
    ttk.Button(tables_frame, text="Refresh", command=update_table_list).pack(side=tk.BOTTOM, pady=5)

    # Initialize database info and table list
    update_db_info()
    update_table_list()
    
    # If it's the first run, show a welcome message and setup admin credentials
    if first_run:
        def setup_admin():
            """Set up admin credentials on first run"""
            admin_username = admin_username_var.get().strip()
            admin_email = admin_email_var.get().strip()
            admin_password = admin_password_var.get().strip()
            
            if not admin_username or not admin_email or not admin_password:
                messagebox.showerror("Error", "All fields are required")
                return
                
            if not admin_email or '@' not in admin_email:
                messagebox.showerror("Error", "Please enter a valid email address")
                return
                
            if len(admin_password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters")
                return
                
            # Set config values
            config["ADMIN_USERNAME"] = admin_username
            config["ADMIN_EMAIL"] = admin_email
            save_config(config)
            
            # Create admin user in database
            try:
                import bcrypt
                import uuid
                
                # Initialize database if needed
                init_db()
                
                # Hash password
                hashed_password = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt())
                
                # Check if user already exists
                existing_user = db_execute(
                    'SELECT id FROM users WHERE username = ? OR email = ?',
                    (admin_username, admin_email),
                    fetchone=True
                )
                
                if existing_user:
                    # Update existing user
                    db_execute(
                        'UPDATE users SET username = ?, email = ?, password = ? WHERE id = ?',
                        (admin_username, admin_email, hashed_password, existing_user['id']),
                        commit=True
                    )
                    user_id = existing_user['id']
                else:
                    # Create new user
                    user_id = str(uuid.uuid4())
                    timestamp = int(time.time())
                    
                    db_execute(
                        'INSERT INTO users (id, username, email, password, created_at, last_password_change) VALUES (?, ?, ?, ?, ?, ?)',
                        (user_id, admin_username, admin_email, hashed_password, timestamp, timestamp),
                        commit=True
                    )
                
                # Close the dialog
                admin_dialog.destroy()
                
                # Show success message
                messagebox.showinfo("Success", 
                                  f"Admin user '{admin_username}' has been created.\n\n"
                                  f"You can now start the server and login with these credentials.")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create admin user: {str(e)}")
                logging.error(f"Admin setup error: {str(e)}")
        
        # Create admin setup dialog
        admin_dialog = tk.Toplevel(root)
        admin_dialog.title("Admin Setup")
        admin_dialog.geometry("400x300")
        admin_dialog.transient(root)
        admin_dialog.grab_set()
        
        # Center dialog
        admin_dialog.update_idletasks()
        x = root.winfo_rootx() + (root.winfo_width() - admin_dialog.winfo_width()) // 2
        y = root.winfo_rooty() + (root.winfo_height() - admin_dialog.winfo_height()) // 2
        admin_dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        
        # Add admin setup fields
        ttk.Label(admin_dialog, text="Welcome to Vespeyr Auth Server Setup", 
                 font=('Helvetica', 12, 'bold')).pack(pady=(20, 10))
        
        ttk.Label(admin_dialog, text="Please set up your admin credentials").pack(pady=(0, 20))
        
        # Username
        username_frame = ttk.Frame(admin_dialog)
        username_frame.pack(fill=tk.X, padx=30, pady=5)
        
        ttk.Label(username_frame, text="Admin Username:").pack(side=tk.LEFT)
        admin_username_var = tk.StringVar(value=config.get("ADMIN_USERNAME", ""))
        ttk.Entry(username_frame, textvariable=admin_username_var, width=25).pack(side=tk.RIGHT)
        
        # Email
        email_frame = ttk.Frame(admin_dialog)
        email_frame.pack(fill=tk.X, padx=30, pady=5)
        
        ttk.Label(email_frame, text="Admin Email:").pack(side=tk.LEFT)
        admin_email_var = tk.StringVar(value=config.get("ADMIN_EMAIL", ""))
        ttk.Entry(email_frame, textvariable=admin_email_var, width=25).pack(side=tk.RIGHT)
        
        # Password
        password_frame = ttk.Frame(admin_dialog)
        password_frame.pack(fill=tk.X, padx=30, pady=5)
        
        ttk.Label(password_frame, text="Admin Password:").pack(side=tk.LEFT)
        admin_password_var = tk.StringVar()
        ttk.Entry(password_frame, textvariable=admin_password_var, show="*", width=25).pack(side=tk.RIGHT)
        
        # Buttons
        button_frame = ttk.Frame(admin_dialog)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Save Admin Settings", command=setup_admin).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Skip", command=admin_dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Make dialog modal
        admin_dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing with X
        root.wait_window(admin_dialog)  # Wait for dialog to close
    
    # Handle window close
    def on_closing():
        if server_running:
            if messagebox.askyesno("Quit", "Server is still running. Are you sure you want to quit?"):
                if task_manager:
                    task_manager.stop()
                root.destroy()
        else:
            if task_manager:
                task_manager.stop()
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    return root