# gui/help_dialog.py - Help dialog implementation
import tkinter as tk
from tkinter import ttk, scrolledtext

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
        general_text.insert(tk.END, """
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
           http://{HOST}:{PORT}/auth/
        
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
        
        # Production Deployment tab
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
                proxy_pass https://api.vespeyr.com:5000;
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