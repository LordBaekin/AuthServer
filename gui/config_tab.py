# gui/config_tab.py - Configuration tab implementation
import tkinter as tk
from tkinter import ttk, messagebox
import os
import logging
import time
import subprocess
from tkinter import filedialog, simpledialog
from .base import BaseTab
from .utils import create_scrollable_frame, PasswordEntry
from config import save_config, DEFAULT_CONFIG
from db import db_execute

class ConfigTab(BaseTab):
    def __init__(self, parent, app_controller):
        self.gui_vars = {}
        super().__init__(parent, app_controller)
        
    def setup_ui(self):
        """Set up the configuration tab UI."""
        # Header
        config_label = ttk.Label(self, text="Server Configuration", style='Header.TLabel')
        config_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
    
        # Create scrollable frame
        config_container, config_scrollable_frame = create_scrollable_frame(self)
        config_container.grid(column=0, row=1, sticky="nsew", padx=5, pady=5)
    
        # Store reference to scrollable frame for SSL section
        self.scrollable_frame = config_scrollable_frame
    
        # Set grid weights to make config area expandable
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
    
        # Add environment variable indicators
        env_vars_label = ttk.Label(
            self, 
            text="Note: Settings with 🔒 are loaded from environment variables", 
            foreground="blue", 
            font=('Helvetica', 9)
        )
        env_vars_label.grid(column=0, row=2, columnspan=2, sticky='w', padx=5, pady=(5, 0))
    
        # Create config sections
        self._create_config_sections(config_scrollable_frame)
    
        # Add SSL configuration section
        # Find the next available row number by checking existing widgets
        existing_widgets = config_scrollable_frame.grid_slaves()
        if existing_widgets:
            max_row = max(widget.grid_info()['row'] for widget in existing_widgets if widget.grid_info()['row'] is not None)
            next_row = max_row + 1
        else:
            next_row = 0
    
        # Add SSL configuration section
        self.add_ssl_configuration_section(config_scrollable_frame, next_row)
    
        # Control buttons
        cfg_buttons_frame = ttk.Frame(self)
        cfg_buttons_frame.grid(column=0, row=3, sticky='ew', padx=5, pady=10)
    
        ttk.Button(cfg_buttons_frame, text="Save Changes", command=self.save_config_changes).grid(
            column=0, row=0, padx=5, pady=5
        )
        ttk.Button(cfg_buttons_frame, text="Reset to Defaults", command=self.reset_config_to_defaults).grid(
            column=1, row=0, padx=5, pady=5
        )
        ttk.Button(cfg_buttons_frame, text="Generate JWT Secret", command=self.generate_new_jwt_secret).grid(
            column=2, row=0, padx=5, pady=5
        )
        ttk.Button(cfg_buttons_frame, text="Test MySQL", command=self.check_mysql_connection).grid(
            column=3, row=0, padx=5, pady=5
        )
        
    def _create_config_sections(self, parent_frame):
        """Create configuration sections in the UI."""
        config = self.app_controller.config
        
        # Group config settings into categories
        config_sections = {
            'Server': ['DB_TYPE', 'HOST', 'PORT', 'SERVER_TYPE', 'WORKERS', 'DEBUG_MODE', 
                      'ENABLE_HTTPS_REDIRECT', 'ALLOWED_ORIGINS', 'APP_NAME', 'COMPANY_NAME'],
            'Security': ['JWT_SECRET', 'JWT_ISSUER', 'JWT_AUDIENCE', 'JWT_EXPIRATION', 'REFRESH_TOKEN_EXPIRATION', 
                        'SECURE_COOKIES', 'SESSION_TIMEOUT'],
            'Passwords': ['PASSWORD_MIN_LENGTH', 'PASSWORD_REQUIRE_MIXED_CASE', 
                         'PASSWORD_REQUIRE_DIGIT', 'PASSWORD_REQUIRE_SPECIAL', 'PASSWORD_HISTORY_COUNT'],
            'Account': ['ACCOUNT_LOCKOUT_THRESHOLD', 'ACCOUNT_LOCKOUT_DURATION', 
                       'RATE_LIMIT_DEFAULT', 'RATE_LIMIT_LOGIN', 'RATE_LIMIT_RESET'],
            'Email': ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 
                     'RESET_URL_BASE', 'LOGIN_URL', 'ENABLE_WELCOME_EMAIL'],
            'Database': ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 
                        'DB_PATH', 'DB_POOL_SIZE', 'BACKUP_INTERVAL', 'MAX_BACKUPS'],
            'Redis': ['REDIS_ENABLED', 'REDIS_HOST', 'REDIS_PORT', 'REDIS_PASSWORD', 
                     'REDIS_RATELIMIT_DB', 'REDIS_TOKEN_DB'],
            'Admin': ['ADMIN_USERNAME', 'ADMIN_EMAIL'],
            'Logging': ['LOG_LEVEL', 'LOG_FORMAT', 'LOG_MAX_SIZE', 'LOG_BACKUP_COUNT'],
            'Updates': ['UPDATE_MANIFEST_URL', 'CHECK_UPDATES_ON_STARTUP']  # New section for update settings
        }
        
        # Add config entries to scrollable frame by category
        current_row = 0
        for section, keys in config_sections.items():
            # Section header
            ttk.Label(parent_frame, text=section, font=('Helvetica', 11, 'bold')).grid(
                column=0, row=current_row, columnspan=2, sticky='w', padx=5, pady=(15, 5)
            )
            current_row += 1
            
            # Section frame with slight indent
            section_frame = ttk.Frame(parent_frame)
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
                    
                    self.gui_vars[key] = var
    
    def save_config_changes(self):
        """Save changes to configuration."""
        updated = False
        updates = {}
        
        for key, var in self.gui_vars.items():
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
            
            if self.app_controller.config[key] != val:
                self.app_controller.config[key] = val
                updates[key] = val
                updated = True
        
        # Save SSL configuration (MOVED OUTSIDE THE LOOP)
        if hasattr(self, 'ssl_enabled_var'):
            ssl_updated = False
            
            if self.app_controller.config.get("SSL_ENABLED") != self.ssl_enabled_var.get():
                self.app_controller.config["SSL_ENABLED"] = self.ssl_enabled_var.get()
                updates["SSL_ENABLED"] = self.ssl_enabled_var.get()
                ssl_updated = True
                
            if self.app_controller.config.get("SSL_CERT_PATH") != self.ssl_cert_var.get():
                self.app_controller.config["SSL_CERT_PATH"] = self.ssl_cert_var.get()
                updates["SSL_CERT_PATH"] = self.ssl_cert_var.get()
                ssl_updated = True
                
            if self.app_controller.config.get("SSL_KEY_PATH") != self.ssl_key_var.get():
                self.app_controller.config["SSL_KEY_PATH"] = self.ssl_key_var.get()
                updates["SSL_KEY_PATH"] = self.ssl_key_var.get()
                ssl_updated = True
                
            if self.app_controller.config.get("SSL_CA_CERT_PATH") != self.ssl_ca_var.get():
                self.app_controller.config["SSL_CA_CERT_PATH"] = self.ssl_ca_var.get()
                updates["SSL_CA_CERT_PATH"] = self.ssl_ca_var.get()
                ssl_updated = True
            
            if ssl_updated:
                updated = True
        
        if updated:
            save_config(self.app_controller.config)
            self.app_controller.update_config(self.app_controller.config)
            messagebox.showinfo("Success", "Configuration saved successfully")
            
            # Log configuration changes if server is running
            if self.app_controller.server_running:
                admin_user = self.app_controller.config.get("ADMIN_USERNAME", "admin")
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

    def reset_config_to_defaults(self):
        """Reset all configuration to defaults."""
        if messagebox.askyesno("Reset Configuration", 
                              "Are you sure you want to reset all settings to defaults? This will not affect the database."):
            # Keep admin settings
            admin_username = self.app_controller.config.get("ADMIN_USERNAME", "")
            admin_email = self.app_controller.config.get("ADMIN_EMAIL", "")
            
            # Reset config
            for key, val in DEFAULT_CONFIG.items():
                # Skip environment variable settings
                env_var = f"VESPEYR_AUTH_{key}"
                if env_var in os.environ:
                    continue
                    
                self.app_controller.config[key] = val
            
            # Restore admin settings
            if admin_username:
                self.app_controller.config["ADMIN_USERNAME"] = admin_username
            if admin_email:
                self.app_controller.config["ADMIN_EMAIL"] = admin_email
                
            save_config(self.app_controller.config)
            
            # Update UI
            for key, var in self.gui_vars.items():
                # Skip environment variable settings
                env_var = f"VESPEYR_AUTH_{key}"
                if env_var in os.environ:
                    continue
                    
                val = self.app_controller.config[key]
                if isinstance(var, tk.BooleanVar):
                    var.set(bool(val))
                else:
                    var.set(str(val))
                    
            messagebox.showinfo("Success", "Configuration reset to defaults")
    
    def generate_new_jwt_secret(self):
        """Generate a new random JWT secret."""
        # Check if JWT_SECRET is from environment variable
        if "VESPEYR_AUTH_JWT_SECRET" in os.environ:
            messagebox.showinfo("Environment Variable", 
                              "JWT_SECRET is set from environment variable. Please update the environment variable instead.")
            return
            
        if messagebox.askyesno("Generate JWT Secret", 
                              "Generate a new random JWT secret? This will invalidate all existing tokens."):
            import secrets
            new_secret = secrets.token_hex(32)
            self.gui_vars["JWT_SECRET"].set(new_secret)
            self.app_controller.config["JWT_SECRET"] = new_secret
            save_config(self.app_controller.config)
            messagebox.showinfo("Success", "Generated new JWT secret")
    
    def check_mysql_connection(self):
        """Test MySQL connection with current settings."""
        if self.app_controller.config.get("DB_TYPE") != "mysql":
            messagebox.showinfo("Database Type", "Please set DB_TYPE to 'mysql' first")
            return
        
        try:
            import pymysql
        
            # Try to connect to MySQL
            conn = pymysql.connect(
                host=self.app_controller.config.get("DB_HOST", "localhost"),
                port=int(self.app_controller.config.get("DB_PORT", 3306)),
                user=self.app_controller.config.get("DB_USER", ""),
                password=self.app_controller.config.get("DB_PASSWORD", "")
            )
        
            # Try to create database if not exists
            cursor = conn.cursor()
            db_name = self.app_controller.config.get("DB_NAME", "vespeyr_auth")
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

    def add_ssl_configuration_section(self, parent, row_num):
        """Add SSL configuration section to the config tab."""
        
        # SSL Configuration Section
        ssl_frame = ttk.LabelFrame(parent, text="SSL/HTTPS Configuration")
        ssl_frame.grid(column=0, row=row_num, sticky='ew', padx=5, pady=5, columnspan=2)
        
        # SSL Enabled checkbox
        self.ssl_enabled_var = tk.BooleanVar(value=self.app_controller.config.get("SSL_ENABLED", False))
        ttk.Checkbutton(ssl_frame, text="Enable HTTPS/SSL", 
                       variable=self.ssl_enabled_var,
                       command=self.on_ssl_enabled_changed).grid(column=0, row=0, sticky='w', padx=10, pady=5, columnspan=2)
        
        # SSL Certificate Path
        ttk.Label(ssl_frame, text="SSL Certificate (.crt/.pem):").grid(column=0, row=1, sticky='e', padx=(10, 5), pady=5)
        self.ssl_cert_var = tk.StringVar(value=self.app_controller.config.get("SSL_CERT_PATH", ""))
        ssl_cert_frame = ttk.Frame(ssl_frame)
        ssl_cert_frame.grid(column=1, row=1, sticky='ew', padx=5, pady=5)
        ssl_cert_frame.columnconfigure(0, weight=1)
        
        self.ssl_cert_entry = ttk.Entry(ssl_cert_frame, textvariable=self.ssl_cert_var, width=50)
        self.ssl_cert_entry.grid(column=0, row=0, sticky='ew', padx=(0, 5))
        
        ttk.Button(ssl_cert_frame, text="Browse", 
                  command=lambda: self.browse_ssl_file(self.ssl_cert_var, "SSL Certificate", 
                                                     [("Certificate files", "*.crt *.pem *.cert"), ("All files", "*.*")])).grid(column=1, row=0)
        
        # SSL Private Key Path
        ttk.Label(ssl_frame, text="SSL Private Key (.key):").grid(column=0, row=2, sticky='e', padx=(10, 5), pady=5)
        self.ssl_key_var = tk.StringVar(value=self.app_controller.config.get("SSL_KEY_PATH", ""))
        ssl_key_frame = ttk.Frame(ssl_frame)
        ssl_key_frame.grid(column=1, row=2, sticky='ew', padx=5, pady=5)
        ssl_key_frame.columnconfigure(0, weight=1)
        
        self.ssl_key_entry = ttk.Entry(ssl_key_frame, textvariable=self.ssl_key_var, width=50)
        self.ssl_key_entry.grid(column=0, row=0, sticky='ew', padx=(0, 5))
        
        ttk.Button(ssl_key_frame, text="Browse", 
                  command=lambda: self.browse_ssl_file(self.ssl_key_var, "SSL Private Key", 
                                                     [("Key files", "*.key *.pem"), ("All files", "*.*")])).grid(column=1, row=0)
        
        # SSL CA Certificate Path (Optional)
        ttk.Label(ssl_frame, text="CA Certificate (Optional):").grid(column=0, row=3, sticky='e', padx=(10, 5), pady=5)
        self.ssl_ca_var = tk.StringVar(value=self.app_controller.config.get("SSL_CA_CERT_PATH", ""))
        ssl_ca_frame = ttk.Frame(ssl_frame)
        ssl_ca_frame.grid(column=1, row=3, sticky='ew', padx=5, pady=5)
        ssl_ca_frame.columnconfigure(0, weight=1)
        
        self.ssl_ca_entry = ttk.Entry(ssl_ca_frame, textvariable=self.ssl_ca_var, width=50)
        self.ssl_ca_entry.grid(column=0, row=0, sticky='ew', padx=(0, 5))
        
        ttk.Button(ssl_ca_frame, text="Browse", 
                  command=lambda: self.browse_ssl_file(self.ssl_ca_var, "CA Certificate", 
                                                     [("Certificate files", "*.crt *.pem *.cert"), ("All files", "*.*")])).grid(column=1, row=0)
        
        # SSL Validation and Generate Buttons
        ssl_buttons_frame = ttk.Frame(ssl_frame)
        ssl_buttons_frame.grid(column=0, row=4, columnspan=2, pady=10, padx=10, sticky='ew')
        
        self.ssl_validate_btn = ttk.Button(ssl_buttons_frame, text="Validate SSL Certificates", command=self.validate_ssl_certificates)
        self.ssl_validate_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(ssl_buttons_frame, text="Generate Test Certificates", command=self.generate_test_certificates).pack(side=tk.LEFT)
        
        # SSL Status Label
        self.ssl_status_var = tk.StringVar(value="SSL not configured")
        self.ssl_status_label = ttk.Label(ssl_frame, textvariable=self.ssl_status_var, foreground='orange')
        self.ssl_status_label.grid(column=0, row=5, columnspan=2, pady=5)
        
        # Configure column weights for proper resizing
        ssl_frame.columnconfigure(1, weight=1)
        
        # Update SSL field states
        self.on_ssl_enabled_changed()
        
        return row_num + 1

    def on_ssl_enabled_changed(self):
        """Handle SSL enabled checkbox change."""
        enabled = self.ssl_enabled_var.get()
        state = 'normal' if enabled else 'disabled'
        
        self.ssl_cert_entry.config(state=state)
        self.ssl_key_entry.config(state=state)
        self.ssl_ca_entry.config(state=state)
        self.ssl_validate_btn.config(state=state)
        
        if enabled:
            self.ssl_status_var.set("SSL enabled - validate certificates")
            self.ssl_status_label.config(foreground='orange')
        else:
            self.ssl_status_var.set("SSL disabled")
            self.ssl_status_label.config(foreground='gray')

    def browse_ssl_file(self, var, title, filetypes):
        """Browse for an SSL file and set the variable."""
        from tkinter import filedialog
        filename = filedialog.askopenfilename(title=f"Select {title}", filetypes=filetypes)
        if filename:
            var.set(filename)
            # Auto-validate if both cert and key are selected
            if hasattr(self, 'ssl_cert_var') and hasattr(self, 'ssl_key_var'):
                if self.ssl_cert_var.get() and self.ssl_key_var.get():
                    self.validate_ssl_certificates()

    def validate_ssl_certificates(self):
        """Validate SSL certificates."""
        try:
            from .server_runner import validate_ssl_certificates
            
            cert_path = self.ssl_cert_var.get()
            key_path = self.ssl_key_var.get()
            ca_path = self.ssl_ca_var.get() if self.ssl_ca_var.get() else None
            
            if not cert_path or not key_path:
                self.ssl_status_var.set("Please select certificate and key files")
                self.ssl_status_label.config(foreground='orange')
                messagebox.showwarning("SSL Validation", "Please select both certificate and private key files.")
                return
            
            issues = validate_ssl_certificates(cert_path, key_path, ca_path)
            
            if not issues:
                self.ssl_status_var.set("✅ SSL certificates valid")
                self.ssl_status_label.config(foreground='green')
                messagebox.showinfo("SSL Validation", "SSL certificates are valid and ready for HTTPS!")
            else:
                self.ssl_status_var.set("❌ SSL certificate issues found")
                self.ssl_status_label.config(foreground='red')
                error_msg = "SSL Certificate Issues:\n\n" + "\n".join(f"• {issue}" for issue in issues)
                messagebox.showerror("SSL Validation Failed", error_msg)
                
        except Exception as e:
            self.ssl_status_var.set("SSL validation error")
            self.ssl_status_label.config(foreground='red')
            messagebox.showerror("SSL Validation Error", f"Failed to validate SSL certificates:\n\n{str(e)}")

    def generate_test_certificates(self):
        """Generate self-signed test certificates."""
        from tkinter import filedialog, simpledialog
        
        # Ask user where to save certificates
        cert_dir = filedialog.askdirectory(title="Select directory to save SSL certificates")
        if not cert_dir:
            return
        
        try:
            # Ask for domain name
            domain = simpledialog.askstring("Domain Name", "Enter domain name for certificate:", initialvalue="localhost")
            if not domain:
                domain = "localhost"
            
            # Generate certificates using Python cryptography
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                import ipaddress
                from datetime import datetime, timedelta
            except ImportError:
                messagebox.showerror("Missing Library", 
                                   "The 'cryptography' library is required to generate certificates.\n\n"
                                   "Install it with: pip install cryptography")
                return
            
            cert_file = os.path.join(cert_dir, "server.crt")
            key_file = os.path.join(cert_dir, "server.key")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Write private key
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Write certificate
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Update the fields with the generated certificate paths
            self.ssl_cert_var.set(cert_file)
            self.ssl_key_var.set(key_file)
            
            # Validate the generated certificates
            self.validate_ssl_certificates()
            
            messagebox.showinfo("Certificates Generated", 
                              f"SSL certificates generated successfully!\n\n"
                              f"Certificate: {cert_file}\n"
                              f"Private Key: {key_file}\n\n"
                              f"Domain: {domain}\n"
                              f"Valid for: 365 days\n\n"
                              f"⚠️ These are self-signed certificates for testing only.\n"
                              f"Browsers will show security warnings.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error generating certificates:\n\n{str(e)}")