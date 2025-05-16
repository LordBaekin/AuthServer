# gui/admin_setup.py - Admin setup dialog
import tkinter as tk
from tkinter import ttk, messagebox
import uuid
import time
import logging
import bcrypt

from config import config, save_config
from db import db_execute, init_db

class AdminSetupDialog:
    def __init__(self, parent, app_controller):
        self.parent = parent
        self.app_controller = app_controller
        self.admin_username_var = tk.StringVar(value=app_controller.config.get("ADMIN_USERNAME", ""))
        self.admin_email_var = tk.StringVar(value=app_controller.config.get("ADMIN_EMAIL", ""))
        self.admin_password_var = tk.StringVar()
        
        self.create_dialog()
        
    def create_dialog(self):
        """Create the admin setup dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Admin Setup")
        self.dialog.geometry("400x300")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center dialog
        self.dialog.update_idletasks()
        x = self.parent.winfo_rootx() + (self.parent.winfo_width() - self.dialog.winfo_width()) // 2
        y = self.parent.winfo_rooty() + (self.parent.winfo_height() - self.dialog.winfo_height()) // 2
        self.dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        
        # Add admin setup fields
        ttk.Label(self.dialog, text="Welcome to Vespeyr Auth Server Setup", 
                 font=('Helvetica', 12, 'bold')).pack(pady=(20, 10))
        
        ttk.Label(self.dialog, text="Please set up your admin credentials").pack(pady=(0, 20))
        
        # Username
        username_frame = ttk.Frame(self.dialog)
        username_frame.pack(fill=tk.X, padx=30, pady=5)
        
        ttk.Label(username_frame, text="Admin Username:").pack(side=tk.LEFT)
        ttk.Entry(username_frame, textvariable=self.admin_username_var, width=25).pack(side=tk.RIGHT)
        
        # Email
        email_frame = ttk.Frame(self.dialog)
        email_frame.pack(fill=tk.X, padx=30, pady=5)
        
        ttk.Label(email_frame, text="Admin Email:").pack(side=tk.LEFT)
        ttk.Entry(email_frame, textvariable=self.admin_email_var, width=25).pack(side=tk.RIGHT)
        
        # Password
        password_frame = ttk.Frame(self.dialog)
        password_frame.pack(fill=tk.X, padx=30, pady=5)
        
        ttk.Label(password_frame, text="Admin Password:").pack(side=tk.LEFT)
        ttk.Entry(password_frame, textvariable=self.admin_password_var, show="*", width=25).pack(side=tk.RIGHT)
        
        # Buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Save Admin Settings", command=self.setup_admin).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Skip", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # Make dialog modal
        self.dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing with X
        
    def setup_admin(self):
        """Set up admin credentials and create/update user in the database."""
        admin_username = self.admin_username_var.get().strip()
        admin_email = self.admin_email_var.get().strip()
        admin_password = self.admin_password_var.get().strip()
        
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
        self.app_controller.config["ADMIN_USERNAME"] = admin_username
        self.app_controller.config["ADMIN_EMAIL"] = admin_email
        save_config(self.app_controller.config)
        
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
            self.dialog.destroy()
            
            # Show success message
            messagebox.showinfo("Success", 
                              f"Admin user '{admin_username}' has been created.\n\n"
                              f"You can now start the server and login with these credentials.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create admin user: {str(e)}")
            logging.error(f"Admin setup error: {str(e)}")
