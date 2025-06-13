# api_console.py
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import requests
import json
import os
import pathlib

class ApiConsoleFrame(ttk.Frame):
    def __init__(self, master, api_base="https://api.vespeyr.com:5000"):
        super().__init__(master)
        self.api_base = api_base.rstrip("/")
        self.access_token = None
        self.refresh_token = None
        
        # Path to RSA key files (must match what's in auth.py)
        self.private_key_path = os.path.join(
            pathlib.Path(__file__).parent.absolute(), 'private_key.pem'
        )
        self.public_key_path = os.path.join(
            pathlib.Path(__file__).parent.absolute(), 'public_key.pem'
        )

        # --- Login section ---
        login_frame = ttk.Labelframe(self, text="Login / Register")
        login_frame.pack(fill="x", pady=5, padx=5)

        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky="e")
        self.username_entry = ttk.Entry(login_frame, width=20)
        self.username_entry.grid(row=0, column=1, padx=2)

        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky="e")
        self.password_entry = ttk.Entry(login_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=1, padx=2)

        ttk.Button(login_frame, text="Login",   command=self.do_login).grid(row=0, column=2, rowspan=2, padx=10)
        ttk.Button(login_frame, text="Register",command=self.do_register).grid(row=0, column=3, rowspan=2)
        
        # --- JWT Configuration section ---
        jwt_frame = ttk.Labelframe(self, text="JWT Configuration")
        jwt_frame.pack(fill="x", pady=5, padx=5)
        
        # JWT Algorithm Selection
        ttk.Label(jwt_frame, text="JWT Algorithm:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.algorithm_var = tk.StringVar(value="auto")
        algorithm_combo = ttk.Combobox(jwt_frame, textvariable=self.algorithm_var, 
                                     values=["auto", "RS256", "HS256"], width=15, state="readonly")
        algorithm_combo.grid(row=0, column=1, sticky="w", padx=5, pady=5)
        algorithm_combo.bind("<<ComboboxSelected>>", self.update_jwt_algorithm)
        
        ttk.Button(jwt_frame, text="Update Algorithm", 
                 command=self.update_jwt_algorithm).grid(row=0, column=2, padx=5, pady=5)
        
        # RSA Key Management
        key_buttons_frame = ttk.Frame(jwt_frame)
        key_buttons_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        
        ttk.Button(key_buttons_frame, text="Generate New Keys", 
                 command=self.generate_new_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_buttons_frame, text="View Public Key", 
                 command=self.view_public_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_buttons_frame, text="View Private Key", 
                 command=self.view_private_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_buttons_frame, text="Copy Public Key", 
                 command=lambda: self.copy_key(self.public_key_path)).pack(side=tk.LEFT, padx=5)

        # --- Actions section ---
        actions_frame = ttk.Labelframe(self, text="Actions")
        actions_frame.pack(fill="x", pady=5, padx=5)

        buttons = [
          ("Profile",             self.do_profile),
          ("Change Password",     self.do_change_password),
          ("List Sessions",       self.do_list_sessions),
          ("Revoke Sessions",     self.do_revoke_sessions),
          ("Admin: List Users",   self.do_admin_list_users),
          ("Admin: Security Log", self.do_admin_security_log),
          ("Admin: Stats",        self.do_admin_stats),
        ]
        for col, (text, cmd) in enumerate(buttons):
            ttk.Button(actions_frame, text=text, command=cmd).grid(row=0, column=col, padx=2)

        # --- Output section ---
        out_frame = ttk.Labelframe(self, text="API Response")
        out_frame.pack(fill="both", expand=True, pady=5, padx=5)
        self.output = tk.Text(out_frame, wrap="none", height=15)
        self.output.pack(fill="both", expand=True)

    def update_jwt_algorithm(self, event=None):
        """Update the JWT algorithm setting on the server"""
        algorithm = self.algorithm_var.get()
        
        # Map UI selection to config value
        algorithm_map = {
            "auto": None,
            "RS256": "RS256",
            "HS256": "HS256"
        }
        
        config_value = algorithm_map.get(algorithm)
        
        # Call API to update the configuration
        body = {"setting": "FORCE_JWT_ALGORITHM", "value": config_value}
        try:
            resp = requests.post(f"{self.api_base}/auth/admin/config", 
                               headers={"Authorization": f"Bearer {self.access_token}"}, 
                               json=body, timeout=5)
            
            if resp.status_code == 200:
                messagebox.showinfo("Success", f"JWT algorithm updated to: {algorithm}")
            else:
                messagebox.showerror("Error", f"Failed to update JWT algorithm: {resp.text}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update JWT algorithm: {str(e)}")

    def generate_new_keys(self):
        """Generate new RSA key pair on the server"""
        try:
            resp = requests.post(f"{self.api_base}/auth/admin/generate-keys", 
                               headers={"Authorization": f"Bearer {self.access_token}"}, 
                               timeout=5)
            
            if resp.status_code == 200:
                messagebox.showinfo("Success", "New RSA keys generated successfully")
            else:
                messagebox.showerror("Error", f"Failed to generate new keys: {resp.text}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate new keys: {str(e)}")

    def view_public_key(self):
        """View the public key in a dialog window"""
        self._view_key(self.public_key_path, "Public Key")
    
    def view_private_key(self):
        """View the private key in a dialog window"""
        self._view_key(self.private_key_path, "Private Key")
    
    def _view_key(self, key_path, title):
        """Display a key file in a dialog window"""
        if not os.path.exists(key_path):
            messagebox.showerror("Error", f"{title} file not found at: {key_path}")
            return
            
        try:
            with open(key_path, 'r') as f:
                key_content = f.read()
                
            # Create dialog window
            dialog = tk.Toplevel(self)
            dialog.title(f"View {title}")
            dialog.geometry("600x400")
            dialog.transient(self)
            dialog.grab_set()
            
            # Add instructions label
            instructions = ttk.Label(dialog, 
                text=f"This is your {title.lower()}. " + 
                ("You'll need to provide this to Coherence Cloud." if title == "Public Key" else 
                 "Keep this secure and do not share it."))
            instructions.pack(pady=10, padx=10)
            
            # Add key text area
            key_text = scrolledtext.ScrolledText(dialog, width=70, height=15)
            key_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            key_text.insert(tk.END, key_content)
            key_text.config(state=tk.DISABLED)
            
            # Add copy button
            ttk.Button(dialog, text=f"Copy {title}", 
                     command=lambda: self._copy_to_clipboard(key_content)).pack(pady=10)
            
            # Add close button
            ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read {title.lower()}: {str(e)}")

    def copy_key(self, key_path):
        """Copy a key file to clipboard"""
        if not os.path.exists(key_path):
            messagebox.showerror("Error", f"Key file not found at: {key_path}")
            return
            
        try:
            with open(key_path, 'r') as f:
                key_content = f.read()
            
            self._copy_to_clipboard(key_content)
            messagebox.showinfo("Success", "Key copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy key: {str(e)}")

    def _copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.clipboard_clear()
        self.clipboard_append(text)
    
    def _call_api(self, method, path, json_body=None):
        url = f"{self.api_base}{path}"
        headers = {}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        try:
            resp = requests.request(method, url, headers=headers, json=json_body, timeout=5)
        except requests.exceptions.RequestException as e:
            messagebox.showerror(
                "Connection Error",
                f"Could not reach the server at {self.api_base}:\n{e}"
            )
            return

        # render response
        try:
            data = resp.json()
            pretty = json.dumps(data, indent=2)
        except Exception:
            pretty = resp.text or ""
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, f"{resp.status_code} {resp.reason}\n{pretty}")

        # Capture tokens on login/register/refresh
        if path in ("/auth/login", "/auth/register", "/auth/refresh") and resp.status_code == 200:
            self.access_token  = data.get("access_token")
            self.refresh_token = data.get("refresh_token")

    def do_login(self):
        body = {"username": self.username_entry.get(),
                "password": self.password_entry.get()}
        self._call_api("POST", "/auth/login", body)

    def do_register(self):
        body = {"username": self.username_entry.get(),
                "email":    f"{self.username_entry.get()}@example.com",
                "password": self.password_entry.get()}
    
        # Call API with improved error handling
        try:
            resp = requests.post(f"{self.api_base}/auth/register", 
                                headers={}, json=body, timeout=5)
        
            # Parse response
            try:
                data = resp.json()
            except:
                data = {"error": resp.text or "Unknown error"}
        
            # Output results to the text widget
            self.output.delete("1.0", tk.END)
            self.output.insert(tk.END, f"{resp.status_code} {resp.reason}\n")
        
            if resp.status_code == 409:
                # Highlight error for duplicate username
                error_msg = data.get("error", "Username already exists")
                self.output.insert(tk.END, f"ERROR: {error_msg}\n\n")
                self.output.insert(tk.END, "Please try a different username.")
            else:
                # Regular response display
                import json
                pretty = json.dumps(data, indent=2)
                self.output.insert(tk.END, pretty)
        
            # Capture tokens on success
            if resp.status_code == 201:
                self.access_token = data.get("access_token")
                self.refresh_token = data.get("refresh_token")
            
        except requests.exceptions.RequestException as e:
            messagebox.showerror(
                "Connection Error",
                f"Could not reach the server at {self.api_base}:\n{e}"
            )
            return

    def do_profile(self):
        self._call_api("GET", "/auth/profile")

    def do_change_password(self):
        new_pw = simpledialog.askstring("Change Password", "New password:", show="*")
        if not new_pw:
            return
        body = {"current_password": self.password_entry.get(),
                "new_password":     new_pw}
        self._call_api("POST", "/auth/change-password", body)

    def do_list_sessions(self):
        self._call_api("GET", "/auth/sessions")

    def do_revoke_sessions(self):
        if messagebox.askyesno("Revoke", "Revoke all sessions except current?"):
            self._call_api("POST", "/auth/sessions/revoke", {"all_except_current": True})

    def do_admin_list_users(self):
        self._call_api("GET", "/auth/admin/users")

    def do_admin_security_log(self):
        self._call_api("GET", "/auth/admin/security-log")

    def do_admin_stats(self):
        self._call_api("GET", "/auth/admin/stats")