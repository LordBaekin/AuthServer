# api_console.py
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests
import json

class ApiConsoleFrame(ttk.Frame):
    def __init__(self, master, api_base="http://localhost:5000"):
        super().__init__(master)
        self.api_base = api_base.rstrip("/")
        self.access_token = None
        self.refresh_token = None

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
        self._call_api("POST", "/auth/register", body)

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
