# gui/logs_tab.py - Logs tab implementation
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import logging

from .base import BaseTab
from config import LOG_DIR

class LogsTab(BaseTab):
    def __init__(self, parent, app_controller):
        self.log_file_var = None
        self.filter_var = None
        self.log_status_var = None
        self.log_viewer = None
        super().__init__(parent, app_controller)
        
    def setup_ui(self):
        """Set up the logs tab UI."""
        # Header
        logs_label = ttk.Label(self, text="Server Logs", style='Header.TLabel')
        logs_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
        
        # Log file selector
        log_selector_frame = ttk.Frame(self)
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
        
        self.log_file_var = tk.StringVar(value=available_logs[0] if available_logs else "auth_server.log")
        log_file_combo = ttk.Combobox(log_selector_frame, textvariable=self.log_file_var, width=30, 
                                    values=available_logs)
        log_file_combo.grid(column=1, row=0, padx=5, sticky='w')
        
        # Filter frame
        filter_frame = ttk.LabelFrame(log_selector_frame, text="Filter")
        filter_frame.grid(column=2, row=0, padx=10, sticky='w')
        
        self.filter_var = tk.StringVar(value="")
        ttk.Entry(filter_frame, textvariable=self.filter_var, width=20).grid(column=0, row=0, padx=5, pady=5)
        ttk.Button(filter_frame, text="Apply", command=self.load_log_file).grid(column=1, row=0, padx=5, pady=5)
        
        # Log viewer
        self.log_viewer = scrolledtext.ScrolledText(self, width=90, height=20, wrap=tk.NONE)
        self.log_viewer.grid(column=0, row=2, sticky='nsew', padx=5, pady=5)
        self.log_viewer.config(state=tk.DISABLED)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        
        # Log status bar
        self.log_status_var = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.log_status_var).grid(column=0, row=3, sticky='w', padx=5)
        
        # Log controls
        log_controls = ttk.Frame(self)
        log_controls.grid(column=0, row=4, sticky='ew', padx=5, pady=5)
        
        ttk.Button(log_controls, text="Refresh", command=self.load_log_file).grid(
            column=0, row=0, padx=5
        )
        ttk.Button(log_controls, text="Clear Log", command=self.clear_log_file).grid(
            column=1, row=0, padx=5
        )
        
        # Bind events
        log_file_combo.bind('<<ComboboxSelected>>', lambda e: self.load_log_file())
        
        # Load initial log file
        self.load_log_file()
    
    def load_log_file(self):
        """Load and display selected log file."""
        filename = os.path.join(LOG_DIR, self.log_file_var.get())
        filter_text = self.filter_var.get().strip().lower()
        
        self.log_viewer.config(state=tk.NORMAL)
        self.log_viewer.delete(1.0, tk.END)
        
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
                        self.log_viewer.insert(tk.END, line)
                        
                    self.log_status_var.set(f"Loaded {len(lines)} lines from {os.path.basename(filename)}")
            else:
                self.log_viewer.insert(tk.END, f"Log file {filename} does not exist yet.")
                self.log_status_var.set("Log file not found")
        except Exception as e:
            self.log_viewer.insert(tk.END, f"Error loading log file: {str(e)}")
            self.log_status_var.set(f"Error: {str(e)}")
            
        self.log_viewer.see(tk.END)
        self.log_viewer.config(state=tk.DISABLED)
    
    def clear_log_file(self):
        """Clear the current log file."""
        filename = os.path.join(LOG_DIR, self.log_file_var.get())
        
        if messagebox.askyesno("Clear Log", f"Are you sure you want to clear {self.log_file_var.get()}?"):
            try:
                if os.path.exists(filename):
                    with open(filename, 'w') as f:
                        pass  # Just open and truncate
                    
                    self.log_viewer.config(state=tk.NORMAL)
                    self.log_viewer.delete(1.0, tk.END)
                    self.log_viewer.insert(tk.END, f"Log file {filename} has been cleared.")
                    self.log_viewer.config(state=tk.DISABLED)
                    
                    self.log_status_var.set(f"Cleared log file {os.path.basename(filename)}")
                else:
                    messagebox.showinfo("Log Not Found", f"Log file {filename} does not exist yet.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear log file: {str(e)}")
                
    def on_tab_selected(self):
        """Called when this tab is selected."""
        # Refresh log file
        self.load_log_file()
