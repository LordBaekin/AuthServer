# gui/utils.py - Shared utility functions
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import os

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
        
    def restore(self):
        """Restore original stdout and stderr."""
        sys.stdout = self.stdout
        sys.stderr = self.stderr

# Create a scrollable frame
def create_scrollable_frame(parent):
    """Create and return a scrollable frame with canvas."""
    container = ttk.Frame(parent)
    
    canvas = tk.Canvas(container)
    scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    
    scrollable_frame = ttk.Frame(canvas)
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Enable mouse wheel scrolling
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    canvas.bind_all("<MouseWheel>", _on_mousewheel)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    return container, scrollable_frame

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
