# gui/base.py - Base classes for GUI components
import tkinter as tk
from tkinter import ttk

class BaseTab(ttk.Frame):
    """Base class for all tabs in the application."""
    
    def __init__(self, parent, app_controller):
        super().__init__(parent, padding=10)
        self.parent = parent
        self.app_controller = app_controller
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface - to be implemented by subclasses."""
        raise NotImplementedError
        
    def update(self):
        """Update any dynamic content - called periodically."""
        pass
        
    def on_tab_selected(self):
        """Called when this tab is selected."""
        pass
        
    def on_tab_deselected(self):
        """Called when user navigates away from this tab."""
        pass
        
    def on_config_updated(self, config):
        """Called when configuration has been updated."""
        pass
        
    def on_server_status_changed(self, running):
        """Called when server status has changed."""
        pass
