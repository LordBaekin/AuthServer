# gui/main.py - Main GUI initialization and window setup
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
import os
import sys

from db import db_execute
from config import config, APP_VERSION

from .app_controller import AppController
from .config_tab import ConfigTab
from .logs_tab import LogsTab
from .status_tab import StatusTab
from .database_tab import DatabaseTab
from .scheduled_tasks import ScheduledTasksManager
from .admin_setup import AdminSetupDialog
from api_console import ApiConsoleFrame
from .templates_tab import TemplatesTab

# Import theme and update managers
try:
    from tk_theme_manager import get_theme_manager, ThemeSelector
    _has_theme_support = True
except ImportError:
    _has_theme_support = False
    logging.warning("Theme manager not available")

try:
    from tk_update_manager import UpdateManager
    _has_update_support = True
except ImportError:
    _has_update_support = False
    logging.warning("Update manager not available")

# Global task manager reference that will be set later
_task_manager = None

def create_gui():
    """Create and initialize the main GUI application.
    
    This function is called by server.py, which handles database initialization,
    logging setup, and signal handlers.
    
    Returns:
        tk.Tk: The root Tkinter window.
    """
    global _task_manager
    
    # Create app controller
    app_controller = AppController()
    app_controller.config = config
    
    # Use the shared task manager instance or create a new one
    if _task_manager is not None:
        app_controller.task_manager = _task_manager
    else:
        app_controller.task_manager = ScheduledTasksManager()
        _task_manager = app_controller.task_manager
    
    # Check if admin is configured
    first_run = not config.get("ADMIN_USERNAME") or not config.get("ADMIN_EMAIL")
    
    # Create main window
    root = tk.Tk()
    root.title(f'Vespeyr Auth Server Console v{APP_VERSION}')
    root.geometry('900x650')
    root.minsize(800, 600)
    
    # Store app controller in root for access from server.py
    root.app_controller = app_controller
    
    # Set app icon (if exists)
    try:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'icon.ico')
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
    
    # Initialize theme manager if available
    theme_manager = None
    if _has_theme_support:
        theme_manager = get_theme_manager()
    
    # Create toolbar at the top
    toolbar = ttk.Frame(root)
    toolbar.pack(side=tk.TOP, fill=tk.X, padx=10, pady=5)
    
    # Add theme selector
    if _has_theme_support:
        theme_selector = ThemeSelector(toolbar)
        theme_selector.pack(side=tk.LEFT, padx=5)
    
    # Initialize update manager
    update_manager = None
    if _has_update_support:
        try:
            update_url = config.get("UPDATE_MANIFEST_URL", "https://example.com/vespeyr/manifest.json")
            update_manager = UpdateManager(root, update_url, APP_VERSION)
            
            # Add update button
            update_btn = ttk.Button(
                toolbar, 
                text="Check for Updates", 
                command=update_manager.check_for_updates
            )
            update_btn.pack(side=tk.RIGHT, padx=5)
        except Exception as e:
            logging.error(f"Failed to initialize update manager: {e}")
    
    # Create notebook for tabs
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    # Create tabs
    config_tab = ConfigTab(notebook, app_controller)
    logs_tab = LogsTab(notebook, app_controller)
    status_tab = StatusTab(notebook, app_controller)
    database_tab = DatabaseTab(notebook, app_controller)
    templates_tab = TemplatesTab(notebook)
    
    # Fix for the API Console: Use localhost instead of 0.0.0.0 for client connections
    host = "localhost" if config.get('HOST') == '0.0.0.0' else config.get('HOST', 'localhost')
    api_tab = ApiConsoleFrame(notebook, api_base=f"http://{host}:{config.get('PORT', 5000)}")
    
    # Register tabs with controller
    app_controller.register_tab('config', config_tab)
    app_controller.register_tab('logs', logs_tab)
    app_controller.register_tab('status', status_tab)
    app_controller.register_tab('database', database_tab)
    app_controller.register_tab('api', api_tab)
    app_controller.register_tab('templates', templates_tab)
    
    # Add tabs to notebook
    notebook.add(config_tab, text='Configuration')
    notebook.add(logs_tab, text='Logs')
    notebook.add(status_tab, text='Server Status')
    notebook.add(database_tab, text='Database')
    notebook.add(api_tab, text='API Console')
    notebook.add(templates_tab, text='Email Templates')



    # Handle tab selection events
    def on_tab_change(event):
        tab_id = notebook.select()
        tab_index = notebook.index(tab_id)
        
        # Deselect previous tab if it has an on_tab_deselected method
        previous_tab = getattr(on_tab_change, 'previous_tab', None)
        if previous_tab is not None and hasattr(previous_tab, 'on_tab_deselected'):
            previous_tab.on_tab_deselected()
        
        # Get selected tab
        if tab_index == 0:
            selected_tab = config_tab
        elif tab_index == 1:
            selected_tab = logs_tab
        elif tab_index == 2:
            selected_tab = status_tab
        elif tab_index == 3:
            selected_tab = database_tab
        elif tab_index == 4:
            selected_tab = api_tab
        else:
            selected_tab = None
        
        # Call on_tab_selected if the tab has that method
        if selected_tab and hasattr(selected_tab, 'on_tab_selected'):
            selected_tab.on_tab_selected()
        
        # Store current tab for next change
        on_tab_change.previous_tab = selected_tab
    
    notebook.bind('<<NotebookTabChanged>>', on_tab_change)
    
    # Apply theme if theme support is available
    if _has_theme_support:
        try:
            # Apply theme to the entire UI
            theme_manager.apply_theme(root)
        except Exception as e:
            logging.error(f"Failed to apply theme: {e}")
    
    # Function to run after main window is shown
    def post_init():
        # If first run, show admin setup dialog
        if first_run:
            AdminSetupDialog(root, app_controller)
        elif update_manager and config.get("CHECK_UPDATES_ON_STARTUP", True):
            # Check for updates if enabled (with delay to ensure UI is loaded)
            root.after(3000, update_manager.check_for_updates)
    
    # Schedule post-initialization
    root.after(500, post_init)
    
    # Handle window close
    def on_closing():
        if app_controller.server_running:
            if messagebox.askyesno("Quit", "Server is still running. Are you sure you want to quit?"):
                if app_controller.task_manager:
                    app_controller.task_manager.stop()
                
                # Shutdown server if running
                if app_controller.server_running:
                    app_controller.shutdown_server()
                
                root.destroy()
        else:
            if app_controller.task_manager:
                app_controller.task_manager.stop()
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Select first tab to trigger on_tab_selected
    notebook.select(0)
    
    return root

# Set up the task manager that will be accessed from outside
def get_task_manager():
    """Get the task manager instance, creating it if needed."""
    global _task_manager
    if _task_manager is None:
        _task_manager = ScheduledTasksManager()
    return _task_manager

# Make sure create_gui is exported
__all__ = ['create_gui', 'get_task_manager']