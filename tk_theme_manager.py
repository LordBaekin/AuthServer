# tk_theme_manager.py - Simple Tkinter theme manager
import tkinter as tk
from tkinter import ttk
import json
import os

# Simple, reliable theme definitions for Tkinter
THEMES = {
    "Light": {
        "bg": "#f5f5f5",
        "fg": "#000000",
        "selected_bg": "#0078d7",
        "selected_fg": "#ffffff",
        "input_bg": "#ffffff",
        "button_bg": "#e1e1e1",
        "success": "#008000",
        "error": "#e74c3c",
        "warning": "#f39c12"
    },
    "Dark": {
        "bg": "#1e1e1e",
        "fg": "#ffffff",
        "selected_bg": "#0078d7",
        "selected_fg": "#ffffff",
        "input_bg": "#2d2d2d",
        "button_bg": "#3c3c3c",
        "success": "#27ae60",
        "error": "#e74c3c",
        "warning": "#f39c12"
    },
    "Blue": {
        "bg": "#1e3a8a",
        "fg": "#ffffff",
        "selected_bg": "#5b94fc",
        "selected_fg": "#ffffff",
        "input_bg": "#2e4a9a",
        "button_bg": "#385baa",
        "success": "#27ae60",
        "error": "#e74c3c",
        "warning": "#f39c12"
    },
    "Neutral": {
        "bg": "#f0f0f0",
        "fg": "#333333",
        "selected_bg": "#a0a0a0",
        "selected_fg": "#ffffff",
        "input_bg": "#ffffff",
        "button_bg": "#d1d1d1",
        "success": "#27ae60",
        "error": "#e74c3c",
        "warning": "#f39c12"
    }
}

# File to store theme preferences
THEME_CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "theme_config.json"
)

class ThemeManager:
    def __init__(self):
        """Initialize the theme manager"""
        self.current_theme = self._load_theme_preference()
    
    def _load_theme_preference(self):
        """Load theme preference from file or return default"""
        try:
            if os.path.exists(THEME_CONFIG_FILE):
                with open(THEME_CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    theme = data.get('theme', 'Light')
                    if theme in THEMES:
                        return theme
        except:
            pass
        return "Light"  # Default theme
    
    def _save_theme_preference(self):
        """Save current theme preference to file"""
        try:
            with open(THEME_CONFIG_FILE, 'w') as f:
                json.dump({'theme': self.current_theme}, f)
        except:
            pass
    
    def get_current_theme(self):
        """Get current theme name"""
        return self.current_theme
        
    def get_theme_colors(self):
        """Get current theme colors dictionary"""
        return THEMES.get(self.current_theme, THEMES["Light"])
    
    def set_theme(self, theme_name):
        """Set theme by name and save preference"""
        if theme_name not in THEMES:
            return False
        self.current_theme = theme_name
        self._save_theme_preference()
        return True
    
    def apply_theme(self, root):
        """Apply theme to all widgets in the root window"""
        colors = self.get_theme_colors()

        # ——————————————————————————————————————————————————
        # 1) Setup ttk.Style on a theme we can fully override
        # ——————————————————————————————————————————————————
        style = ttk.Style(root)
        style.theme_use("clam")

        # ——————————————————————————————————————————————————
        # 2) YOUR ORIGINAL ttk CONFIGURATIONS (unchanged)
        # ——————————————————————————————————————————————————
        style.configure('TButton',
                        background=colors["button_bg"],
                        foreground=colors["fg"])
        style.configure('TLabel',
                        background=colors["bg"],
                        foreground=colors["fg"])
        style.configure('Header.TLabel',
                        background=colors["bg"],
                        foreground=colors["fg"],
                        font=('Helvetica', 12, 'bold'))
        style.configure('TFrame',
                        background=colors["bg"])
        style.configure('TLabelframe',
                        background=colors["bg"],
                        foreground=colors["fg"])
        style.configure('TLabelframe.Label',
                        background=colors["bg"],
                        foreground=colors["fg"])
        style.configure('TEntry',
                        fieldbackground=colors["input_bg"],
                        foreground=colors["fg"])
        style.configure('TCombobox',
                        fieldbackground=colors["input_bg"],
                        background=colors["button_bg"],
                        foreground=colors["fg"])
        style.map('TCombobox',
                  fieldbackground=[('readonly', colors["input_bg"])])
        style.configure('TNotebook',
                        background=colors["bg"])
        style.configure('TNotebook.Tab',
                        background=colors["button_bg"],
                        foreground=colors["fg"])
        style.map('TNotebook.Tab',
                  background=[('selected', colors["selected_bg"])],
                  foreground=[('selected', colors["selected_fg"])])
        style.configure('Success.TLabel',
                        background=colors["bg"],
                        foreground=colors["success"])
        style.configure('Error.TLabel',
                        background=colors["bg"],
                        foreground=colors["error"])
        style.configure('Warning.TLabel',
                        background=colors["bg"],
                        foreground=colors["warning"])

        # ——————————————————————————————————————————————————
        # 3) NEW: enforce true defaults + style common widgets
        # ——————————————————————————————————————————————————
        # 3a) Catch-all so any ttk widget not explicitly configured uses our bg/fg
        style.configure(".",
                        background=colors["bg"],
                        foreground=colors["fg"])
        # 3b) Button hover & pressed
        style.map("TButton",
                  background=[("active", colors["selected_bg"]),
                              ("pressed", colors["selected_bg"])],
                  foreground=[("active", colors["selected_fg"]),
                              ("pressed", colors["selected_fg"])])
        # 3c) Spinbox & Checkbutton
        style.configure("TSpinbox",
                        fieldbackground=colors["input_bg"],
                        foreground=colors["fg"])
        style.configure("TCheckbutton",
                        background=colors["bg"],
                        foreground=colors["fg"])
        # 3d) ttk Scrollbars
        style.configure("TScrollbar",
                        troughcolor=colors["button_bg"],
                        background=colors["bg"],
                        arrowcolor=colors["fg"])
        # 3e) Treeview (if you happen to use one for logs/status)
        style.configure("Treeview",
                        background=colors["input_bg"],
                        fieldbackground=colors["input_bg"],
                        foreground=colors["fg"])
        style.map("Treeview",
                  background=[("selected", colors["selected_bg"])],
                  foreground=[("selected", colors["selected_fg"])])

        # ——————————————————————————————————————————————————
        # 4) Apply to root + pure-tk recursion (with scrollbar theming)
        # ——————————————————————————————————————————————————
        root.configure(background=colors["bg"])

        def recurse(widget):
            try:
                # if the widget supports a 'background' option, set it
                if 'background' in widget.configure():
                    bg_key = 'input_bg' if isinstance(widget, tk.Text) else 'bg'
                    widget.configure(background=colors.get(bg_key, colors["bg"]))
                # text widgets also need fg/insert/select
                if isinstance(widget, (tk.Entry, tk.Text)):
                    widget.configure(
                        foreground=colors["fg"],
                        insertbackground=colors["fg"],
                        selectbackground=colors["selected_bg"],
                        selectforeground=colors["selected_fg"]
                    )
                # pure-tk Scrollbar theming
                if isinstance(widget, tk.Scrollbar):
                    widget.configure(
                        background=colors["bg"],
                        troughcolor=colors["button_bg"],
                        activebackground=colors["selected_bg"],
                        arrowcolor=colors["fg"],
                        troughrelief='flat',
                        highlightbackground=colors["bg"]
                    )
            except tk.TclError:
                pass

            for child in widget.winfo_children():
                recurse(child)

        recurse(root)

    def _apply_theme_to_widget(self, widget, colors):
        """Apply theme to a specific widget and its children"""
        # (This method is unused by apply_theme now, but preserved for backward
        # compatibility if you ever call it directly elsewhere.)
        try:
            widget.winfo_exists()
            if isinstance(widget, tk.Button):
                widget.configure(
                    background=colors["button_bg"],
                    foreground=colors["fg"],
                    activebackground=colors["selected_bg"],
                    activeforeground=colors["selected_fg"],
                    highlightbackground=colors["bg"]
                )
            elif isinstance(widget, tk.Label):
                widget.configure(
                    background=colors["bg"],
                    foreground=colors["fg"]
                )
            elif isinstance(widget, (tk.Frame, tk.LabelFrame)):
                widget.configure(background=colors["bg"])
                if isinstance(widget, tk.LabelFrame):
                    try:
                        widget.configure(foreground=colors["fg"])
                    except:
                        pass
            elif isinstance(widget, (tk.Entry, tk.Text)):
                widget.configure(
                    background=colors["input_bg"],
                    foreground=colors["fg"],
                    insertbackground=colors["fg"],
                    selectbackground=colors["selected_bg"],
                    selectforeground=colors["selected_fg"]
                )
            elif isinstance(widget, tk.Scrollbar):
                widget.configure(
                    background=colors["bg"],
                    troughcolor=colors["button_bg"],
                    activebackground=colors["selected_bg"],
                    arrowcolor=colors["fg"],
                    troughrelief='flat',
                    highlightbackground=colors["bg"]
                )
        except:
            pass

        for child in widget.winfo_children():
            self._apply_theme_to_widget(child, colors)

# Global theme manager instance
_theme_manager = None

def get_theme_manager():
    """Get the global theme manager instance"""
    global _theme_manager
    if _theme_manager is None:
        _theme_manager = ThemeManager()
    return _theme_manager

# Theme selector widget
class ThemeSelector(ttk.Frame):
    """Widget for selecting themes"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.theme_manager = get_theme_manager()

        ttk.Label(self, text="Theme:").pack(side=tk.LEFT, padx=5)
        self.theme_var = tk.StringVar(
            value=self.theme_manager.get_current_theme()
        )
        self.theme_combo = ttk.Combobox(
            self,
            textvariable=self.theme_var,
            values=list(THEMES.keys()),
            width=10,
            state="readonly"
        )
        self.theme_combo.pack(side=tk.LEFT, padx=5)
        self.theme_combo.bind(
            "<<ComboboxSelected>>", self._on_theme_changed
        )

    def _on_theme_changed(self, event):
        """Handle theme selection change"""
        theme_name = self.theme_var.get()
        if self.theme_manager.set_theme(theme_name):
            self.theme_manager.apply_theme(
                self.winfo_toplevel()
            )
