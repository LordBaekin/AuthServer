import tkinter as tk
from tkinter import ttk, messagebox
from email_service import load_templates, save_template

class TemplatesTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        # Load available template names
        self.templates = list(load_templates().keys())
        # Current selected template
        self.current = tk.StringVar(value=self.templates[0] if self.templates else "")

        # Top: template selection dropdown
        ttk.Label(self, text="Select template:").grid(row=0, column=0, sticky="w", pady=5)
        self.combo = ttk.Combobox(
            self,
            values=self.templates,
            textvariable=self.current,
            state="readonly"
        )
        self.combo.grid(row=0, column=1, sticky="ew", pady=5)
        self.combo.bind("<<ComboboxSelected>>", lambda e: self._load())

        # Middle: text editor for template content
        self.text = tk.Text(self, wrap="none")
        self.text.grid(row=1, column=0, columnspan=2, sticky="nsew")

        # Scrollbars for the text editor
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        vsb.grid(row=1, column=2, sticky="ns")
        self.text.configure(yscrollcommand=vsb.set)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        hsb.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.text.configure(xscrollcommand=hsb.set)

        # Bottom: save button
        self.save_btn = ttk.Button(self, text="Save Template", command=self._save)
        self.save_btn.grid(row=3, column=0, columnspan=2, pady=10)

        # Configure resizing behavior
        self.rowconfigure(1, weight=1)
        self.columnconfigure(1, weight=1)

        # Load initial template content
        if self.templates:
            self._load()

    def _load(self):
        """Load the selected template into the text editor"""
        name = self.current.get()
        templates = load_templates()
        content = templates.get(name, "")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)

    def _save(self):
        """Save the current text editor content back to disk"""
        name = self.current.get()
        content = self.text.get("1.0", "end")
        success = save_template(name, content)
        if success:
            messagebox.showinfo(
                "Saved",
                f"Template '{name}' has been saved.",
                parent=self
            )
        else:
            messagebox.showerror(
                "Error",
                f"Failed to save template '{name}'.",
                parent=self
            )
