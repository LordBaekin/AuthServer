# tk_update_manager.py - Simplified update manager for Tkinter
import os
import sys
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import urllib.request
import urllib.error
from urllib.parse import urlparse
import tempfile
import shutil

class UpdateManager:
    def __init__(self, parent, manifest_url, current_version):
        """
        Initialize the update manager

        Args:
            parent: Parent Tkinter window
            manifest_url: URL to the update manifest JSON
            current_version: Current application version string
        """
        self.parent = parent
        self.manifest_url = manifest_url
        self.current_version = current_version
        self.progress_dialog = None
        self.download_path = None

        # Check if this is first run after update
        self._check_first_run()

    def _check_first_run(self):
        """Check if this is the first run after an update"""
        try:
            config_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "update_config.json"
            )
            last_version = None

            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    last_version = data.get('last_version')

            # If the version has changed, show a notification
            if last_version and last_version != self.current_version:
                messagebox.showinfo(
                    "Update Complete",
                    f"Successfully updated to version {self.current_version}",
                    parent=self.parent
                )

            # Save current version
            with open(config_path, 'w') as f:
                json.dump({'last_version': self.current_version}, f)

        except Exception as e:
            print(f"Error checking first run status: {e}")

    def check_for_updates(self):
        """Check for application updates"""
        try:
            # Create progress dialog
            self.progress_dialog = tk.Toplevel(self.parent)
            self.progress_dialog.title("Checking for Updates")
            self.progress_dialog.geometry("300x120")
            self.progress_dialog.transient(self.parent)
            self.progress_dialog.grab_set()
            self.progress_dialog.resizable(False, False)

            # Center the dialog
            sw = self.parent.winfo_screenwidth()
            sh = self.parent.winfo_screenheight()
            x = (sw - 300) // 2
            y = (sh - 120) // 2
            self.progress_dialog.geometry(f"+{x}+{y}")

            ttk.Label(self.progress_dialog, text="Checking for updates...")\
                .pack(pady=(20, 10))
            progress = ttk.Progressbar(
                self.progress_dialog, mode="indeterminate"
            )
            progress.pack(fill=tk.X, padx=20, pady=10)
            progress.start()

            # Start check in background thread
            threading.Thread(target=self._do_update_check, daemon=True).start()

        except Exception as e:
            self._close_progress_dialog()
            messagebox.showerror(
                "Update Error",
                f"Failed to check for updates:\n\n{e}",
                parent=self.parent
            )

    def _do_update_check(self):
        """Perform the actual update check in a background thread"""
        try:
            with urllib.request.urlopen(self.manifest_url, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))

            latest_version     = data.get('version', '')
            min_required       = data.get('min_required_version', '')
            download_url       = data.get('url', '')
            release_notes      = data.get('release_notes', '')
            release_date       = data.get('release_date', '')

            def to_tuple(v):
                return tuple(int(x) for x in v.split('.'))

            cur_t = to_tuple(self.current_version)
            min_t = to_tuple(min_required) if min_required else cur_t
            lat_t = to_tuple(latest_version) if latest_version else cur_t

            # Forced update if below minimum required version
            if cur_t < min_t:
                def force_update():
                    self._close_progress_dialog()
                    messagebox.showwarning(
                        "Update Required",
                        f"Version {self.current_version} is no longer supported.\n"
                        f"You must install version {min_required} or later.",
                        parent=self.parent
                    )
                    self._start_download(latest_version, download_url)
                self.parent.after(0, force_update)
                return

            # Optional update if a newer version exists
            if lat_t > cur_t and download_url:
                def prompt_update():
                    self._close_progress_dialog()
                    self._show_update_available(
                        latest_version, download_url,
                        release_notes, release_date
                    )
                self.parent.after(0, prompt_update)
            else:
                def no_update():
                    self._close_progress_dialog()
                    messagebox.showinfo(
                        "No Updates Available",
                        f"You are using the latest version ({self.current_version}).",
                        parent=self.parent
                    )
                self.parent.after(0, no_update)

        except Exception as e:
            err = str(e)
            print(f"Update check error: {err}")
            def show_error():
                self._close_progress_dialog()
                messagebox.showerror(
                    "Update Check Failed",
                    f"Failed to check for updates:\n\n{err}",
                    parent=self.parent
                )
            self.parent.after(0, show_error)

    def _close_progress_dialog(self):
        """Close the progress dialog if it exists"""
        if self.progress_dialog:
            try:
                self.progress_dialog.destroy()
            except:
                pass
            self.progress_dialog = None

    def _show_update_available(self, version, url, release_notes, release_date):
        """Show update available dialog with release notes and date"""
        msg = f"A new version ({version}) is available."
        if release_date:
            msg += f"\nReleased on {release_date}."
        if release_notes:
            msg += f"\n\nRelease Notes:\n{release_notes}"
        msg += "\n\nDownload and install now?"

        if messagebox.askyesno("Update Available", msg, parent=self.parent):
            self._start_download(version, url)

    def _start_download(self, version, url):
        """Start downloading the update file"""
        try:
            parsed = urlparse(url)
            filename = os.path.basename(parsed.path) or f"update-{version}.exe"
            downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(downloads, exist_ok=True)
            self.download_path = os.path.join(downloads, filename)

            # Download progress dialog
            self.progress_dialog = tk.Toplevel(self.parent)
            self.progress_dialog.title(f"Downloading v{version}...")
            self.progress_dialog.geometry("400x150")
            self.progress_dialog.transient(self.parent)
            self.progress_dialog.grab_set()
            self.progress_dialog.resizable(False, False)

            sw = self.parent.winfo_screenwidth()
            sh = self.parent.winfo_screenheight()
            x = (sw - 400) // 2
            y = (sh - 150) // 2
            self.progress_dialog.geometry(f"+{x}+{y}")

            ttk.Label(
                self.progress_dialog,
                text=f"Downloading version {version}..."
            ).pack(pady=(15, 5))

            self.progress_var = tk.DoubleVar(value=0)
            progress = ttk.Progressbar(
                self.progress_dialog,
                variable=self.progress_var,
                maximum=100
            )
            progress.pack(fill=tk.X, padx=20, pady=5)

            self.progress_label = ttk.Label(self.progress_dialog, text="")
            self.progress_label.pack(pady=5)

            threading.Thread(
                target=self._do_download, args=(url,), daemon=True
            ).start()

        except Exception as e:
            self._close_progress_dialog()
            messagebox.showerror(
                "Download Error",
                f"Failed to start download:\n\n{e}",
                parent=self.parent
            )

    def _do_download(self, url):
        """Perform the actual download in a background thread"""
        temp_file = None
        err = None
        try:
            fd, temp_file = tempfile.mkstemp(suffix=".part")
            os.close(fd)

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req) as resp, open(temp_file, "wb") as out:
                total = int(resp.headers.get('Content-Length', 0))
                downloaded = 0
                block = 8192

                while True:
                    chunk = resp.read(block)
                    if not chunk:
                        break
                    out.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = min(100, int(downloaded * 100 / total))
                        size_text = self._format_size(downloaded, total)
                        def ui_update(p=pct, s=size_text):
                            if self.progress_dialog:
                                self.progress_var.set(p)
                                self.progress_label.config(
                                    text=f"{p}% - {s}"
                                )
                        self.parent.after(0, ui_update)

            shutil.move(temp_file, self.download_path)
            temp_file = None

            def done():
                self._close_progress_dialog()
                self._show_download_complete()
            self.parent.after(0, done)

        except Exception as e:
            err = str(e)
            print(f"Download error: {err}")
            if temp_file and os.path.exists(temp_file):
                try: os.remove(temp_file)
                except: pass
            def fail_ui():
                self._close_progress_dialog()
                messagebox.showerror(
                    "Download Failed",
                    f"Failed to download update:\n\n{err}",
                    parent=self.parent
                )
            self.parent.after(0, fail_ui)

    def _format_size(self, downloaded, total):
        """Format file size for display"""
        def fmt(n):
            for unit in ("B","KB","MB","GB"):
                if n < 1024:
                    return f"{n:.1f} {unit}"
                n /= 1024
            return f"{n:.1f} TB"
        return f"{fmt(downloaded)} of {fmt(total)}" if total else f"{fmt(downloaded)}"

    def _show_download_complete(self):
        """Show download complete dialog and offer to run the installer"""
        result = messagebox.askyesno(
            "Download Complete",
            f"Update downloaded to:\n{self.download_path}\n\nRun installer now?",
            parent=self.parent
        )
        if result:
            try:
                if sys.platform == 'win32':
                    os.startfile(self.download_path)
                elif sys.platform == 'darwin':
                    os.system(f'open "{self.download_path}"')
                else:
                    os.system(f'xdg-open "{self.download_path}"')
                self.parent.after(500, self.parent.quit)
            except Exception as e:
                messagebox.showerror(
                    "Launch Error",
                    f"Failed to launch the installer:\n\n{e}",
                    parent=self.parent
                )
