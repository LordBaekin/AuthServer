# gui/database_tab.py - Database management tab implementation
import tkinter as tk
from tkinter import ttk, messagebox
import os
import platform
import logging
from datetime import datetime
import threading
import time

from .base import BaseTab
from config import config, BACKUP_DIR
from db import db_execute, backup_database, get_connection_pool_stats

class DatabaseTab(BaseTab):
    def __init__(self, parent, app_controller):
        self.db_type_info_var = None
        self.db_path_var = None
        self.db_size_var = None
        self.db_users_var = None
        self.last_backup_var = None
        self.backup_loc_var = None
        self.backup_count_var = None
        self.tables_tree = None
        self.update_timer = None
        super().__init__(parent, app_controller)
        
    def setup_ui(self):
        """Set up the database tab UI."""
        # Header
        db_label = ttk.Label(self, text="Database Management", style='Header.TLabel')
        db_label.grid(column=0, row=0, columnspan=2, pady=(0, 10), sticky='w')
        
        # Database info frame
        db_info_frame = ttk.LabelFrame(self, text="Database Information")
        db_info_frame.grid(column=0, row=1, sticky='ew', padx=5, pady=5, columnspan=2)
        
        ttk.Label(db_info_frame, text="Database Type:").grid(column=0, row=0, sticky='e', padx=(10, 5), pady=5)
        self.db_type_info_var = tk.StringVar(value=self.app_controller.config.get("DB_TYPE", "sqlite"))
        ttk.Label(db_info_frame, textvariable=self.db_type_info_var).grid(column=1, row=0, sticky='w', pady=5)
        
        ttk.Label(db_info_frame, text="Database Path:").grid(column=0, row=1, sticky='e', padx=(10, 5), pady=5)
        self.db_path_var = tk.StringVar(value=self._get_db_path_display())
        ttk.Label(db_info_frame, textvariable=self.db_path_var).grid(column=1, row=1, sticky='w', pady=5)
        
        ttk.Label(db_info_frame, text="Size:").grid(column=0, row=2, sticky='e', padx=(10, 5), pady=5)
        self.db_size_var = tk.StringVar(value="Unknown")
        ttk.Label(db_info_frame, textvariable=self.db_size_var).grid(column=1, row=2, sticky='w', pady=5)
        
        ttk.Label(db_info_frame, text="Users:").grid(column=0, row=3, sticky='e', padx=(10, 5), pady=5)
        self.db_users_var = tk.StringVar(value="0")
        ttk.Label(db_info_frame, textvariable=self.db_users_var).grid(column=1, row=3, sticky='w', pady=5)
        
        ttk.Label(db_info_frame, text="Last Backup:").grid(column=2, row=0, sticky='e', padx=(20, 5), pady=5)
        self.last_backup_var = tk.StringVar(value="Never")
        ttk.Label(db_info_frame, textvariable=self.last_backup_var).grid(column=3, row=0, sticky='w', pady=5)
        
        ttk.Label(db_info_frame, text="Backup Location:").grid(column=2, row=1, sticky='e', padx=(20, 5), pady=5)
        self.backup_loc_var = tk.StringVar(value=BACKUP_DIR)
        ttk.Label(db_info_frame, textvariable=self.backup_loc_var).grid(column=3, row=1, sticky='w', pady=5)
        
        ttk.Label(db_info_frame, text="Backups:").grid(column=2, row=2, sticky='e', padx=(20, 5), pady=5)
        self.backup_count_var = tk.StringVar(value="0")
        ttk.Label(db_info_frame, textvariable=self.backup_count_var).grid(column=3, row=2, sticky='w', pady=5)
        
        # Backup controls
        backup_frame = ttk.LabelFrame(self, text="Backup Management")
        backup_frame.grid(column=0, row=2, sticky='ew', padx=5, pady=10, columnspan=2)
        
        ttk.Button(backup_frame, text="Backup Now", command=self.backup_now).grid(
            column=0, row=0, padx=5, pady=5
        )
        
        ttk.Button(backup_frame, text="View Backups", command=self.view_backups).grid(
            column=1, row=0, padx=5, pady=5
        )
        
        # Database tables
        tables_frame = ttk.LabelFrame(self, text="Database Tables")
        tables_frame.grid(column=0, row=3, sticky='nsew', padx=5, pady=5, columnspan=2)
        self.rowconfigure(3, weight=1)
        
        # Table list
        self.tables_tree = ttk.Treeview(tables_frame, columns=('rows',), show='headings', height=10)
        self.tables_tree.heading('rows', text='Rows')
        self.tables_tree.column('rows', width=100, anchor='center')
        
        self.tables_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for table list
        tables_scroll = ttk.Scrollbar(tables_frame, orient="vertical", command=self.tables_tree.yview)
        tables_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tables_tree.configure(yscrollcommand=tables_scroll.set)
        
        # Refresh button for tables
        ttk.Button(tables_frame, text="Refresh", command=self.update_table_list).pack(side=tk.BOTTOM, pady=5)
        
        # Add connection pool management frame
        db_diag_frame = ttk.LabelFrame(self, text="Connection Pool Management")
        db_diag_frame.grid(column=0, row=4, sticky='ew', padx=5, pady=10, columnspan=2)

        # Add diagnostic buttons
        ttk.Button(db_diag_frame, text="Check Connection Pool", 
                 command=self.check_db_pool_status).grid(
            column=0, row=0, padx=5, pady=5
        )

        ttk.Button(db_diag_frame, text="Force Connection Cleanup", 
                 command=self.force_db_connection_cleanup).grid(
            column=1, row=0, padx=5, pady=5
        )

        ttk.Button(db_diag_frame, text="Reset Connection Pool", 
                 command=self.reset_db_connection_pool).grid(
            column=2, row=0, padx=5, pady=5
        )
        
        # Initialize database info and table list
        self.update_db_info()
        self.update_table_list()
        
    def _get_db_path_display(self):
        """Get database path display string based on type."""
        if self.app_controller.config.get("DB_TYPE", "sqlite") == "sqlite":
            return self.app_controller.config.get("DB_PATH", "auth.db")
        else:
            return (f"{self.app_controller.config.get('DB_HOST', 'localhost')}:"
                   f"{self.app_controller.config.get('DB_PORT', 3306)}/"
                   f"{self.app_controller.config.get('DB_NAME', 'vespeyr_auth')}")
        
    def update_db_info(self):
        """Update database information."""
        try:
            # Update database type and path display
            self.db_type_info_var.set(self.app_controller.config.get("DB_TYPE", "sqlite"))
            self.db_path_var.set(self._get_db_path_display())
            
            if self.app_controller.config.get("DB_TYPE", "sqlite") == "sqlite":
                # Get database size
                if os.path.exists(self.app_controller.config.get("DB_PATH", "auth.db")):
                    size_bytes = os.path.getsize(self.app_controller.config.get("DB_PATH", "auth.db"))
                    if size_bytes < 1024:
                        size_str = f"{size_bytes} bytes"
                    elif size_bytes < 1024 * 1024:
                        size_str = f"{size_bytes/1024:.2f} KB"
                    else:
                        size_str = f"{size_bytes/(1024*1024):.2f} MB"
                    self.db_size_var.set(size_str)
                else:
                    self.db_size_var.set("Not found")
            else:
                # For MySQL, show connection details
                self.db_size_var.set("N/A (MySQL)")
            
            # Get user count
            try:
                users = db_execute('SELECT COUNT(*) as count FROM users', fetchone=True)
                if users:
                    self.db_users_var.set(str(users['count']))
            except:
                self.db_users_var.set("Error")
            
            # Get backup info
            if os.path.exists(BACKUP_DIR):
                # Determine file extension based on DB type
                ext = ".sql" if self.app_controller.config.get("DB_TYPE", "sqlite") == "mysql" else ".db"
                
                backup_files = [f for f in os.listdir(BACKUP_DIR) 
                              if f.startswith("auth_db_backup_") and f.endswith(ext)]
                self.backup_count_var.set(str(len(backup_files)))
                
                if backup_files:
                    # Sort by modification time (newest first)
                    backup_files.sort(
                        key=lambda x: os.path.getmtime(os.path.join(BACKUP_DIR, x)), 
                        reverse=True
                    )
                    latest_backup = backup_files[0]
                    backup_time = os.path.getmtime(os.path.join(BACKUP_DIR, latest_backup))
                    self.last_backup_var.set(datetime.fromtimestamp(backup_time).strftime("%Y-%m-%d %H:%M:%S"))
            
        except Exception as e:
            logging.error(f"Error updating database info: {str(e)}")
    
    def update_table_list(self):
        """Update the table list."""
        try:
            # Clear existing items
            for item in self.tables_tree.get_children():
                self.tables_tree.delete(item)
        
            # Get table list and row counts
            if self.app_controller.config.get("DB_TYPE", "sqlite") == "mysql":
                # For MySQL databases
                try:
                    import pymysql
                
                    # Connect to MySQL
                    conn = pymysql.connect(
                        host=self.app_controller.config.get("DB_HOST", "localhost"),
                        port=int(self.app_controller.config.get("DB_PORT", 3306)),
                        user=self.app_controller.config.get("DB_USER", ""),
                        password=self.app_controller.config.get("DB_PASSWORD", ""),
                        database=self.app_controller.config.get("DB_NAME", "vespeyr_auth")
                    )
                
                    cursor = conn.cursor(pymysql.cursors.DictCursor)
                
                    # Get table list
                    cursor.execute("SHOW TABLES")
                    tables = cursor.fetchall()
                
                    for table in tables:
                        table_name = list(table.values())[0]  # Get first value in the dictionary
                    
                        # Get row count
                        try:
                            cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
                            row_count = cursor.fetchone()
                            count = row_count['count'] if row_count else 0
                        except:
                            count = "Error"
                    
                        self.tables_tree.insert('', tk.END, text=table_name, values=(count,), iid=table_name)
                    
                    cursor.close()
                    conn.close()
                
                except ImportError:
                    self.tables_tree.insert('', tk.END, text="PyMySQL not installed", 
                                          values=("N/A",), iid="error")
                    self.tables_tree.insert('', tk.END, text="Install with: pip install pymysql", 
                                          values=("N/A",), iid="hint")
                except Exception as e:
                    self.tables_tree.insert('', tk.END, text=f"MySQL Error: {str(e)}", 
                                          values=("N/A",), iid="error")
            else:
                # For SQLite databases
                try:
                    tables = db_execute(
                        "SELECT name FROM sqlite_master WHERE type='table'",
                        fetchall=True
                    )
                
                    for table in tables:
                        table_name = table['name']
                        # Get row count
                        try:
                            row_count = db_execute(
                                f"SELECT COUNT(*) as count FROM {table_name}",
                                fetchone=True
                            )
                            count = row_count['count'] if row_count else 0
                        except:
                            count = "Error"
                    
                        self.tables_tree.insert('', tk.END, text=table_name, values=(count,), iid=table_name)
                except Exception as e:
                    self.tables_tree.insert('', tk.END, text=f"SQLite Error: {str(e)}", 
                                          values=("N/A",), iid="error")
            
        except Exception as e:
            logging.error(f"Error updating table list: {str(e)}")
            self.tables_tree.insert('', tk.END, text=f"Error: {str(e)}", values=("N/A",), iid="error")
    
    def backup_now(self):
        """Trigger manual database backup."""
        try:
            if backup_database():
                messagebox.showinfo("Success", "Database backup created successfully")
                self.update_db_info()  # Update info immediately
            else:
                messagebox.showerror("Error", "Failed to create database backup")
        except Exception as e:
            messagebox.showerror("Error", f"Backup error: {str(e)}")
    
    def view_backups(self):
        """Open backup directory in file explorer."""
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
            
        if platform.system() == "Windows":
            os.startfile(os.path.abspath(BACKUP_DIR))
        elif platform.system() == "Darwin":  # macOS
            os.system(f"open {os.path.abspath(BACKUP_DIR)}")
        else:  # Linux
            os.system(f"xdg-open {os.path.abspath(BACKUP_DIR)}")
    
    def check_db_pool_status(self):
        """Check status of database connection pool and display diagnostic information."""
        try:
            # Import needed modules
            from db import _sqlite_pool, _mysql_pool
            
            # For SQLite
            if self.app_controller.config.get("DB_TYPE", "sqlite") == "sqlite" and _sqlite_pool:
                with _sqlite_pool.lock:
                    total = len(_sqlite_pool.connections)
                    in_use = len(_sqlite_pool.in_use)
                    max_conns = _sqlite_pool.max_connections
                    
                    # Access connection metadata from the pool
                    _connection_metadata = getattr(_sqlite_pool, '_connection_metadata', {})
                    
                    # Calculate ages
                    now = time.time()
                    ages = []
                    for conn in _sqlite_pool.connections:
                        conn_id = id(conn)
                        if conn_id in _connection_metadata:
                            ages.append(now - _connection_metadata[conn_id]['created_time'])
                    
                    avg_age = sum(ages) / len(ages) if ages else 0
                    
                    message = (f"SQLite Connection Pool Status:\n\n"
                              f"Total connections: {total}/{max_conns}\n"
                              f"In use: {in_use}\n"
                              f"Idle: {total - in_use}\n"
                              f"Average connection age: {avg_age:.1f}s\n\n")
                    
                    # Add detailed connection info
                    message += "Connection Details:\n"
                    for i, conn in enumerate(_sqlite_pool.connections):
                        conn_id = id(conn)
                        if conn_id in _connection_metadata:
                            age = now - _connection_metadata[conn_id]['created_time']
                        else:
                            age = 0
                        status = "IN USE" if conn in _sqlite_pool.in_use else "idle"
                        message += f"Conn #{i+1}: {status}, Age: {age:.1f}s\n"
                
                messagebox.showinfo("Connection Pool Status", message)
                
                # Warn if running low on connections
                if in_use >= max_conns * 0.8:
                    messagebox.showwarning(
                        "Connection Pool Warning", 
                        f"Connection pool is at {in_use}/{max_conns} capacity.\n"
                        f"Consider increasing DB_POOL_SIZE in config.json or check for connection leaks."
                    )
                    
            # For MySQL
            elif self.app_controller.config.get("DB_TYPE", "sqlite") == "mysql" and _mysql_pool:
                with _mysql_pool.lock:
                    total = len(_mysql_pool.connections)
                    in_use = len(_mysql_pool.in_use)
                    max_conns = _mysql_pool.max_connections
                
                message = (f"MySQL Connection Pool Status:\n\n"
                          f"Total connections: {total}/{max_conns}\n"
                          f"In use: {in_use}\n"
                          f"Idle: {total - in_use}")
                          
                messagebox.showinfo("Connection Pool Status", message)
                
                # Warn if running low on connections
                if in_use >= max_conns * 0.8:
                    messagebox.showwarning(
                        "Connection Pool Warning", 
                        f"Connection pool is at {in_use}/{max_conns} capacity.\n"
                        f"Consider increasing DB_POOL_SIZE in config.json or check for connection leaks."
                    )
            else:
                messagebox.showinfo("Connection Pool Status", "No active database connection pool found.")
        except Exception as e:
            logging.error(f"Failed to check pool status: {str(e)}")
            messagebox.showerror("Error", f"Failed to check connection pool status: {str(e)}")

    def force_db_connection_cleanup(self):
        """Force cleanup of all idle database connections."""
        try:
            # Import needed modules
            from db import _sqlite_pool
            
            # For SQLite
            if self.app_controller.config.get("DB_TYPE", "sqlite") == "sqlite" and _sqlite_pool:
                # Get stats before cleanup
                with _sqlite_pool.lock:
                    before_total = len(_sqlite_pool.connections)
                    before_in_use = len(_sqlite_pool.in_use)
                    
                # Force cleanup
                _sqlite_pool._cleanup_old_connections()
                
                # Get stats after cleanup
                with _sqlite_pool.lock:
                    after_total = len(_sqlite_pool.connections)
                    after_in_use = len(_sqlite_pool.in_use)
                    
                # Calculate differences
                closed = before_total - after_total
                
                message = (f"Connection Cleanup Results:\n\n"
                          f"Connections before: {before_total} (in use: {before_in_use})\n"
                          f"Connections after: {after_total} (in use: {after_in_use})\n"
                          f"Connections closed: {closed}")
                          
                messagebox.showinfo("Connection Cleanup", message)
                
                # Log the action
                logging.info(f"Manual connection cleanup: {closed} connections closed")
            else:
                messagebox.showinfo("Connection Cleanup", 
                                  "No active SQLite connection pool found or using MySQL.")
        except Exception as e:
            logging.error(f"Failed to cleanup connections: {str(e)}")
            messagebox.showerror("Error", f"Failed to cleanup connections: {str(e)}")

    def reset_db_connection_pool(self):
        """Reset the database connection pool completely."""
        if messagebox.askyesno(
            "Reset Connection Pool", 
            "Are you sure you want to reset the connection pool?\n"
            "This will close all existing database connections."
        ):
            try:
                # Import reset function
                from db import reset_connection_pool
                
                # Reset the pool
                reset_connection_pool()
                
                messagebox.showinfo("Success", "Database connection pool has been reset.")
                logging.info("Manual connection pool reset performed")
            except Exception as e:
                logging.error(f"Failed to reset connection pool: {str(e)}")
                messagebox.showerror("Error", f"Failed to reset connection pool: {str(e)}")
                
    def on_tab_selected(self):
        """Called when this tab is selected."""
        # Update database info
        self.update_db_info()
        self.update_table_list()
        
        # Schedule periodic updates
        self.update_timer = self.after(30000, self.update_db_info)
        
    def on_tab_deselected(self):
        """Called when user navigates away from this tab."""
        # Cancel any pending timer
        if self.update_timer:
            self.after_cancel(self.update_timer)
            self.update_timer = None
            
    def on_config_updated(self, config):
        """Called when configuration is updated."""
        # Update database info
        self.update_db_info()
        self.update_table_list()

