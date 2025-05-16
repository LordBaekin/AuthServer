# gui.py - GUI interface for the authentication server
# This file maintains compatibility with server.py by providing the same API
# while delegating to the new modular implementation

# Import create_gui function
from gui.main import create_gui, get_task_manager

# Create task manager instance once
task_manager = get_task_manager()

# Export both create_gui and task_manager to maintain compatibility with server.py
__all__ = ['create_gui', 'task_manager']

# If this module is run directly (which shouldn't normally happen), create and run the GUI
if __name__ == "__main__":
    root = create_gui()
    root.mainloop()