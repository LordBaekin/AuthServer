# gui/__init__.py - GUI package initialization
# Create task_manager first without any imports
from .scheduled_tasks import ScheduledTasksManager
task_manager = ScheduledTasksManager()

# Import create_gui function but don't expose it yet
from .main import create_gui

# Export both symbols
__all__ = ['create_gui', 'task_manager']