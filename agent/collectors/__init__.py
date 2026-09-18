"""
ForensiTrace Agent Collectors.
Provides modules for monitoring endpoint telemetry:
- File System Events (watchdog)
- USB / Removable Storage Events (WMI / pywin32 - upcoming)
- Windows Event Logs (pywin32 / python-evtx - upcoming)
"""

from .file_system import FileSystemCollector

__all__ = ["FileSystemCollector"]
