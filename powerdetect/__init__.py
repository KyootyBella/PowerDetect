"""PowerDetect - deterministic static triage of PowerShell command lines."""
from .engine import Report, Rules, analyze

__all__ = ["analyze", "Rules", "Report"]
__version__ = "0.1.0"
