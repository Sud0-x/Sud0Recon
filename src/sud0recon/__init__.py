"""
Sud0Recon - Next-level automated reconnaissance and vulnerability scanning tool

Author: Sud0-x
Contact: sud0x.dev@proton.me
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Sud0-x"
__email__ = "sud0x.dev@proton.me"
__description__ = (
    "Next-level automated reconnaissance & vulnerability scanning tool"
)

from .core.scanner import Scanner
from .core.config import Config

__all__ = ["Scanner", "Config", "__version__"]
