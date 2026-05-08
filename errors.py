"""
errors.py
Custom exceptions for the malware analysis pipeline.
"""

class AnalyzerBaseError(Exception):
    """Base exception for all custom analyzer errors."""
    pass

class BinaryLoadError(AnalyzerBaseError):
    """Raised when Binary Ninja fails to load the executable or file is missing."""
    pass

class ConfigurationError(AnalyzerBaseError):
    """Raised when the external configuration file is missing or malformed."""
    pass