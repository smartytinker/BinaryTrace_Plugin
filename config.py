"""
config.py
Dynamic configuration and regex patterns.
"""
import re
import json
import os
from errors import ConfigurationError

# Static Regex Patterns
URL_PATTERN = re.compile(r"http[s]?://[^\s]+")
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")

XOR_SEARCH_PATTERNS = [
    r"http[s]?://[^\s]+",
    r"[a-zA-Z0-9_-]+\.com",
    r"powershell",
    r"cmd\.exe",
    r"socket"
]

def load_rules(filepath: str = "rules.json") -> dict:
    """Loads external analysis rules and signatures."""
    if not os.path.exists(filepath):
        raise ConfigurationError(f"Missing configuration file: {filepath}")
    
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigurationError(f"Malformed JSON in {filepath}: {e}")

# Load the rules globally so analyzer.py can still import them easily
try:
    _rules = load_rules()
    API_CATEGORIES = _rules.get("api_categories", {})
    CATEGORY_SCORES = _rules.get("category_scores", {})
    KNOWN_PACKERS = _rules.get("known_packers", {})
    ANTI_DEBUG_APIS = _rules.get("anti_debug_apis", [])    # NEW
    ANTI_VM_STRINGS = _rules.get("anti_vm_strings", [])    # NEW
    MITRE_MAPPING = _rules.get("mitre_mapping", {})
except ConfigurationError as e:
    # If config fails to load, we crash early before doing any analysis
    print(f"CRITICAL: {e}")
    exit(1)