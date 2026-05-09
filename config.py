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
    # Force Python to look in the exact directory where config.py lives
    current_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(current_dir, filepath)

    if not os.path.exists(full_path):
        raise ConfigurationError(f"Missing configuration file: {full_path}")
    
    try:
        with open(full_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ConfigurationError(f"Malformed JSON in {full_path}: {e}")

# Load the rules globally so analyzer.py can still import them easily
try:
    _rules = load_rules()
    API_CATEGORIES = _rules.get("api_categories", {})
    CATEGORY_SCORES = _rules.get("category_scores", {})
    KNOWN_PACKERS = _rules.get("known_packers", {})
    ANTI_DEBUG_APIS = _rules.get("anti_debug_apis", [])
    ANTI_VM_STRINGS = _rules.get("anti_vm_strings", [])
    MITRE_MAPPING = _rules.get("mitre_mapping", {})
    THREAT_INTEL_CONFIG = _rules.get("threat_intel", {})
except ConfigurationError as e:
    # Safely abort without crashing Binary Ninja
    raise RuntimeError(f"CRITICAL CONFIG ERROR: {e}")