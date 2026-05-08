"""
utils.py
Helper functions for cryptography, decoding, and IOC extraction.
"""
import base64
import logging
from typing import List, Tuple, Dict, Any, Optional
from config import URL_PATTERN, IP_PATTERN, BASE64_PATTERN, XOR_SEARCH_PATTERNS
import re
import math
from collections import Counter

logger = logging.getLogger(__name__)

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte array."""
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    occurrences = Counter(data)

    for count in occurrences.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 2)

def filter_iocs(strings: List[str]) -> Tuple[List[str], List[str]]:
    """Extracts URLs and IPs from a list of strings."""
    urls, ips = [], []
    for s in strings:
        if URL_PATTERN.search(s):
            urls.append(s)
        elif IP_PATTERN.search(s):
            ips.append(s)
    return urls, ips

def detect_base64(strings: List[str], min_length: int = 20) -> List[str]:
    """Finds potential base64 strings."""
    return [s for s in strings if len(s) > min_length and BASE64_PATTERN.match(s)]

def try_base64_decode(data: str) -> Optional[str]:
    """Attempts to decode a base64 string safely."""
    try:
        return base64.b64decode(data).decode("utf-8")
    except Exception:
        return None

def xor_decode(data: bytes, key: int) -> bytes:
    """Applies single-byte XOR against a byte sequence."""
    return bytes([b ^ key for b in data])

def brute_force_xor(encoded_string: str) -> List[Dict[str, str]]:
    """Brute forces 256 single-byte XOR keys looking for known malware patterns."""
    results = []
    try:
        raw = encoded_string.encode("latin-1")
    except UnicodeEncodeError:
        return results

    if len(raw) < 6:
        return results

    for key in range(256):
        decoded = xor_decode(raw, key)
        try:
            decoded_text = decoded.decode("utf-8")
            
            # Check for printable characters mostly
            if not all(32 <= ord(c) < 127 or c in '\r\n\t' for c in decoded_text):
                continue

            for pattern in XOR_SEARCH_PATTERNS:
                if re.search(pattern, decoded_text.lower()):
                    results.append({
                        "key": hex(key),
                        "decoded": decoded_text
                    })
                    break
        except UnicodeDecodeError:
            continue

    return results