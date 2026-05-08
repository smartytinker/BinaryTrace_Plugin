"""
config.py
Static configurations, regex patterns, and API classifications.
"""
import re

# Regex Patterns
URL_PATTERN = re.compile(r"http[s]?://[^\s]+")
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/=]+$")

# Patterns to look for in decoded XOR strings
XOR_SEARCH_PATTERNS = [
    r"http[s]?://[^\s]+",
    r"[a-zA-Z0-9_-]+\.com",
    r"powershell",
    r"cmd\.exe",
    r"socket"
]

# Suspicious Windows APIs categorized by capability
API_CATEGORIES = {
    "Keylogging": ["GetAsyncKeyState", "SetWindowsHookEx"],
    "Process Injection": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"],
    "Networking": ["InternetOpen", "InternetOpenUrl", "URLDownloadToFile", "socket", "connect"],
    "Persistence": ["RegSetValueEx", "CreateService"],
    "Command Execution": ["WinExec", "ShellExecute", "CreateProcess"],
    "Cryptography": ["CryptAcquireContext", "CryptEncrypt", "CryptDecrypt"]
}

# Risk scoring weights
CATEGORY_SCORES = {
    "Networking": 10,
    "Command Execution": 25,
    "Process Injection": 30,
    "Persistence": 20,
    "Keylogging": 35,
    "Cryptography": 15
}