"""
threat_intel.py
Handles external integrations (VirusTotal, AbuseIPDB) and local YARA scanning.
"""
import hashlib
import os
import logging
import requests
import yara
from typing import List, Dict
from config import THREAT_INTEL_CONFIG
from models import ThreatIntelResult, YaraMatch

logger = logging.getLogger(__name__)

class ThreatIntelEngine:
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.vt_key = THREAT_INTEL_CONFIG.get("vt_api_key", "")
        self.ipdb_key = THREAT_INTEL_CONFIG.get("abuseipdb_api_key", "")
        self.yara_dir = THREAT_INTEL_CONFIG.get("yara_rules_dir", "./yara_rules")

    def get_file_hash(self) -> str:
        """Calculates the SHA256 hash of the target file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(self.target_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash file: {e}")
            return "UNKNOWN"

    def check_virustotal(self, file_hash: str) -> tuple:
        """Queries VirusTotal for the file hash."""
        if not self.vt_key:
            return 0, 0 # Skip if no key

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.vt_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                return malicious, total
            elif response.status_code == 404:
                return 0, 0 # File not found on VT
            else:
                logger.warning(f"VT API Error: {response.status_code}")
        except Exception as e:
            logger.error(f"VT Request failed: {e}")
        
        return 0, 0

    def check_abuseipdb(self, ips: List[str]) -> Dict[str, int]:
        """Queries AbuseIPDB to see if extracted IPs are malicious."""
        malicious_ips = {}
        if not self.ipdb_key:
            return malicious_ips

        headers = {
            "Accept": "application/json",
            "Key": self.ipdb_key
        }

        for ip in ips:
            url = f"https://api.abuseipdb.com/api/v2/check"
            querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
            
            try:
                response = requests.get(url, headers=headers, params=querystring, timeout=10)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    if score > 10: # Only flag if confidence is > 10%
                        malicious_ips[ip] = score
            except Exception as e:
                logger.error(f"AbuseIPDB Request failed for {ip}: {e}")

        return malicious_ips

    def run_yara_scans(self) -> List[YaraMatch]:
        """Compiles and runs local YARA rules against the binary."""
        matches = []
        if not os.path.exists(self.yara_dir):
            os.makedirs(self.yara_dir) # Create the folder if it doesn't exist
            return matches

        rule_files = {}
        for filename in os.listdir(self.yara_dir):
            if filename.endswith(".yar") or filename.endswith(".yara"):
                rule_files[filename] = os.path.join(self.yara_dir, filename)

        if not rule_files:
            return matches

        try:
            compiled_rules = yara.compile(filepaths=rule_files)
            yara_results = compiled_rules.match(self.target_path)
            
            for match in yara_results:
                matches.append(YaraMatch(
                    rule_name=match.rule,
                    description=match.meta.get("description", "No description provided")
                ))
        except Exception as e:
            logger.error(f"YARA compilation/scanning failed: {e}")

        return matches

    def gather_intelligence(self, ips: List[str]) -> ThreatIntelResult:
        """Runs all Threat Intel modules."""
        logger.info("Hashing file...")
        file_hash = self.get_file_hash()
        
        logger.info(f"Checking VirusTotal for {file_hash}...")
        vt_positives, vt_total = self.check_virustotal(file_hash)
        
        logger.info("Checking AbuseIPDB for extracted IPs...")
        bad_ips = self.check_abuseipdb(ips)
        
        logger.info("Running local YARA scans...")
        yara_matches = self.run_yara_scans()

        return ThreatIntelResult(
            file_hash=file_hash,
            vt_positives=vt_positives,
            vt_total=vt_total,
            malicious_ips=bad_ips,
            yara_matches=yara_matches
        )