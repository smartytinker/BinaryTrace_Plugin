"""
analyzer.py
Core Binary Ninja analysis module.
"""
import logging
import binaryninja as bn
from typing import List, Dict, Any
from config import API_CATEGORIES, CATEGORY_SCORES
from utils import filter_iocs, detect_base64, brute_force_xor
from models import AnalysisReport, RiskAssessment, IOCs, Obfuscation, XorHit, SuspiciousImport
from errors import BinaryLoadError

logger = logging.getLogger(__name__)

class MalwareAnalyzer:
    def __init__(self, target_path: str):
        self.target_path = target_path
        self.bv = None

    def __enter__(self):
        logger.info(f"Loading binary into Binary Ninja: {self.target_path}")
        try:
            self.bv = bn.load(self.target_path, update_analysis=True)
        except Exception as e:
            raise BinaryLoadError(f"Binary Ninja exception: {e}")

        if self.bv is None:
            raise BinaryLoadError(f"File not found or format unsupported: {self.target_path}")
            
        self.bv.update_analysis_and_wait() 
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.bv:
            self.bv.file.close()

    def extract_strings(self) -> List[str]:
        """Extracts all strings from the BinaryView."""
        return [s.value for s in self.bv.strings]

    def trace_string_references(self, target_string: str) -> List[Dict[str, str]]:
        """Finds cross-references to a specific string."""
        references = []
        for s in self.bv.strings:
            if target_string in s.value:
                code_refs = self.bv.get_code_refs(s.start)
                data_refs = self.bv.get_data_refs(s.start)

                for ref in code_refs:
                    func = ref.function
                    if func:
                        references.append({
                            "type": "code",
                            "string": s.value,
                            "address": hex(s.start),
                            "function": func.name,
                            "ref_address": hex(ref.address)
                        })

                for ref in data_refs:
                    references.append({
                        "type": "data",
                        "string": s.value,
                        "address": hex(s.start),
                        "ref_address": hex(ref.address)
                    })
        return references

    def analyze_imports(self) -> List[SuspiciousImport]:
        """Maps binary imports to suspicious API categories using typed models."""
        suspicious_imports = []
        seen = set()

        for symbol in self.bv.get_symbols():
            name = symbol.name
            if "__" in name or name in seen:
                continue

            seen.add(name)

            for category, apis in API_CATEGORIES.items():
                for api in apis:
                    if api.lower() in name.lower():
                        suspicious_imports.append(SuspiciousImport(
                            category=category,
                            api=name,
                            address=hex(symbol.address)
                        ))
        return suspicious_imports

    def calculate_risk_score(self, urls: List[str], xor_hits: List[XorHit], imports: List[SuspiciousImport]) -> RiskAssessment:
        """Calculates a risk score out of 100 based on found artifacts."""
        score = 0
        reasons = []

        if urls:
            score += 10
            reasons.append("Suspicious URLs detected")

        if xor_hits:
            score += 15
            reasons.append("Possible XOR-obfuscated strings")

        seen_categories = set()
        for imp in imports:
            category = imp.category
            if category not in seen_categories:
                seen_categories.add(category)
                score += CATEGORY_SCORES.get(category, 0)
                reasons.append(f"{category} APIs detected")

        return RiskAssessment(score=min(score, 100), reasons=reasons)

    def run_full_analysis(self) -> AnalysisReport:
        """Orchestrates the full analysis pipeline."""
        logger.info("Extracting strings...")
        strings = self.extract_strings()
        
        logger.info("Extracting IOCs...")
        urls, ips = filter_iocs(strings)
        
        logger.info("Detecting Base64...")
        b64_candidates = detect_base64(strings)
        
        logger.info("Checking for XOR'd strings...")
        xor_results = []
        for s in strings:
            hits = brute_force_xor(s)
            if hits:
                # Convert raw dicts from utils into typed XorHit objects
                for hit in hits:
                    xor_results.append(XorHit(key=hit["key"], decoded=hit["decoded"]))

        logger.info("Analyzing Imports...")
        suspicious_imports = self.analyze_imports()

        logger.info("Calculating Risk Score...")
        risk = self.calculate_risk_score(urls, xor_results, suspicious_imports)

        return AnalysisReport(
            file=self.target_path,
            risk_assessment=risk,
            iocs=IOCs(urls=urls, ips=ips),
            obfuscation=Obfuscation(
                base64_candidates_count=len(b64_candidates),
                xor_decoded=xor_results
            ),
            suspicious_imports=suspicious_imports
        )