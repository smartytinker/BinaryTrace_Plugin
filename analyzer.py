"""
analyzer.py
Core Binary Ninja analysis module.
"""
import logging
import binaryninja as bn
from typing import List, Dict, Any

from errors import BinaryLoadError
from config import API_CATEGORIES, CATEGORY_SCORES, KNOWN_PACKERS, ANTI_DEBUG_APIS, ANTI_VM_STRINGS
from utils import filter_iocs, detect_base64, brute_force_xor, calculate_shannon_entropy
from models import AnalysisReport, RiskAssessment, IOCs, Obfuscation, XorHit, SuspiciousImport, SectionInfo, PackerDetection, EvasionInfo, Capability

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

    def analyze_sections(self) -> List[SectionInfo]:
        """Calculates entropy for all sections in the binary."""
        section_infos = []
        for section_name, section in self.bv.sections.items():
            # Read the raw bytes of the section
            data = self.bv.read(section.start, section.end - section.start)
            entropy = calculate_shannon_entropy(data)
            
            section_infos.append(SectionInfo(
                name=section_name,
                size=len(data),
                entropy=entropy,
                is_highly_entropic=entropy >= 7.0
            ))
        return section_infos

    def detect_packer(self, sections: List[SectionInfo]) -> PackerDetection:
        """Determines if the binary is packed based on section names and entropy."""
        is_packed = False
        suspicious_sections = []
        suspected_packer = "None"

        # Check for highly entropic sections
        for sec in sections:
            if sec.is_highly_entropic:
                is_packed = True
                suspicious_sections.append(sec.name)

        # Check section names against known packer signatures
        for sec in sections:
            for packer_name, signatures in KNOWN_PACKERS.items():
                if sec.name in signatures or sec.name.upper() in signatures:
                    is_packed = True
                    suspected_packer = packer_name
                    if sec.name not in suspicious_sections:
                        suspicious_sections.append(sec.name)

        return PackerDetection(
            is_packed=is_packed,
            suspicious_sections=suspicious_sections,
            suspected_packer=suspected_packer
        )

    def detect_evasion(self, strings: List[str], imports: List[SuspiciousImport]) -> EvasionInfo:
        """Detects signs of Anti-Debugging or Anti-VM techniques."""
        found_debug_apis = []
        found_vm_strings = []

        # Check imports for Anti-Debug APIs
        for symbol in self.bv.get_symbols():
            for api in ANTI_DEBUG_APIS:
                if api.lower() in symbol.name.lower() and api not in found_debug_apis:
                    found_debug_apis.append(api)

        # Check strings for Anti-VM artifacts
        for s in strings:
            for vm_str in ANTI_VM_STRINGS:
                if vm_str.lower() in s.lower() and vm_str not in found_vm_strings:
                    found_vm_strings.append(vm_str)

        return EvasionInfo(
            uses_anti_debug=len(found_debug_apis) > 0,
            anti_debug_apis_found=found_debug_apis,
            uses_anti_vm=len(found_vm_strings) > 0,
            anti_vm_strings_found=found_vm_strings
        )

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

        return RiskAssessment(score=score, reasons=reasons)
    
    def map_capabilities(self, imports: List[SuspiciousImport], evasion: EvasionInfo) -> List[Capability]:
        """Maps findings to MITRE ATT&CK techniques."""
        capabilities = []
        mapping_tracker = {}

        # 1. Map imported APIs to MITRE Categories
        for imp in imports:
            if imp.category in MITRE_MAPPING:
                # Group APIs by category to serve as evidence
                if imp.category not in mapping_tracker:
                    mapping_tracker[imp.category] = []
                mapping_tracker[imp.category].append(imp.api)

        # Build the capability objects for Imports
        for category, apis in mapping_tracker.items():
            mitre_info = MITRE_MAPPING[category]
            capabilities.append(Capability(
                technique_id=mitre_info["id"],
                tactic=mitre_info["tactic"],
                description=mitre_info["description"],
                evidence=apis
            ))

        # 2. Add Evasion capabilities if detected
        if evasion.uses_anti_debug or evasion.uses_anti_vm:
            evidence = evasion.anti_debug_apis_found + evasion.anti_vm_strings_found
            capabilities.append(Capability(
                technique_id="T1497",
                tactic="Defense Evasion",
                description="Virtualization/Sandbox Evasion",
                evidence=evidence
            ))

        return capabilities

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
                for hit in hits:
                    xor_results.append(XorHit(key=hit["key"], decoded=hit["decoded"]))

        logger.info("Analyzing Imports...")
        suspicious_imports = self.analyze_imports()

        logger.info("Analyzing Sections & Entropy...")
        sections = self.analyze_sections()
        packer_info = self.detect_packer(sections)

        logger.info("Checking for Evasion Techniques...")
        evasion = self.detect_evasion(strings, suspicious_imports)

        logger.info("Calculating Risk Score...")
        risk = self.calculate_risk_score(urls, xor_results, suspicious_imports)
        
        # Penalize for packing
        if packer_info.is_packed:
            risk.score += 40
            risk.reasons.append(f"Binary is likely packed (Suspected: {packer_info.suspected_packer})")
            
        # Penalize for evasion
        if evasion.uses_anti_debug or evasion.uses_anti_vm:
            risk.score += 25
            risk.reasons.append("Anti-Analysis/Evasion techniques detected")

        # Cap score at 100
        risk.score = min(risk.score, 100)

        logger.info("Mapping MITRE ATT&CK Capabilities...")
        capabilities = self.map_capabilities(suspicious_imports, evasion)

        return AnalysisReport(
            file=self.target_path,
            risk_assessment=risk,
            iocs=IOCs(urls=urls, ips=ips),
            obfuscation=Obfuscation(
                base64_candidates_count=len(b64_candidates),
                xor_decoded=xor_results
            ),
            suspicious_imports=suspicious_imports,
            sections=sections,
            packer_info=packer_info,
            evasion_info=evasion,
            capabilities=capabilities     # NEW
        )