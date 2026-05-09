"""
analyzer.py
Core Binary Ninja analysis module.
"""
import logging
import binaryninja as bn
from typing import List, Dict, Any
from threat_intel import ThreatIntelEngine
from errors import BinaryLoadError
from config import API_CATEGORIES, CATEGORY_SCORES, KNOWN_PACKERS, ANTI_DEBUG_APIS, ANTI_VM_STRINGS, MITRE_MAPPING
from utils import filter_iocs, detect_base64, brute_force_xor, calculate_shannon_entropy
from models import AnalysisReport, RiskAssessment, IOCs, Obfuscation, XorHit, SuspiciousImport, SectionInfo, PackerDetection, EvasionInfo, Capability, InterestingFunction, StringReference, ThreatIntelResult

logger = logging.getLogger(__name__)

class MalwareAnalyzer:
    def __init__(self, target_path: str = None, bv: bn.BinaryView = None):
        """Initializes the analyzer. Accepts either a file path (headless) or an open BinaryView (GUI)."""
        self.target_path = target_path or (bv.file.filename if bv else "Unknown")
        self.bv = bv
        self._is_headless = bv is None # Track if we need to close it later

    def __enter__(self):
        # If we were passed an open BinaryView from the GUI, just return self
        if not self._is_headless:
            return self

        # Otherwise, load it headlessly like we used to
        logger.info(f"Loading binary headlessly: {self.target_path}")
        try:
            self.bv = bn.load(self.target_path, update_analysis=True)
        except Exception as e:
            raise BinaryLoadError(f"Binary Ninja exception: {e}")

        if self.bv is None:
            raise BinaryLoadError(f"File not found or format unsupported: {self.target_path}")
            
        self.bv.update_analysis_and_wait() 
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Only close the file if we opened it headlessly. 
        # If the GUI is using it, we don't want to crash the user's session!
        if self._is_headless and self.bv:
            self.bv.file.close()

    def extract_strings(self) -> List[str]:
        """Extracts all strings from the BinaryView."""
        return [s.value for s in self.bv.strings]

    def trace_string_references(self, target_string: str) -> List[StringReference]:
        """Finds cross-references to a specific string."""
        references = []
        for s in self.bv.strings:
            if target_string in s.value:
                code_refs = self.bv.get_code_refs(s.start)
                data_refs = self.bv.get_data_refs(s.start)

                for ref in code_refs:
                    func = ref.function
                    if func:
                        references.append(StringReference(
                            string_value=s.value,
                            string_address=hex(s.start),
                            ref_type="code",
                            ref_address=hex(ref.address),
                            referencing_function=func.name
                        ))

                for ref in data_refs:
                    references.append(StringReference(
                        string_value=s.value,
                        string_address=hex(s.start),
                        ref_type="data",
                        ref_address=hex(ref) # FIX: ref is already an int!
                    ))
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
    
    def rank_suspicious_functions(self) -> List[InterestingFunction]:
        """Analyzes all functions to find decryption routines and malicious behavior."""
        scored_functions = []

        for func in self.bv.functions:
            # Skip library/imported functions; we only care about the malware's own code
            if func.symbol.type.name == 'ImportedFunctionSymbol':
                continue

            score = 0
            reasons = []

            # 1. Check for high complexity (Indicator of Encryption/Decryption algorithms)
            # Malware authors use complex math loops to decrypt payloads
            if len(func.basic_blocks) > 20:
                score += 15
                reasons.append("High Cyclomatic Complexity (Possible crypto/decryption routine)")

            # 2. Check what other functions this function calls
            for callee in func.callees:
                for category, apis in API_CATEGORIES.items():
                    for api in apis:
                        if api.lower() in callee.name.lower():
                            # Award points based on the severity of the API
                            api_score = CATEGORY_SCORES.get(category, 10)
                            score += api_score
                            reasons.append(f"Calls {category} API: {callee.name}")

            # 3. Check for heavy XOR usage in HLIL (High-Level IL)
            # Binary Ninja lifts assembly to C-like code (HLIL). We can scan it easily!
            if func.hlil:
                xor_count = 0
                for instruction in func.hlil.instructions:
                    # Look for XOR operations in the intermediate language
                    if instruction.operation == bn.HighLevelILOperation.HLIL_XOR:
                        xor_count += 1
                
                if xor_count > 5:
                    score += 20
                    reasons.append(f"Heavy XOR usage detected ({xor_count} operations)")

            # If the function hit any of our heuristics, save it
            if score > 0:
                # Deduplicate reasons to keep the report clean
                unique_reasons = list(set(reasons))

                callers = [caller.name for caller in func.callers]
                
                scored_functions.append(InterestingFunction(
                    name=func.name,
                    address=hex(func.start),
                    suspicion_score=score,
                    reasons=unique_reasons,
                    instruction_count=len(list(func.hlil.instructions)) if func.hlil else 0,
                    called_by=callers
                ))

        # Sort the functions by score (highest first)
        scored_functions.sort(key=lambda x: x.suspicion_score, reverse=True)

        # Return only the Top 5 most dangerous functions to avoid overwhelming the analyst
        return scored_functions[:5]

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

        logger.info("Scoring and Ranking Internal Functions...")
        top_functions = self.rank_suspicious_functions()

        # NEW: Trace where our IOCs are used in the assembly!
        logger.info("Tracing IOC Cross-References...")
        ioc_refs = []
        for url in urls:
            ioc_refs.extend(self.trace_string_references(url))
        for ip in ips:
            ioc_refs.extend(self.trace_string_references(ip))

        logger.info("Gathering External Threat Intelligence...")
        ti_engine = ThreatIntelEngine(self.target_path)
        threat_intel = ti_engine.gather_intelligence(ips)

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
            capabilities=capabilities,     # NEW
            top_suspicious_functions=top_functions,  # NEW
            ioc_references=ioc_refs,
            threat_intel=threat_intel
        )