"""
models.py
Dataclasses representing the strictly typed schema for analysis results.
"""
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class IOCs:
    urls: List[str]
    ips: List[str]

@dataclass
class XorHit:
    key: str
    decoded: str

@dataclass
class Obfuscation:
    base64_candidates_count: int
    xor_decoded: List[XorHit]

@dataclass
class RiskAssessment:
    score: int
    reasons: List[str]

@dataclass
class SuspiciousImport:
    category: str
    api: str
    address: str

@dataclass
class EvasionInfo:
    uses_anti_debug: bool
    anti_debug_apis_found: List[str]
    uses_anti_vm: bool
    anti_vm_strings_found: List[str]

@dataclass
class Capability:
    technique_id: str
    tactic: str
    description: str
    evidence: List[str]

@dataclass
class StringReference:
    string_value: str
    string_address: str
    ref_type: str
    ref_address: str
    referencing_function: str = "Unknown"

@dataclass
class InterestingFunction:
    name: str
    address: str
    suspicion_score: int
    reasons: List[str]
    instruction_count: int
    called_by: List[str]

@dataclass
class YaraMatch:
    rule_name: str
    description: str

@dataclass
class ThreatIntelResult:
    file_hash: str
    vt_positives: int
    vt_total: int
    malicious_ips: Dict[str, int]
    yara_matches: List[YaraMatch]

# Moved these two up!
@dataclass
class SectionInfo:
    name: str
    size: int
    entropy: float
    is_highly_entropic: bool

@dataclass
class PackerDetection:
    is_packed: bool
    suspicious_sections: List[str]
    suspected_packer: str

# AnalysisReport goes last so it can see everything defined above it
@dataclass
class AnalysisReport:
    file: str
    risk_assessment: RiskAssessment
    iocs: IOCs
    obfuscation: Obfuscation
    suspicious_imports: List[SuspiciousImport]
    sections: List[SectionInfo] 
    packer_info: PackerDetection
    evasion_info: EvasionInfo
    capabilities: List[Capability]
    top_suspicious_functions: List[InterestingFunction]
    ioc_references: List[StringReference]
    threat_intel: ThreatIntelResult

    def to_dict(self) -> dict:
        """Converts the dataclass hierarchy into a JSON-serializable dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict):
        """Reconstructs the AnalysisReport object from a database JSON dictionary."""
        return cls(
            file=data.get("file", "Unknown"),
            risk_assessment=RiskAssessment(**data.get("risk_assessment", {})),
            iocs=IOCs(**data.get("iocs", {})),
            obfuscation=Obfuscation(
                base64_candidates_count=data.get("obfuscation", {}).get("base64_candidates_count", 0),
                xor_decoded=[XorHit(**x) for x in data.get("obfuscation", {}).get("xor_decoded", [])]
            ),
            suspicious_imports=[SuspiciousImport(**x) for x in data.get("suspicious_imports", [])],
            sections=[SectionInfo(**x) for x in data.get("sections", [])],
            packer_info=PackerDetection(**data.get("packer_info", {})),
            evasion_info=EvasionInfo(**data.get("evasion_info", {})),
            capabilities=[Capability(**x) for x in data.get("capabilities", [])],
            top_suspicious_functions=[InterestingFunction(**x) for x in data.get("top_suspicious_functions", [])],
            ioc_references=[StringReference(**x) for x in data.get("ioc_references", [])],
            threat_intel=ThreatIntelResult(
                file_hash=data.get("threat_intel", {}).get("file_hash", ""),
                vt_positives=data.get("threat_intel", {}).get("vt_positives", 0),
                vt_total=data.get("threat_intel", {}).get("vt_total", 0),
                malicious_ips=data.get("threat_intel", {}).get("malicious_ips", {}),
                yara_matches=[YaraMatch(**x) for x in data.get("threat_intel", {}).get("yara_matches", [])]
            )
        )