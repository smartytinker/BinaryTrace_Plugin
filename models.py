"""
models.py
Dataclasses representing the strictly typed schema for analysis results.
"""
from dataclasses import dataclass, asdict
from typing import List

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
class AnalysisReport:
    file: str
    risk_assessment: RiskAssessment
    iocs: IOCs
    obfuscation: Obfuscation
    suspicious_imports: List[SuspiciousImport]
    # NEW FIELDS:
    sections: List[SectionInfo] 
    packer_info: PackerDetection
    evasion_info: EvasionInfo    # NEW FIELD

    def to_dict(self) -> dict:
        """Converts the dataclass hierarchy into a JSON-serializable dictionary."""
        return asdict(self)

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