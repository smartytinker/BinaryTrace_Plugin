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
class AnalysisReport:
    file: str
    risk_assessment: RiskAssessment
    iocs: IOCs
    obfuscation: Obfuscation
    suspicious_imports: List[SuspiciousImport]

    def to_dict(self) -> dict:
        """Converts the dataclass hierarchy into a JSON-serializable dictionary."""
        return asdict(self)