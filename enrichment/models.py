from dataclasses import dataclass, field
from typing import List


# --------------------------------------------------
# VirusTotal Indicator
# --------------------------------------------------

@dataclass
class ThreatIndicator:

    indicator: str

    indicator_type: str          # IP / DOMAIN / HASH

    source: str                  # VirusTotal

    malicious: int

    suspicious: int

    harmless: int

    undetected: int

    reputation: int


# --------------------------------------------------
# GeoIP
# --------------------------------------------------

@dataclass
class GeoLocation:

    ip: str

    country: str

    city: str

    region: str

    isp: str

    asn: str


# --------------------------------------------------
# MITRE
# --------------------------------------------------

@dataclass
class MitreTechnique:

    technique_id: str

    name: str

    tactic: str

    description: str


# --------------------------------------------------
# CVE
# --------------------------------------------------

@dataclass
class Vulnerability:

    cve_id: str

    software: str

    version: str

    severity: str

    cvss_score: float

    description: str

    published: str

    reference: str


# --------------------------------------------------
# Master Threat Intelligence Object
# --------------------------------------------------

@dataclass
class ThreatIntel:

    indicators: List[ThreatIndicator] = field(default_factory=list)

    geo_locations: List[GeoLocation] = field(default_factory=list)

    mitre_results: List[MitreTechnique] = field(default_factory=list)

    cve_results: List[Vulnerability] = field(default_factory=list)