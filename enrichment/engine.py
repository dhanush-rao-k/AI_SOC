from enrichment.ioc import IOC
from ingestion.software import Software
from enrichment.models import (
    ThreatIntel,
    ThreatIndicator,
    GeoLocation,
    MitreTechnique,
)

from enrichment.virustotal import VirusTotalClient
from enrichment.geoip import GeoIPClient
from enrichment.mitre import MitreLookup
from enrichment.cve import CVELookup


class EnrichmentEngine:

    def __init__(self):

        self.virustotal = VirusTotalClient()

        self.geoip = GeoIPClient()

        self.mitre = MitreLookup()

        self.cve = CVELookup()

    # ----------------------------------------------------

    def enrich(

        self,

        ioc: IOC,

        software: list[Software],

        event_type: str

    ) -> ThreatIntel:

        intel = ThreatIntel()

        # --------------------------------------------
        # VirusTotal - IP Addresses
        # --------------------------------------------

        for ip in set(ioc.ip_addresses):

            result = self.virustotal.lookup_ip(ip)

            if result.found:

                intel.indicators.append(ThreatIndicator(
                    indicator=ip,
                    indicator_type="IP",
                    source="VirusTotal",
                    malicious=result.malicious,
                    suspicious=result.suspicious,
                    harmless=result.harmless,
                    undetected=result.undetected,
                    reputation=result.reputation,
                ))

        # --------------------------------------------
        # VirusTotal - Domains
        # --------------------------------------------

        for domain in set(ioc.domains):

            result = self.virustotal.lookup_domain(domain)

            if result.found:

                intel.indicators.append(ThreatIndicator(
                    indicator=domain,
                    indicator_type="DOMAIN",
                    source="VirusTotal",
                    malicious=result.malicious,
                    suspicious=result.suspicious,
                    harmless=result.harmless,
                    undetected=result.undetected,
                    reputation=result.reputation,
                ))

        # --------------------------------------------
        # VirusTotal - File Hashes
        # --------------------------------------------

        for file_hash in set(ioc.file_hashes):

            result = self.virustotal.lookup_hash(file_hash)

            if result.found:

                intel.indicators.append(
                    ThreatIndicator(
                        indicator=file_hash,
                        indicator_type="HASH",
                        source="VirusTotal",
                        malicious=result.malicious,
                        suspicious=result.suspicious,
                        harmless=result.harmless,
                        undetected=result.undetected,
                        reputation=result.reputation,
                    )
                )

        # --------------------------------------------
        # GeoIP
        # --------------------------------------------

        for ip in set(ioc.ip_addresses):

            geo = self.geoip.lookup_ip(ip)

            if geo.success:

                intel.geo_locations.append(GeoLocation(
                    ip=geo.ip,
                    country=geo.country or "",
                    city=geo.city or "",
                    region=geo.region or "",
                    isp=geo.isp or "",
                    asn=geo.asn or "",
                ))

        # --------------------------------------------
        # MITRE
        # --------------------------------------------

        mitre_result = self.mitre.lookup(event_type)

        if mitre_result.found:

            intel.mitre_results.append(MitreTechnique(
                technique_id=mitre_result.technique_id,
                name=mitre_result.technique,
                tactic=mitre_result.tactic,
                description=mitre_result.description,
            ))

        # --------------------------------------------
        # CVE
        # --------------------------------------------

        vulnerabilities = self.cve.lookup_all(software)

        intel.cve_results.extend(vulnerabilities)

        return intel