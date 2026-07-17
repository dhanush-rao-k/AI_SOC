from enrichment.ioc import IOC
from ingestion.software import Software
from enrichment.models import ThreatIntel

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

                intel.indicators.append(result)

        # --------------------------------------------
        # VirusTotal - Domains
        # --------------------------------------------

        for domain in set(ioc.domains):

            result = self.virustotal.lookup_domain(domain)

            if result.found:

                intel.indicators.append(result)

        # --------------------------------------------
        # VirusTotal - File Hashes
        # --------------------------------------------

        for file_hash in set(ioc.file_hashes):

            result = self.virustotal.lookup_hash(file_hash)

            if result.found:

                intel.indicators.append(result)

        # --------------------------------------------
        # GeoIP
        # --------------------------------------------

        for ip in set(ioc.ip_addresses):

            geo = self.geoip.lookup_ip(ip)

            if geo.success:

                intel.geo_locations.append(geo)

        # --------------------------------------------
        # MITRE
        # --------------------------------------------

        mitre_results = self.mitre.lookup(event_type)

        intel.mitre_results.extend(mitre_results)

        # --------------------------------------------
        # CVE
        # --------------------------------------------

        vulnerabilities = self.cve.lookup_all(software)

        intel.cve_results.extend(vulnerabilities)

        return intel