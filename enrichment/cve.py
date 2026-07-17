from dataclasses import dataclass
from typing import List

import requests

from ingestion.software import Software


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


class CVELookup:
    """
    Queries the NVD CVE database using software name and version.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def lookup(
        self,
        software: Software,
        limit: int = 5
    ) -> List[Vulnerability]:

        keyword = f"{software.name} {software.version}"

        response = requests.get(
            self.BASE_URL,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": limit
            },
            timeout=20
        )

        if response.status_code != 200:
            return []

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):

            cve = item["cve"]

            severity = "UNKNOWN"
            score = 0.0

            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:

                metric = metrics["cvssMetricV31"][0]

                severity = metric["cvssData"]["baseSeverity"]

                score = metric["cvssData"]["baseScore"]

            elif "cvssMetricV30" in metrics:

                metric = metrics["cvssMetricV30"][0]

                severity = metric["cvssData"]["baseSeverity"]

                score = metric["cvssData"]["baseScore"]

            elif "cvssMetricV2" in metrics:

                metric = metrics["cvssMetricV2"][0]

                severity = metric["baseSeverity"]

                score = metric["cvssData"]["baseScore"]

            description = ""

            for desc in cve["descriptions"]:

                if desc["lang"] == "en":

                    description = desc["value"]

                    break

            vulnerabilities.append(

                Vulnerability(

                    cve_id=cve["id"],

                    software=software.name,

                    version=software.version,

                    severity=severity,

                    cvss_score=score,

                    description=description,

                    published=cve["published"],

                    reference=f"https://nvd.nist.gov/vuln/detail/{cve['id']}"

                )

            )

        return vulnerabilities

    def lookup_all(
        self,
        software_list: List[Software],
        limit: int = 5
    ) -> List[Vulnerability]:

        results = []

        for software in software_list:

            results.extend(
                self.lookup(
                    software,
                    limit
                )
            )

        return results