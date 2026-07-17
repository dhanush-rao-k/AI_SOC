from dataclasses import dataclass

from enrichment.models import ThreatIntel


@dataclass
class ConfidenceAssessment:

    score: int

    level: str

    reasons: list[str]


class ConfidenceEngine:

    def calculate(

        self,

        threat_intel: ThreatIntel,

        average_similarity: float,

        similar_incidents: int

    ) -> ConfidenceAssessment:

        score = 0

        reasons = []

        # ----------------------------------
        # Semantic Similarity
        # ----------------------------------

        if average_similarity >= 0.90:

            score += 30

            reasons.append(
                "Strong semantic match with historical incidents."
            )

        elif average_similarity >= 0.80:

            score += 20

            reasons.append(
                "Good semantic similarity."
            )

        elif average_similarity >= 0.70:

            score += 10

            reasons.append(
                "Moderate semantic similarity."
            )

        # ----------------------------------
        # VirusTotal
        # ----------------------------------

        malicious = max(

            (indicator.malicious
             for indicator in threat_intel.indicators),

            default=0

        )

        if malicious >= 10:

            score += 30

            reasons.append(
                "VirusTotal strongly supports the finding."
            )

        elif malicious > 0:

            score += 15

            reasons.append(
                "VirusTotal partially supports the finding."
            )

        # ----------------------------------
        # Similar Incidents
        # ----------------------------------

        if similar_incidents >= 10:

            score += 20

            reasons.append(
                "Many similar incidents observed."
            )

        elif similar_incidents >= 5:

            score += 10

            reasons.append(
                "Repeated historical activity."
            )

        # ----------------------------------
        # MITRE
        # ----------------------------------

        if threat_intel.mitre_results:

            score += 10

            reasons.append(
                "MITRE ATT&CK mapping available."
            )

        # ----------------------------------
        # CVE
        # ----------------------------------

        if threat_intel.cve_results:

            score += 10

            reasons.append(
                "Relevant software vulnerabilities found."
            )

        score = min(score, 100)

        if score >= 80:

            level = "High"

        elif score >= 60:

            level = "Medium"

        else:

            level = "Low"

        return ConfidenceAssessment(

            score=score,

            level=level,

            reasons=reasons

        )