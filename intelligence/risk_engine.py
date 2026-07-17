from dataclasses import dataclass
from enrichment.models import ThreatIntel


@dataclass
class RiskAssessment:

    score: int

    level: str

    reasons: list[str]


class RiskEngine:

    def calculate(

        self,

        threat_intel: ThreatIntel,

        event_type: str,

        similar_incidents: int

    ) -> RiskAssessment:

        score = 0

        reasons = []

        # ---------------------------------------
        # VirusTotal
        # ---------------------------------------

        malicious = max(
            (i.malicious for i in threat_intel.indicators),
            default=0
        )

        if malicious >= 15:

            score += 30

            reasons.append(

                "IOC highly malicious on VirusTotal"

            )

        elif malicious >= 5:

            score += 20

            reasons.append(

                "IOC reported malicious by VirusTotal"

            )

        elif malicious > 0:

            score += 10

            reasons.append(

                "IOC has limited malicious detections"

            )

        # ---------------------------------------
        # Similar Incidents
        # ---------------------------------------

        if similar_incidents >= 20:

            score += 20

            reasons.append(

                "Large number of correlated incidents"

            )

        elif similar_incidents >= 10:

            score += 15

            reasons.append(

                "Multiple correlated incidents"

            )

        elif similar_incidents >= 5:

            score += 10

            reasons.append(

                "Repeated historical activity"

            )

        # ---------------------------------------
        # MITRE
        # ---------------------------------------

        if threat_intel.mitre_results:

            score += 10

            reasons.append(

                "Mapped to MITRE ATT&CK"

            )

        # ---------------------------------------
        # CVEs
        # ---------------------------------------

        highest_cvss = max(
            (v.cvss_score for v in threat_intel.cve_results),
            default=0
        )

        if highest_cvss >= 9:

            score += 20

            reasons.append(

                "Critical vulnerability detected"

            )

        elif highest_cvss >= 7:

            score += 15

            reasons.append(

                "High severity vulnerability detected"

            )

        elif highest_cvss >= 4:

            score += 10

            reasons.append(

                "Medium severity vulnerability detected"

            )

        # ---------------------------------------
        # Event Severity
        # ---------------------------------------

        critical_events = {

            "RANSOMWARE",
            "PRIVILEGE_ESCALATION",
            "COMMAND_EXECUTION",
            "FAILED_LOGIN"

        }

        medium_events = {

            "INVALID_USER",
            "PORT_SCAN",
            "CONNECTION_REFUSED"

        }

        if event_type in critical_events:

            score += 20

            reasons.append(

                f"Critical event: {event_type}"

            )

        elif event_type in medium_events:

            score += 10

            reasons.append(

                f"Medium severity event: {event_type}"

            )

        score = min(score, 100)

        if score >= 80:

            level = "Critical"

        elif score >= 60:

            level = "High"

        elif score >= 40:

            level = "Medium"

        else:

            level = "Low"

        return RiskAssessment(

            score=score,

            level=level,

            reasons=reasons

        )