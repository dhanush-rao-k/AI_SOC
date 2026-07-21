import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class IOC:

    ip_addresses: List[str] = field(default_factory=list)

    domains: List[str] = field(default_factory=list)

    urls: List[str] = field(default_factory=list)

    file_hashes: List[str] = field(default_factory=list)

    emails: List[str] = field(default_factory=list)


# File extensions that should NOT be classified as domains
_FILE_EXTENSIONS = {
    ".exe", ".dll", ".zip", ".pdf", ".doc", ".docx", ".txt",
    ".png", ".jpg", ".jpeg", ".gif", ".js", ".css", ".iso", ".bin",
}


class IOCExtractor:

    def __init__(self):

        self.ip_pattern = re.compile(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        )

        self.url_pattern = re.compile(
            r"https?://[^\s]+"
        )

        self.domain_pattern = re.compile(
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        )

        self.email_pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        )

        self.hash_pattern = re.compile(
            r"\b[a-fA-F0-9]{32,64}\b"
        )

    # ------------------------------------------------------------------
    # Private helper methods
    # ------------------------------------------------------------------

    def _extract_ips(self, log: str) -> List[str]:
        return sorted(set(self.ip_pattern.findall(log)))

    def _extract_urls(self, log: str) -> List[str]:
        return sorted(set(self.url_pattern.findall(log)))

    def _extract_domains(self, log: str) -> List[str]:
        # Strip URLs from the log first so URL hostnames are not double-counted
        cleaned = self.url_pattern.sub("", log)

        # Also strip email addresses so the host part is not matched as a domain
        cleaned = self.email_pattern.sub("", cleaned)

        matches = self.domain_pattern.findall(cleaned)

        results = set()
        for match in matches:
            # Reject anything that ends with a known file extension
            lower = match.lower()
            if any(lower.endswith(ext) for ext in _FILE_EXTENSIONS):
                continue
            results.add(match)

        return sorted(results)

    def _extract_hashes(self, log: str) -> List[str]:
        return sorted(set(self.hash_pattern.findall(log)))

    def _extract_emails(self, log: str) -> List[str]:
        return sorted(set(self.email_pattern.findall(log)))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_iocs(self, log: str) -> IOC:

        return IOC(
            ip_addresses=self._extract_ips(log),
            urls=self._extract_urls(log),
            domains=self._extract_domains(log),
            file_hashes=self._extract_hashes(log),
            emails=self._extract_emails(log),
        )