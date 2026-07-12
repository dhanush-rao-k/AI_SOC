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

    def extract_iocs(self, log: str) -> IOC:

        return IOC(

            ip_addresses=list(
                set(self.ip_pattern.findall(log))
            ),

            domains=list(
                set(self.domain_pattern.findall(log))
            ),

            urls=list(
                set(self.url_pattern.findall(log))
            ),

            file_hashes=list(
                set(self.hash_pattern.findall(log))
            ),

            emails=list(
                set(self.email_pattern.findall(log))
            )

        )