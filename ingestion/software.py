import re
from dataclasses import dataclass
from typing import List


@dataclass
class Software:

    name: str

    version: str


class SoftwareExtractor:
    """
    Extracts software names and versions from security logs.

    Examples:
        OpenSSH_8.2p1
        Apache/2.4.57
        nginx/1.22.0
        OpenSSL 3.0.2
        Log4j 2.17.1
    """

    def __init__(self):

        self.patterns = [

            # OpenSSH_8.2p1
            re.compile(
                r"(OpenSSH)[_/ ]([0-9A-Za-z.\-p]+)",
                re.IGNORECASE
            ),

            # Apache/2.4.57
            re.compile(
                r"(Apache)[/ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            ),

            # nginx/1.22.0
            re.compile(
                r"(nginx)[/ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            ),

            # OpenSSL 3.0.2
            re.compile(
                r"(OpenSSL)[ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            ),

            # Log4j 2.17.1
            re.compile(
                r"(Log4j)[ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            ),

            # MySQL 8.0.36
            re.compile(
                r"(MySQL)[ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            ),

            # PostgreSQL 15.4
            re.compile(
                r"(PostgreSQL)[ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            ),

            # Python/3.11
            re.compile(
                r"(Python)[/ ]([0-9A-Za-z.\-]+)",
                re.IGNORECASE
            )
        ]

    def extract(self, log: str) -> List[Software]:

        software_found = []

        for pattern in self.patterns:

            matches = pattern.findall(log)

            for name, version in matches:

                software_found.append(

                    Software(

                        name=name,

                        version=version

                    )

                )

        # Remove duplicates

        unique = {}

        for software in software_found:

            key = (

                software.name.lower(),

                software.version

            )

            unique[key] = software

        return list(unique.values())