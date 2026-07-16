from dataclasses import dataclass
from typing import Optional

import requests

from config import VIRUSTOTAL_API_KEY, VT_BASE_URL


@dataclass
class VirusTotalResult:
    found: bool

    malicious: int

    suspicious: int

    harmless: int

    undetected: int

    reputation: int

    last_analysis_date: Optional[int]

    link: str


class VirusTotalClient:

    def __init__(self):

        self.headers = {

            "x-apikey": VIRUSTOTAL_API_KEY

        }

    def lookup_ip(self, ip: str) -> VirusTotalResult:

        url = f"{VT_BASE_URL}/ip_addresses/{ip}"

        return self.__query(url)

    def lookup_domain(self, domain: str) -> VirusTotalResult:

        url = f"{VT_BASE_URL}/domains/{domain}"

        return self.__query(url)


    def lookup_url(self, url: str):

        raise NotImplementedError(
            "URL lookup requires URL submission or URL ID."
        )


    def lookup_hash(self, file_hash: str) -> VirusTotalResult:

        url = f"{VT_BASE_URL}/files/{file_hash}"

        return self.__query(url)

    def __query(self, url: str) -> VirusTotalResult:

        response = requests.get(

            url,

            headers=self.headers,

            timeout=15

        )

        if response.status_code != 200:

            return VirusTotalResult(

                found=False,

                malicious=0,

                suspicious=0,

                harmless=0,

                undetected=0,

                reputation=0,

                last_analysis_date=None,

                link=""

            )

        data = response.json()["data"]["attributes"]

        stats = data["last_analysis_stats"]

        return VirusTotalResult(

            found=True,

            malicious=stats.get("malicious", 0),

            suspicious=stats.get("suspicious", 0),

            harmless=stats.get("harmless", 0),

            undetected=stats.get("undetected", 0),

            reputation=data.get("reputation", 0),

            last_analysis_date=data.get(
                "last_analysis_date"
            ),

            link=response.json()["data"]["links"]["self"]

        )