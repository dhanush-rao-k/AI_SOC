from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class GeoIPResult:
    ip: str
    country: Optional[str]
    city: Optional[str]
    region: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    isp: Optional[str]
    asn: Optional[str]
    success: bool


class GeoIPClient:

    BASE_URL = "http://ip-api.com/json"

    def lookup_ip(self, ip: str) -> GeoIPResult:

        response = requests.get(
            f"{self.BASE_URL}/{ip}",
            timeout=10
        )

        if response.status_code != 200:
            return GeoIPResult(
                ip=ip,
                country=None,
                city=None,
                region=None,
                latitude=None,
                longitude=None,
                isp=None,
                asn=None,
                success=False
            )

        data = response.json()

        if data["status"] != "success":
            return GeoIPResult(
                ip=ip,
                country=None,
                city=None,
                region=None,
                latitude=None,
                longitude=None,
                isp=None,
                asn=None,
                success=False
            )

        return GeoIPResult(
            ip=ip,
            country=data.get("country"),
            city=data.get("city"),
            region=data.get("regionName"),
            latitude=data.get("lat"),
            longitude=data.get("lon"),
            isp=data.get("isp"),
            asn=data.get("as"),
            success=True
        )