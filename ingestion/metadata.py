import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Metadata:
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    username: Optional[str]
    protocol: Optional[str]
    timestamp: Optional[str]
    hostname: Optional[str]
    process: Optional[str]
    event_type: Optional[str]

class MetadataExtractor:

    def __init__(self):

        self.ip_pattern = re.compile(
            r"(?:\d{1,3}\.){3}\d{1,3}"
        )

        self.port_pattern = re.compile(
            r"port\s+(\d+)"
        )

        self.user_pattern = re.compile(
            r"for\s+([A-Za-z0-9_\-]+)"
        )

        self.process_pattern = re.compile(
            r"([A-Za-z0-9_\-]+)\[\d+\]"
        )

        self.timestamp_pattern = re.compile(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)"
        )

    def extract_metadata(self, log: str) -> Metadata:

        ips = self.ip_pattern.findall(log)

        src_ip = ips[0] if len(ips) > 0 else None
        dst_ip = ips[1] if len(ips) > 1 else None

        port = self.port_pattern.search(log)
        username = self.user_pattern.search(log)
        process = self.process_pattern.search(log)
        timestamp = self.timestamp_pattern.search(log)

        protocol = self.detect_protocol(log)
        event = self.detect_event(log)

        hostname = log.split()[3] if len(log.split()) >= 4 else None

        return Metadata(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=int(port.group(1)) if port else None,
            username=username.group(1) if username else None,
            protocol=protocol,
            timestamp=timestamp.group(1) if timestamp else None,
            hostname=hostname,
            process=process.group(1) if process else None,
            event_type=event,
        )

    def detect_protocol(self, log: str):

        log = log.lower()

        if "ssh" in log:
            return "SSH"

        if "http" in log:
            return "HTTP"

        if "https" in log:
            return "HTTPS"

        if "ftp" in log:
            return "FTP"

        return "UNKNOWN"

    def detect_event(self, log: str):

        log = log.lower()

        if "failed password" in log:
            return "FAILED_LOGIN"

        if "accepted password" in log:
            return "SUCCESSFUL_LOGIN"

        if "invalid user" in log:
            return "INVALID_USER"

        if "authentication failure" in log:
            return "AUTH_FAILURE"

        return "UNKNOWN"