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

    EVENT_PATTERNS = {
        "FAILED_LOGIN": [
            r"failed password",
            r"authentication failure"
        ],

        "SUCCESSFUL_LOGIN": [
            r"accepted password",
            r"login successful"
        ],

        "INVALID_USER": [
            r"invalid user"
        ],

        "CONNECTION_REFUSED": [
            r"connection refused"
        ],

        "PORT_SCAN": [
            r"port scan",
            r"nmap scan"
        ],

        "AUTH_FAILURE": [
            r"authentication failure"
        ]
    }

    def __init__(self):

        self.ip_pattern = re.compile(
            r"(?:\d{1,3}\.){3}\d{1,3}"
        )

        self.port_pattern = re.compile(
            r"port\s+(\d+)",
            re.IGNORECASE
        )

        self.process_pattern = re.compile(
            r"([A-Za-z0-9_\-]+)\[\d+\]"
        )

        self.timestamp_pattern = re.compile(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)"
        )

        # Username patterns

        self.failed_login_pattern = re.compile(
            r"failed password for\s+([A-Za-z0-9_\-]+)",
            re.IGNORECASE
        )

        self.accepted_login_pattern = re.compile(
            r"accepted password for\s+([A-Za-z0-9_\-]+)",
            re.IGNORECASE
        )

        self.invalid_user_pattern = re.compile(
            r"invalid user\s+([A-Za-z0-9_\-]+)",
            re.IGNORECASE
        )

    def extract_metadata(self, log: str) -> Metadata:

        ips = self.ip_pattern.findall(log)

        src_ip = ips[0] if len(ips) > 0 else None
        dst_ip = ips[1] if len(ips) > 1 else None

        port = self.port_pattern.search(log)

        username = self.extract_username(log)

        process = self.process_pattern.search(log)

        timestamp = self.timestamp_pattern.search(log)

        protocol = self.detect_protocol(log)

        event = self.detect_event(log)

        # Disable hostname extraction for now.
        # We'll implement proper hostname parsing later.
        hostname = None

        return Metadata(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=None,
            dst_port=int(port.group(1)) if port else None,
            username=username,
            protocol=protocol,
            timestamp=timestamp.group(1) if timestamp else None,
            hostname=hostname,
            process=process.group(1) if process else None,
            event_type=event,
        )

    def extract_username(self, log: str) -> Optional[str]:

        for pattern in (
            self.failed_login_pattern,
            self.accepted_login_pattern,
            self.invalid_user_pattern
        ):

            match = pattern.search(log)

            if match:
                return match.group(1)

        return None

    def detect_protocol(self, log: str) -> str:

        log = log.lower()

        if "ssh" in log or "ssh2" in log:
            return "SSH"

        if "https" in log:
            return "HTTPS"

        if "http" in log:
            return "HTTP"

        if "ftp" in log:
            return "FTP"

        return "UNKNOWN"

    def detect_event(self, log: str) -> str:

        log = log.lower()

        for event, patterns in self.EVENT_PATTERNS.items():

            for pattern in patterns:

                if re.search(pattern, log, re.IGNORECASE):

                    return event

        return "UNKNOWN"