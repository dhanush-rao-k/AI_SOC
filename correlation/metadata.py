import re
from typing import Dict


class MetadataExtractor:
    """
    Extracts useful metadata from a security log.

    Initially supports generic syslog/SSH logs.
    More parsers can be added later for:
    - Wazuh
    - Zeek
    - Suricata
    - Windows Event Logs
    - Firewall Logs
    """

    def __init__(self):

        self.ip_regex = re.compile(
            r"(?:\d{1,3}\.){3}\d{1,3}"
        )

        self.port_regex = re.compile(
            r"port\s+(\d+)"
        )

        self.username_regex = re.compile(
            r"for\s+([A-Za-z0-9_\-]+)"
        )

        self.timestamp_regex = re.compile(
            r"^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)"
        )

    def extract(self, log: str) -> Dict:

        metadata = {

            "src_ip": self.extract_source_ip(log),

            "dst_ip": self.extract_destination_ip(log),

            "src_port": self.extract_source_port(log),

            "dst_port": self.extract_destination_port(log),

            "protocol": self.extract_protocol(log),

            "username": self.extract_username(log),

            "hostname": self.extract_hostname(log),

            "timestamp": self.extract_timestamp(log),

            "event_type": self.extract_event_type(log),

            "process": self.extract_process(log)

        }

        return metadata

    def extract_source_ip(self, log):

        ips = self.ip_regex.findall(log)

        if ips:
            return ips[0]

        return None

    def extract_destination_ip(self, log):

        ips = self.ip_regex.findall(log)

        if len(ips) > 1:
            return ips[1]

        return None

    def extract_source_port(self, log):

        return None

    def extract_destination_port(self, log):

        match = self.port_regex.search(log)

        if match:
            return match.group(1)

        return None

    def extract_protocol(self, log):

        log = log.lower()

        if "ssh" in log:
            return "SSH"

        if "http" in log:
            return "HTTP"

        if "https" in log:
            return "HTTPS"

        if "ftp" in log:
            return "FTP"

        if "dns" in log:
            return "DNS"

        return "UNKNOWN"

    def extract_username(self, log):

        match = self.username_regex.search(log)

        if match:
            return match.group(1)

        return None

    def extract_hostname(self, log):

        parts = log.split()

        if len(parts) >= 4:
            return parts[3]

        return None

    def extract_timestamp(self, log):

        match = self.timestamp_regex.search(log)

        if match:
            return match.group(1)

        return None

    def extract_process(self, log):

        match = re.search(r"([A-Za-z0-9_\-]+)\[\d+\]", log)

        if match:
            return match.group(1)

        return None

    def extract_event_type(self, log):

        log = log.lower()

        if "failed password" in log:
            return "FAILED_LOGIN"

        if "accepted password" in log:
            return "SUCCESSFUL_LOGIN"

        if "connection refused" in log:
            return "CONNECTION_REFUSED"

        if "invalid user" in log:
            return "INVALID_USER"

        if "authentication failure" in log:
            return "AUTHENTICATION_FAILURE"

        return "UNKNOWN"