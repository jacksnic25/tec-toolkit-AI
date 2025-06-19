# tools/port_scanner.py
import socket
from concurrent.futures import ThreadPoolExecutor

from utils.output import Result, Status, display_results

# Simple vulnerability database for demonstration
VULNERABILITY_DB = {
    21: {
        "service": "ftp",
        "vulnerabilities": [
            {
                "name": "Anonymous FTP Access",
                "description": "Allows anonymous users to access FTP server.",
                "recommendation": "Disable anonymous FTP or restrict access."
            }
        ]
    },
    22: {
        "service": "ssh",
        "vulnerabilities": [
            {
                "name": "Weak SSH Credentials",
                "description": "Weak or default passwords can be brute-forced.",
                "recommendation": "Use strong passwords and key-based authentication."
            }
        ]
    },
    80: {
        "service": "http",
        "vulnerabilities": [
            {
                "name": "Outdated HTTP Server",
                "description": "Older versions may have known exploits.",
                "recommendation": "Keep HTTP server updated."
            }
        ]
    },
    443: {
        "service": "https",
        "vulnerabilities": [
            {
                "name": "SSL/TLS Vulnerabilities",
                "description": "Misconfigured SSL/TLS can lead to attacks.",
                "recommendation": "Use strong ciphers and keep SSL/TLS updated."
            }
        ]
    }
}

class PortScanner:
    @staticmethod
    def scan(target: str, ports: str = "1-1024") -> Result:
        try:
            # Strip protocol if present
            if target.startswith("http://"):
                target = target[len("http://"):]
            elif target.startswith("https://"):
                target = target[len("https://"):]

            open_ports = []
            closed_ports = []
            port_list = []
            for part in ports.replace(" ", "").split(","):
                if "-" in part:
                    start, end = part.split("-")
                    port_list.extend(range(int(start), int(end) + 1))
                else:
                    port_list.append(int(part))

            def check_port(port):
                with socket.socket() as s:
                    s.settimeout(1)
                    if s.connect_ex((target, port)) == 0:
                        open_ports.append(port)
                    else:
                        closed_ports.append(port)

            with ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(check_port, port_list)

            # Detect services and vulnerabilities for open ports
            services = {}
            vulnerabilities = {}
            for port in open_ports:
                try:
                    service_name = socket.getservbyport(port)
                except OSError:
                    service_name = "unknown"
                services[port] = service_name
                vuln_info = VULNERABILITY_DB.get(port)
                if vuln_info:
                    vulnerabilities[port] = vuln_info

            return Result(
                status=Status.SUCCESS,
                data={
                    "target": target,
                    "open_ports": sorted(open_ports),
                    "closed_ports": sorted(closed_ports),
                    "services": services,
                    "vulnerabilities": vulnerabilities,
                    "scan_type": "TCP Connect"
                }
            )
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))
