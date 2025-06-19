# utils/network.py
import requests
import ipaddress
from typing import Optional, Dict
from utils.output import Result, Status, display_results

#function for dns-harvester
def is_domain_resolvable(domain: str) -> bool:
    """Check if a domain resolves to any IP"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
def ip_lookup(ip: str) -> Optional[Dict]:
    """Standardized IP geolocation lookup"""
    if ipaddress.ip_address(ip).is_private:
        return None
    
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=5,
            headers={"Accept": "application/json"}
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "org": data.get("org"),
                "asn": data.get("asn", "").split()[0] if data.get("asn") else None,
                "location": data.get("loc")
            }
    except requests.RequestException:
        return None
