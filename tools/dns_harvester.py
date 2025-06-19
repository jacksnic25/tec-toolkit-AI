#!/usr/bin/env python3
import socket
#!/usr/bin/env python3
import socket
import requests
import json
from typing import List, Dict, Optional
from urllib.parse import urlparse
from pathlib import Path

from utils.output import Result, Status, display_results
from utils.network import is_domain_resolvable
from utils.config import config


from utils.output import Result, Status, display_results
class DNSHarvester:
    def __init__(self, 
                 google_api_key: Optional[str] = None,
                 google_cx: Optional[str] = None):
        # Use parameter if provided, else fall back to config
        self.api_key = google_api_key or config.get_nested("google_api", "key")
        self.cx = google_cx or config.get_nested("google_api", "cx")
        self.prefixes = self._load_prefixes()
        
    def _load_prefixes(self) -> List[str]:
        """Load domain prefixes from file"""
        prefix_file = Path(__file__).parent.parent / 'data' / 'dns_prefixes.txt'
        try:
            with open(prefix_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return ['www', 'mail', 'ftp', 'admin', 'webmail']

    def harvest_from_google(self, domain: str) -> Result:
        """Discover subdomains using Google Custom Search API"""
        if not self.api_key or not self.cx:
            return Result(
                status=Status.ERROR,
                message="Google API key and CX not configured"
            )

        try:
            url = f"https://www.googleapis.com/customsearch/v1?key={self.api_key}&cx={self.cx}&q=site:{domain}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            domains = set()
            for item in response.json().get('items', []):
                parsed = urlparse(item['link'])
                if parsed.netloc:
                    domains.add(parsed.netloc)
            
            return Result(
                status=Status.SUCCESS,
                data={
                    "source": "google",
                    "domains": list(domains),
                    "count": len(domains)
                }
            )
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))

    def harvest_from_dns(self, domain: str) -> Result:
        """Brute-force subdomains using common prefixes"""
        try:
            valid_domains = []
            for prefix in self.prefixes:
                subdomain = f"{prefix}.{domain}"
                if is_domain_resolvable(subdomain):
                    valid_domains.append(subdomain)
            
            return Result(
                status=Status.SUCCESS,
                data={
                    "source": "dns_bruteforce",
                    "domains": valid_domains,
                    "count": len(valid_domains)
                }
            )
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))

    def comprehensive_harvest(self, domain: str) -> Result:
        """Combine multiple harvesting methods"""
        results = []
        
        # Google-based discovery
        google_result = self.harvest_from_google(domain)
        if google_result.status == Status.SUCCESS:
            results.extend(google_result.data['domains'])
        
        # DNS brute-force
        dns_result = self.harvest_from_dns(domain)
        if dns_result.status == Status.SUCCESS:
            results.extend(dns_result.data['domains'])
        
        return Result(
            status=Status.SUCCESS,
            data={
                "domain": domain,
                "subdomains": list(set(results)),  # Remove duplicates
                "sources": ["google", "dns_bruteforce"],
                "total": len(set(results))
            }
        )
