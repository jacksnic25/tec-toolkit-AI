#!/usr/bin/env python3
import re
import quopri
import hashlib
import ipaddress
import email
from email.parser import BytesParser
from typing import Dict, List, Optional
from pathlib import Path
from utils.output import Result, Status, display_results
from utils.network import ip_lookup  # We'll move IP lookup to shared utils

class EmailAnalyzer:
    @staticmethod
    def analyze(file_path: str) -> Result:
        """Main analysis function with standardized output"""
        try:
            email_msg = EmailAnalyzer._read_email(file_path)
            
            return Result(
                status=Status.SUCCESS,
                data={
                    "headers": EmailAnalyzer._extract_headers(email_msg),
                    "ips": EmailAnalyzer._extract_ips(email_msg),
                    "urls": EmailAnalyzer._extract_urls(email_msg),
                    "attachments": EmailAnalyzer._extract_attachments(email_msg),
                    "metadata": {
                        "file": str(Path(file_path).name),
                        "size": Path(file_path).stat().st_size
                    }
                }
            )
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))

    @staticmethod
    def _read_email(file_path: str) -> email.message.Message:
        """Read email file with proper encoding handling"""
        with open(file_path, 'rb') as file:
            return BytesParser().parsebytes(file.read())

    @staticmethod
    def _extract_ips(email_msg: email.message.Message) -> List[Dict]:
        """Extract and validate IP addresses"""
        ips = set()
        
        # Header extraction
        for header_value in email_msg.values():
            ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
        
        # Body extraction
        for part in email_msg.walk():
            if part.get_content_type() in ('text/plain', 'text/html'):
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode('utf-8', errors='ignore')
                    ips.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
        
        # Validation and enrichment
        results = []
        for ip in set(ips):
            try:
                ip_obj = ipaddress.ip_address(ip)
                results.append({
                    "address": ip,
                    "defanged": ip.replace('.', '[.]'),
                    "is_private": ip_obj.is_private,
                    "geo": ip_lookup(ip) if not ip_obj.is_private else None
                })
            except ValueError:
                continue
                
        return results

    @staticmethod
    def _extract_urls(email_msg: email.message.Message) -> List[Dict]:
        """Extract and defang URLs"""
        urls = set()
        for part in email_msg.walk():
            if part.get_content_type() in ('text/plain', 'text/html'):
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode('utf-8', errors='ignore')
                    urls.update(re.findall(
                        r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', 
                        text,
                        re.IGNORECASE
                    ))
        
        return [{
            "original": url,
            "defanged": url.replace('https://', 'hxxps[://]').replace('.', '[.]')
        } for url in urls]

    @staticmethod
    def _extract_headers(email_msg: email.message.Message) -> Dict:
        """Extract security-relevant headers"""
        headers_of_interest = [
            "From", "To", "Subject", "Date", 
            "Received", "Message-ID", "X-Mailer",
            "X-Originating-IP", "X-Sender-IP",
            "Authentication-Results", "DKIM-Signature",
            "Received-SPF"
        ]
        return {
            h: email_msg[h] 
            for h in headers_of_interest 
            if h in email_msg
        }

    @staticmethod
    def _extract_attachments(email_msg: email.message.Message) -> List[Dict]:
        """Extract attachment metadata with hashes"""
        attachments = []
        for part in email_msg.walk():
            if (
                part.get_content_maintype() != 'multipart' and 
                part.get('Content-Disposition') is not None
            ):
                filename = part.get_filename()
                if filename:
                    payload = part.get_payload(decode=True)
                    attachments.append({
                        "filename": filename,
                        "content_type": part.get_content_type(),
                        "size": len(payload),
                        "hashes": {
                            "md5": hashlib.md5(payload).hexdigest(),
                            "sha1": hashlib.sha1(payload).hexdigest(),
                            "sha256": hashlib.sha256(payload).hexdigest()
                        }
                    })
        return attachments
