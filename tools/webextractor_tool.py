#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import os

class WebExtractorTool:
    @staticmethod
    def is_valid_url(url):
        # Disabled URL validation to accept user input as-is
        return True

    @staticmethod
    def scrape_emails(text):
        email_pattern = re.compile(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}', re.IGNORECASE)
        return list(set(email_pattern.findall(text)))

    @staticmethod
    def scrape_phone_numbers(text):
        # Fixed regex pattern by removing extra escaping
        phone_pattern = re.compile(r'(\+?\d{1,3})?[\s\-\.]?\(?\d{2,4}\)?[\s\-\.]?\d{3,5}[\s\-\.]?\d{3,5}')
        phone_numbers = [match.group().strip() for match in re.finditer(phone_pattern, text) if len(match.group().strip()) >= 7]
        return list(set(phone_numbers))

    @staticmethod
    def scrape_links(text):
        link_pattern = re.compile(r'https?://[^\\s"\']+', re.IGNORECASE)
        return list(set(link_pattern.findall(text)))

    @staticmethod
    def scrape_website(url, scrape_em=True, scrape_ph=True, scrape_ln=True):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
            res = requests.get(url, headers=headers, timeout=10)
            res.raise_for_status()

            soup = BeautifulSoup(res.text, 'html.parser')
            text = soup.get_text()
            html = res.text
            results = {}

            if scrape_em:
                emails = WebExtractorTool.scrape_emails(text)
                results['emails'] = emails

            if scrape_ph:
                phones = WebExtractorTool.scrape_phone_numbers(text)
                results['phones'] = phones

            if scrape_ln:
                links = WebExtractorTool.scrape_links(html)
                results['links'] = links

            return results

        except requests.exceptions.RequestException as err:
            return {"error": str(err)}
