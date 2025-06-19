"""
Wrapper tool for iocextract integration.

This module provides a class IoCExtractTool to extract IOCs from text or files
using the iocextract-master/iocextract.py functionality.
"""

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "iocextract-master"))
import iocextract

class IoCExtractTool:
    @staticmethod
    def extract_iocs_from_text(text, refang=False, strip=False):
        """
        Extract IOCs from a given text string.

        :param text: Input text to extract IOCs from
        :param refang: Whether to refang the extracted IOCs
        :param strip: Whether to strip trailing garbage from URLs
        :return: Dictionary of extracted IOC lists by type
        """
        results = {
            "urls": list(iocextract.extract_urls(text, refang=refang, strip=strip)),
            "ips": list(iocextract.extract_ips(text, refang=refang)),
            "emails": list(iocextract.extract_emails(text, refang=refang)),
            "hashes": list(iocextract.extract_hashes(text)),
            "yara_rules": list(iocextract.extract_yara_rules(text)),
            "telephone_nums": list(iocextract.extract_telephone_nums(text)),
        }
        return results

    @staticmethod
    def extract_iocs_from_file(file_path, refang=False, strip=False):
        """
        Extract IOCs from a file.

        :param file_path: Path to the input file
        :param refang: Whether to refang the extracted IOCs
        :param strip: Whether to strip trailing garbage from URLs
        :return: Dictionary of extracted IOC lists by type
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()

        return IoCExtractTool.extract_iocs_from_text(data, refang=refang, strip=strip)
