#!/usr/bin/env python3
import sys
import argparse
from typing import Dict, Callable
from tools.dns_harvester import DNSHarvester
from utils.output import Result, Status, display_results
from tools.vt_integration import VTAnalyzer
from tools import (
    EmailAnalyzer,
    DNSHarvester,
    PortScanner,
    IOCExtractorTool
)
from utils.output import display_results
from utils.config import config
from tools.email_analyzer import EmailAnalyzer
from utils.logger import setup_logger
from tools.whois_tool import WhoisTool


class TecToolkit:
    def __init__(self):
        self.config = config
        self.tools: Dict[str, Callable] = {
            "vt": self.handle_vt,
            "email": self.handle_email,
            "dns": self.handle_dns,
            "portscan": self.handle_portscan,
            "whois": self.handle_whois,
            "malwarechecker": self.handle_malwarechecker,
            "ioc_extractor": self.handle_ioc_extractor
        }

    def handle_vt(self, args):
        api_key = getattr(args, "vt_api_key", None) or self.config.get("virustotal")
        try:
            with VTAnalyzer(api_key) as vt:
                if args.action == "file":
                    return vt.file_report(args.target)
                elif args.action == "url":
                    return vt.scan_url(args.target)
                else:
                    return Result(status=Status.ERROR, message=f"Unknown action for vt: {args.action}")
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))

    def handle_email(self, args):
        return EmailAnalyzer.analyze(args.file)

    def handle_dns(self, args):
        google_key = getattr(args, "google_key", None) or self.config.get_nested("google_api", "key")
        google_cx = getattr(args, "google_cx", None) or self.config.get_nested("google_api", "cx")
        harvester = DNSHarvester(
            google_api_key=google_key,
            google_cx=google_cx
        )
        return harvester.comprehensive_harvest(args.domain)

    def handle_portscan(self, args):
        scanner = PortScanner()
        return scanner.scan(args.target, args.ports)

    def handle_whois(self, args):
        return WhoisTool.lookup(args.domain)

    def handle_malwarechecker(self, args):
        # Removed malwarechecker handler as malwarechecker is removed
        return Result(status=Status.ERROR, message="Malwarechecker tool is not available.")

    def handle_iocextract(self, args):
        try:
            return IoCExtractTool.extract_iocs_from_file(args.file)
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))

    def handle_ioc_extractor(self, args):
        try:
            if args.subtool == "ioc":
                return IOCExtractorTool.extract_iocs_from_file(args.file)
            elif args.subtool == "web":
                scrape_em = args.emails or False
                scrape_ph = args.phones or False
                scrape_ln = args.links or False
                if not any([scrape_em, scrape_ph, scrape_ln]):
                    scrape_em = scrape_ph = scrape_ln = True
                return IOCExtractorTool.scrape_website(args.url, scrape_em, scrape_ph, scrape_ln)
            else:
                return Result(status=Status.ERROR, message="Unknown subtool for ioc_extractor")
        except Exception as e:
            return Result(status=Status.ERROR, message=str(e))

    def run(self):
        parser = argparse.ArgumentParser(description="tec-oolkit")
        subparsers = parser.add_subparsers(dest="tool", required=True)

        # VirusTotal
        vt_parser = subparsers.add_parser("vt", help="VirusTotal operations")
        vt_sub = vt_parser.add_subparsers(dest="action")
        vt_sub.add_parser("file", help="File report").add_argument("target")
        vt_sub.add_parser("url", help="URL scan").add_argument("target")
        vt_parser.add_argument("--vt-api-key", help="VirusTotal API key")

        # Email Analyzer
        email_parser = subparsers.add_parser("email", help="Email analysis")
        email_parser.add_argument("file", help="Path to email file")

        # DNS Harvester
        dns_parser = subparsers.add_parser("dns", help="DNS operations")
        dns_parser.add_argument("domain", help="Target domain")
        dns_parser.add_argument("--google-key", help="Google API key")
        dns_parser.add_argument("--google-cx", help="Google CX")

        # Port Scanner
        port_parser = subparsers.add_parser("portscan", help="Port scanning")
        port_parser.add_argument("target", help="IP or domain")
        port_parser.add_argument("-p", "--ports", default="1-1024")

        # WHOIS
        whois_parser = subparsers.add_parser("whois", help="Domain lookup")
        whois_parser.add_argument("domain", help="Domain to research")

        # Malwarechecker
        mc_parser = subparsers.add_parser("malwarechecker", help="Malwarechecker operations")
        mc_parser.add_argument("--rules", help="Path to YARA rules directory")
        mc_parser.add_argument("--scan", action="store_true", help="Perform a one-time scan")
        mc_parser.add_argument("--root", help="Root directory to scan")
        mc_parser.add_argument("--ext", action="append", help="File extensions to scan")
        mc_parser.add_argument("--report-clean", action="store_true", help="Report clean files")
        mc_parser.add_argument("--report-errors", action="store_true", help="Report errors")
        mc_parser.add_argument("--report-output", help="File path to save the report")
        mc_parser.add_argument("--report-json", action="store_true", help="Output report in JSON format")

        # IoC Extractor
        ioc_extractor_parser = subparsers.add_parser("ioc_extractor", help="IOC extractor tool with subcommands")
        ioc_subparsers = ioc_extractor_parser.add_subparsers(dest="subtool", required=True)

        ioc_parser = ioc_subparsers.add_parser("ioc", help="Extract IOCs from file")
        ioc_parser.add_argument("file", help="Path to input file")

        web_parser = ioc_subparsers.add_parser("web", help="Web extraction from URL")
        web_parser.add_argument("url", help="URL to scrape")
        web_parser.add_argument("--emails", action="store_true", help="Scrape emails")
        web_parser.add_argument("--phones", action="store_true", help="Scrape phone numbers")
        web_parser.add_argument("--links", action="store_true", help="Scrape links")

        # Global report options
        parser.add_argument(
            "-o", "--output-file", help="File path to save the report"
        )
        parser.add_argument(
            "-f", "--output-format", choices=["json", "html", "console", "pdf"], default="console",
            help="Format of the output report"
        )

        args = parser.parse_args()
        result = self.tools[args.tool](args)

        # Handle output format and saving report
        if args.output_format == "console":
            display_results(result)
        else:
            from utils.output import save_report
            save_report(result, args.output_file, args.output_format)
if __name__ == "__main__":
    toolkit = TecToolkit()
    toolkit.run()
