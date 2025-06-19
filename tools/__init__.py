"""Tools Subpackage"""
from .vt_integration import VTAnalyzer
from .email_analyzer import EmailAnalyzer
from .dns_harvester import DNSHarvester
from .portscanner import PortScanner
from .whois_tool import WhoisTool

from .iocextract_tool import IoCExtractTool

__all__ = [
    'VTAnalyzer',
    'EmailAnalyzer',
    'DNSHarvester', 
    'PortScanner',
    'WhoisTool',
    'IoCExtractTool'
]

# Lazy imports to prevent circular dependencies
def VTAnalyzer():
    from .vt_integration import VTAnalyzer as _VTAnalyzer
    return _VTAnalyzer

def DNSHarvester():
    from .dns_harvester import DNSHarvester as _DNSHarvester
    return _DNSHarvester

def IoCExtractTool():
    from .iocextract_tool import IoCExtractTool as _IoCExtractTool
    return _IoCExtractTool
