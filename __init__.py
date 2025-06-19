"""Security Toolkit Package"""
from .cli import main
from .version import __version__
from tools import VTAnalyzer, DNSHarvester

__all__ = ['main', '__version__']


# Then use VTAnalyzer() and DNSHarvester() as functions
