import sys
import os
import json
import configparser
from PyQt5.QtWidgets import QApplication
from tools.gui import IOCExtractorGUI
from tools.email_analyzer_tool import EmailAnalyzerTool

# Load VirusTotal API key for launch_gui usage
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    try:
        config = configparser.ConfigParser()
        config.read("config.ini")
        VT_API_KEY = config.get("virustotal", "api_key", fallback="").strip()
    except Exception:
        VT_API_KEY = None

if not VT_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY environment variable or add it to config.ini under [virustotal] section with api_key.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IOCExtractorGUI()
    window.show()
    sys.exit(app.exec_())
