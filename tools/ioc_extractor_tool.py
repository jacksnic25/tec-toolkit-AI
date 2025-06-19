from tools.iocextract_tool import IoCExtractTool
from tools.webextractor_tool import WebExtractorTool

class IOCExtractorTool:
    @staticmethod
    def extract_iocs_from_file(file_path):
        return IoCExtractTool.extract_iocs_from_file(file_path)

    @staticmethod
    def scrape_website(url, scrape_em=True, scrape_ph=True, scrape_ln=True):
        return WebExtractorTool.scrape_website(url, scrape_em, scrape_ph, scrape_ln)
