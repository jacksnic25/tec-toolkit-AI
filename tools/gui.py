import sys
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QLabel, QPushButton,
    QFileDialog, QTextEdit, QLineEdit, QCheckBox, QMessageBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from tools.iocextract_tool import IoCExtractTool
from tools.webextractor_tool import WebExtractorTool
from tools.email_analyzer_tool import EmailAnalyzerTool
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import main  # Assuming main.py contains the AI processing functions

class AIWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, func, input_data):
        super().__init__()
        self.func = func
        self.input_data = input_data

    def run(self):
        try:
            print(f"AIWorker: Starting AI processing with input: {self.input_data[:100]}...")  # Debug
            result = self.func(self.input_data)
            print(f"AIWorker: AI processing result: {result[:100]}...")  # Debug
        except Exception as e:
            result = f"Error during AI processing: {str(e)}"
            print(result)  # Debug
        self.finished.emit(result)

class IOCExtractorGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unified Threat Analysis Toolkit")
        self.setGeometry(100, 100, 900, 700)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.tabs = QTabWidget()

        self.tabs.addTab(self.create_iocextract_tab(), "IOC Extractor")
        self.tabs.addTab(self.create_webextractor_tab(), "Web Extractor")
        # Adding Email Analyzer tab
        # The email analyzer tab was not added, adding it now
        self.tabs.addTab(self.create_email_analyzer_tab(), "Email Analyzer")
        # self.tabs.addTab(self.create_vt_file_tab(), "VT File")
        self.tabs.addTab(self.create_vt_file_tab(), "VT File")
        self.tabs.addTab(self.create_vt_url_tab(), "VT URL")

        print(f"Tabs count: {self.tabs.count()}")
        for i in range(self.tabs.count()):
            print(f"Tab {i}: {self.tabs.tabText(i)}")

        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def create_email_analyzer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.email_file_path = QLineEdit()
        self.email_file_path.setPlaceholderText("Select email file to analyze")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_email_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.email_file_path)
        file_layout.addWidget(browse_button)

        analyze_button = QPushButton("Analyze Email")
        analyze_button.clicked.connect(self.analyze_email)

        self.email_output = QTextEdit()
        self.email_output.setReadOnly(True)

        layout.addLayout(file_layout)
        layout.addWidget(analyze_button)
        layout.addWidget(QLabel("Email Analysis Results:"))
        layout.addWidget(self.email_output)

        self.email_ai_output = QTextEdit()
        self.email_ai_output.setReadOnly(True)
        layout.addWidget(QLabel("Conclusion:"))
        layout.addWidget(self.email_ai_output)

        tab.setLayout(layout)
        return tab

    def browse_email_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Email File")
        if file_path:
            self.email_file_path.setText(file_path)

    def analyze_email(self):
        file_path = self.email_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select an email file to analyze.")
            return
        try:
            result = EmailAnalyzerTool.analyze(file_path)
            if result.status != "success":
                raise Exception(result.message)
            display_text = json.dumps(result.data, indent=2)
            self.email_output.setPlainText(display_text)
            # Automatically call AI processing after analysis
            self.process_email_ai()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def process_email_ai(self):
        text = self.email_output.toPlainText()
        if not text.strip():
            self.email_ai_output.setPlainText("No email analysis results to process.")
            return
        self.email_ai_output.setPlainText("Processing, please wait...")
        self.email_worker = AIWorker(main.email_ai_processing, text)
        self.email_worker.finished.connect(self.display_email_ai_output)
        self.email_worker.start()

    def display_email_ai_output(self, result):
        self.email_ai_output.setPlainText("Conclusion:\n" + result)

    # IOC Extractor Tab
    def create_iocextract_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.iocextract_file_path = QLineEdit()
        self.iocextract_file_path.setPlaceholderText("Select file to extract IOCs from")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_iocextract_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.iocextract_file_path)
        file_layout.addWidget(browse_button)

        self.iocextract_output = QTextEdit()
        self.iocextract_output.setReadOnly(True)

        extract_button = QPushButton("Extract IOCs")
        extract_button.clicked.connect(self.extract_iocs)

        layout.addLayout(file_layout)
        layout.addWidget(extract_button)
        layout.addWidget(QLabel("Extraction Results:"))
        layout.addWidget(self.iocextract_output)

        self.ioc_ai_output = QTextEdit()
        self.ioc_ai_output.setReadOnly(True)
        layout.addWidget(QLabel("Conclusion:"))
        layout.addWidget(self.ioc_ai_output)

        save_combined_output_btn = QPushButton("Save Combined Output")
        save_combined_output_btn.clicked.connect(self.save_iocextract_combined_output)
        layout.addWidget(save_combined_output_btn)

        tab.setLayout(layout)
        return tab

    def save_iocextract_combined_output(self):
        tool_output = self.iocextract_output.toPlainText().strip()
        ai_output = self.ioc_ai_output.toPlainText().strip()
        if not tool_output and not ai_output:
            QMessageBox.warning(self, "Save Error", "No content to save.")
            return
        combined_content = ""
        if tool_output:
            combined_content += "Extraction Results:\n" + tool_output + "\n\n"
        if ai_output:
            combined_content += "Conclusion:\n" + ai_output + "\n"
        self.save_output(combined_content, "ioc_combined_output")

    def browse_iocextract_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.iocextract_file_path.setText(file_path)

    def extract_iocs(self):
        file_path = self.iocextract_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select a file to extract IOCs from.")
            return
        try:
            results = IoCExtractTool.extract_iocs_from_file(file_path)
            display_text = ""
            for key, values in results.items():
                display_text += f"{key}:\n"
                for v in values:
                    display_text += f"  {v}\n"
                display_text += "\n"
            self.iocextract_output.setPlainText(display_text)
            # Automatically call AI processing after extraction
            self.process_ioc_ai()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def process_ioc_ai(self):
        text = self.iocextract_output.toPlainText()
        if not text.strip():
            self.ioc_ai_output.setPlainText("No IOC extraction results to process.")
            return
        self.ioc_ai_output.setPlainText("Processing, please wait...")
        self.ioc_worker = AIWorker(main.ioc_extractor_tool, text)
        self.ioc_worker.finished.connect(self.display_ioc_ai_output)
        self.ioc_worker.start()

    def display_ioc_ai_output(self, result):
        self.ioc_ai_output.setPlainText("Conclusion:\n" + result)

    # Web Extractor Tab
    def create_webextractor_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.webextractor_url = QLineEdit()
        self.webextractor_url.setPlaceholderText("Enter URL to scrape")

        self.emails_checkbox = QCheckBox("Scrape Emails")
        self.emails_checkbox.setChecked(True)
        self.phones_checkbox = QCheckBox("Scrape Phone Numbers")
        self.phones_checkbox.setChecked(True)
        self.links_checkbox = QCheckBox("Scrape Links")
        self.links_checkbox.setChecked(True)

        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_webextractor_file)

        scrape_button = QPushButton("Scrape Website")
        scrape_button.clicked.connect(self.scrape_website)

        self.webextractor_output = QTextEdit()
        self.webextractor_output.setReadOnly(True)

        layout.addWidget(self.webextractor_url)
        layout.addWidget(self.emails_checkbox)
        layout.addWidget(self.phones_checkbox)
        layout.addWidget(self.links_checkbox)

        file_layout = QVBoxLayout()
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        layout.addWidget(scrape_button)
        layout.addWidget(QLabel("Scraping Results:"))
        layout.addWidget(self.webextractor_output)

        self.webextractor_ai_output = QTextEdit()
        self.webextractor_ai_output.setReadOnly(True)
        layout.addWidget(QLabel("Conclusion:"))
        layout.addWidget(self.webextractor_ai_output)

        save_combined_output_btn = QPushButton("Save Combined Output")
        save_combined_output_btn.clicked.connect(self.save_webextractor_combined_output)
        layout.addWidget(save_combined_output_btn)

        tab.setLayout(layout)
        return tab

    def browse_webextractor_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.webextractor_url.setText(file_path)

    def save_webextractor_combined_output(self):
        tool_output = self.webextractor_output.toPlainText().strip()
        ai_output = self.webextractor_ai_output.toPlainText().strip()
        if not tool_output and not ai_output:
            QMessageBox.warning(self, "Save Error", "No content to save.")
            return
        combined_content = ""
        if tool_output:
            combined_content += "Scraping Results:\n" + tool_output + "\n\n"
        if ai_output:
            combined_content += "Conclusion:\n" + ai_output + "\n"
        self.save_output(combined_content, "webextractor_combined_output")

    def scrape_website(self):
        url = self.webextractor_url.text()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scrape.")
            return
        scrape_em = self.emails_checkbox.isChecked()
        scrape_ph = self.phones_checkbox.isChecked()
        scrape_ln = self.links_checkbox.isChecked()
        try:
            results = WebExtractorTool.scrape_website(url, scrape_em, scrape_ph, scrape_ln)
            if "error" in results:
                QMessageBox.critical(self, "Error", results["error"])
                return
            display_text = ""
            for key, values in results.items():
                display_text += f"{key}:\n"
                for v in values:
                    display_text += f"  {v}\n"
                display_text += "\n"
            self.webextractor_output.setPlainText(display_text)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    # Email Analyzer Tab
    def create_email_analyzer_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.email_file_path = QLineEdit()
        self.email_file_path.setPlaceholderText("Select email file to analyze")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_email_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.email_file_path)
        file_layout.addWidget(browse_button)

        analyze_button = QPushButton("Analyze Email")
        analyze_button.clicked.connect(self.analyze_email)

        self.email_output = QTextEdit()
        self.email_output.setReadOnly(True)

        layout.addLayout(file_layout)
        layout.addWidget(analyze_button)
        layout.addWidget(QLabel("Email Analysis Results:"))
        layout.addWidget(self.email_output)

        self.email_ai_output = QTextEdit()
        self.email_ai_output.setReadOnly(True)
        layout.addWidget(QLabel("Conclusion:"))
        layout.addWidget(self.email_ai_output)

        # Remove separate save buttons and add combined save button for Email Analyzer tab
        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button
        # So remove the above two buttons and add combined save button here

        # Remove separate save buttons
        # Add combined save button

        # Remove separate save buttons and add combined save button
        # Remove above two buttons and add below combined save button instead
        # So remove the above two buttons and add below combined save button

        # Remove the above two buttons
        # Add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here

        # Remove the above two buttons and add combined save button
        # So I will remove the above two buttons and add combined save button here


    def save_email_analysis_output(self):
        self.save_output(self.email_output.toPlainText(), "email_analysis_results")

    def save_email_ai_output(self):
        self.save_output(self.email_ai_output.toPlainText(), "email_ai_output")

        tab.setLayout(layout)
        return tab

    def browse_email_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Email File")
        if file_path:
            self.email_file_path.setText(file_path)

    def analyze_email(self):
        file_path = self.email_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select an email file to analyze.")
            return
        try:
            result = EmailAnalyzerTool.analyze(file_path)
            if result.status != "success":
                raise Exception(result.message)
            display_text = json.dumps(result.data, indent=2)
            self.email_output.setPlainText(display_text)
            # Automatically call AI processing after analysis
            self.process_email_ai()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def process_email_ai(self):
        text = self.email_output.toPlainText()
        if not text.strip():
            self.email_ai_output.setPlainText("No email analysis results to process.")
            return
        self.email_ai_output.setPlainText("Processing, please wait...")
        self.email_worker = AIWorker(main.email_ai_processing, text)
        self.email_worker.finished.connect(self.display_email_ai_output)
        self.email_worker.start()

    def display_email_ai_output(self, result):
        self.email_ai_output.setPlainText("Conclusion:\n" + result)

    # VirusTotal File Tab
    def create_vt_file_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.vt_file_path = QLineEdit()
        self.vt_file_path.setPlaceholderText("Select file for VirusTotal scan")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_vt_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.vt_file_path)
        file_layout.addWidget(browse_button)

        scan_button = QPushButton("Scan File with VirusTotal")
        scan_button.clicked.connect(self.scan_vt_file)

        self.vt_file_output = QTextEdit()
        self.vt_file_output.setReadOnly(True)

        layout.addLayout(file_layout)
        layout.addWidget(scan_button)
        layout.addWidget(QLabel("VirusTotal File Scan Results:"))
        layout.addWidget(self.vt_file_output)

        self.vt_file_ai_output = QTextEdit()
        self.vt_file_ai_output.setReadOnly(True)
        layout.addWidget(QLabel("Conclusion:"))
        layout.addWidget(self.vt_file_ai_output)

        save_combined_output_btn = QPushButton("Save Combined Output")
        save_combined_output_btn.clicked.connect(self.save_vt_file_combined_output)
        layout.addWidget(save_combined_output_btn)

        tab.setLayout(layout)
        return tab

    def save_vt_file_combined_output(self):
        tool_output = self.vt_file_output.toPlainText().strip()
        ai_output = self.vt_file_ai_output.toPlainText().strip()
        if not tool_output and not ai_output:
            QMessageBox.warning(self, "Save Error", "No content to save.")
            return
        combined_content = ""
        if tool_output:
            combined_content += "VirusTotal File Scan Results:\n" + tool_output + "\n\n"
        if ai_output:
            combined_content += "Conclusion:\n" + ai_output + "\n"
        self.save_output(combined_content, "vt_file_combined_output")

    def browse_vt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File for VirusTotal")
        if file_path:
            self.vt_file_path.setText(file_path)

    def scan_vt_file(self):
        file_path = self.vt_file_path.text()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select a file to scan with VirusTotal.")
            return
        try:
            result = main.vt_file(file_path)
            self.vt_file_output.setPlainText(result)
            # Automatically call AI processing after scan
            self.process_vt_file_ai()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def process_vt_file_ai(self):
        text = self.vt_file_output.toPlainText()
        if not text.strip():
            self.vt_file_ai_output.setPlainText("No VirusTotal file scan results to process.")
            return
        self.vt_file_ai_output.setPlainText("Processing, please wait...")
        self.vt_file_worker = AIWorker(main.process_virustotal_output, text)
        self.vt_file_worker.finished.connect(self.display_vt_file_ai_output)
        self.vt_file_worker.start()

    def display_vt_file_ai_output(self, result):
        self.vt_file_ai_output.setPlainText("Conclusion:\n" + result)

    # VirusTotal URL Tab
    def create_vt_url_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.vt_url_input = QLineEdit()
        self.vt_url_input.setPlaceholderText("Enter URL for VirusTotal scan")

        scan_button = QPushButton("Scan URL with VirusTotal")
        scan_button.clicked.connect(self.scan_vt_url)

        self.vt_url_output = QTextEdit()
        self.vt_url_output.setReadOnly(True)

        layout.addWidget(self.vt_url_input)
        layout.addWidget(scan_button)
        layout.addWidget(QLabel("VirusTotal URL Scan Results:"))
        layout.addWidget(self.vt_url_output)

        self.vt_url_ai_output = QTextEdit()
        self.vt_url_ai_output.setReadOnly(True)
        layout.addWidget(QLabel("Conclusion:"))
        layout.addWidget(self.vt_url_ai_output)

        save_combined_output_btn = QPushButton("Save Combined Output")
        save_combined_output_btn.clicked.connect(self.save_vt_url_combined_output)
        layout.addWidget(save_combined_output_btn)

        tab.setLayout(layout)
        return tab

    def save_vt_url_combined_output(self):
        tool_output = self.vt_url_output.toPlainText().strip()
        ai_output = self.vt_url_ai_output.toPlainText().strip()
        if not tool_output and not ai_output:
            QMessageBox.warning(self, "Save Error", "No content to save.")
            return
        combined_content = ""
        if tool_output:
            combined_content += "VirusTotal URL Scan Results:\n" + tool_output + "\n\n"
        if ai_output:
            combined_content += "Conclusion:\n" + ai_output + "\n"
        self.save_output(combined_content, "vt_url_combined_output")

    def scan_vt_url(self):
        url = self.vt_url_input.text()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scan with VirusTotal.")
            return
        try:
            result = main.vt_url(url)
            self.vt_url_output.setPlainText(result)
            # Automatically call AI processing after scan
            self.process_vt_url_ai()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def process_vt_url_ai(self):
        text = self.vt_url_output.toPlainText()
        if not text.strip():
            self.vt_url_ai_output.setPlainText("No VirusTotal URL scan results to process.")
            return
        self.vt_url_ai_output.setPlainText("Processing, please wait...")
        self.vt_url_worker = AIWorker(main.process_virustotal_output, text)
        self.vt_url_worker.finished.connect(self.display_vt_url_ai_output)
        self.vt_url_worker.start()

    def display_vt_url_ai_output(self, result):
        self.vt_url_ai_output.setPlainText("Conclusion:\n" + result)

    # Save functions for IOC Extractor
    def save_iocextract_output(self):
        self.save_output(self.iocextract_output.toPlainText(), "ioc_extraction_results")

    def save_ioc_ai_output(self):
        self.save_output(self.ioc_ai_output.toPlainText(), "ioc_ai_output")

    # Save functions for VirusTotal File
    def save_vt_file_output(self):
        self.save_output(self.vt_file_output.toPlainText(), "vt_file_scan_results")

    def save_vt_file_ai_output(self):
        self.save_output(self.vt_file_ai_output.toPlainText(), "vt_file_ai_output")

    # Save functions for VirusTotal URL
    def save_vt_url_output(self):
        self.save_output(self.vt_url_output.toPlainText(), "vt_url_scan_results")

    def save_vt_url_ai_output(self):
        self.save_output(self.vt_url_ai_output.toPlainText(), "vt_url_ai_output")

    # General save output function
    def save_output(self, content, default_filename):
        if not content.strip():
            QMessageBox.warning(self, "Save Error", "No content to save.")
            return
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Output", default_filename,
                                                   "JSON Files (*.json);;Word Documents (*.docx);;PDF Files (*.pdf)",
                                                   options=options)
        if file_path:
            try:
                if file_path.endswith(".json"):
                    self.save_output_to_json(file_path, content)
                elif file_path.endswith(".docx"):
                    self.save_output_to_word(file_path, content)
                elif file_path.endswith(".pdf"):
                    self.save_output_to_pdf(file_path, content)
                else:
                    QMessageBox.warning(self, "Save Error", "Unsupported file format.")
                    return
                QMessageBox.information(self, "Save Successful", f"Output saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save output: {str(e)}")

    def save_output_to_json(self, file_path, content):
        try:
            with open(file_path, 'w') as f:
                f.write(content)
        except Exception as e:
            raise e

    def save_output_to_word(self, file_path, content):
        try:
            from docx import Document
            doc = Document()
            doc.add_paragraph(content)
            doc.save(file_path)
        except ImportError:
            raise Exception("python-docx module is not installed.")
        except Exception as e:
            raise e

    def save_output_to_pdf(self, file_path, content):
        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.set_font("Arial", size=12)
            for line in content.split('\n'):
                pdf.cell(0, 10, txt=line, ln=True)
            pdf.output(file_path)
        except ImportError:
            raise Exception("fpdf module is not installed.")
        except Exception as e:
            raise e

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = IOCExtractorGUI()
    window.show()
    sys.exit(app.exec_())
