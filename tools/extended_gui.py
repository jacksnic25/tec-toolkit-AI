from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import main  # Assuming main.py contains the AI processing functions
import json
import time

class AIWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, func, input_data):
        super().__init__()
        self.func = func
        self.input_data = input_data

    def run(self):
        result = self.func(self.input_data)
        self.finished.emit(result)

class VirusTotalFileGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VirusTotal File Scan with AI Processing")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.vt_file_path = QLineEdit()
        self.vt_file_path.setPlaceholderText("Select file to scan with VirusTotal")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_vt_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.vt_file_path)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        self.vt_output = QTextEdit()
        self.vt_output.setReadOnly(True)
        layout.addWidget(QLabel("VirusTotal Scan Results:"))
        layout.addWidget(self.vt_output)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(QLabel("AI Output:"))
        layout.addWidget(self.ai_output)

    def browse_vt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.vt_file_path.setText(file_path)
            self.scan_file(file_path)

    def scan_file(self, file_path):
        self.vt_output.setPlainText("Scanning file with VirusTotal, please wait...")
        # Run scan in background thread to avoid blocking UI
        self.worker = AIWorker(main.vt_file, file_path)
        self.worker.finished.connect(self.display_scan_results)
        self.worker.start()

    def display_scan_results(self, result):
        self.vt_output.setPlainText(result)
        # Automatically start AI processing after scan completes
        self.process_with_ai(result)

    def process_with_ai(self, scan_result):
        if not scan_result.strip():
            self.ai_output.setPlainText("No VirusTotal scan results to process.")
            return
        self.ai_output.setPlainText("Processing with AI, please wait...")
        self.ai_worker = AIWorker(main.process_virustotal_output, scan_result)
        self.ai_worker.finished.connect(self.display_ai_output)
        self.ai_worker.start()

    def display_ai_output(self, result):
        self.ai_output.setPlainText(result)

class VirusTotalURLGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VirusTotal URL Scan with AI Processing")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter URL to scan with VirusTotal")
        scan_button = QPushButton("Scan URL")
        scan_button.clicked.connect(self.scan_url)

        layout.addWidget(self.url_input)
        layout.addWidget(scan_button)

        self.vt_output = QTextEdit()
        self.vt_output.setReadOnly(True)
        layout.addWidget(QLabel("VirusTotal URL Scan Results:"))
        layout.addWidget(self.vt_output)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(QLabel("AI Output:"))
        layout.addWidget(self.ai_output)

    def scan_url(self):
        url = self.url_input.text().strip()
        if not url:
            self.vt_output.setPlainText("Please enter a URL to scan.")
            return
        self.vt_output.setPlainText("Scanning URL with VirusTotal, please wait...")
        self.worker = AIWorker(main.vt_url, url)
        self.worker.finished.connect(self.display_scan_results)
        self.worker.start()

    def display_scan_results(self, result):
        self.vt_output.setPlainText(result)
        # Automatically start AI processing after scan completes
        self.process_with_ai(result)

    def process_with_ai(self, scan_result):
        if not scan_result.strip():
            self.ai_output.setPlainText("No VirusTotal URL scan results to process.")
            return
        self.ai_output.setPlainText("Processing with AI, please wait...")
        self.ai_worker = AIWorker(main.process_virustotal_output, scan_result)
        self.ai_worker.finished.connect(self.display_ai_output)
        self.ai_worker.start()

    def display_ai_output(self, result):
        self.ai_output.setPlainText(result)

class EmailAnalyzerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Analyzer with AI Processing")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.email_file_path = QLineEdit()
        self.email_file_path.setPlaceholderText("Select email file to analyze")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_email_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.email_file_path)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        self.email_output = QTextEdit()
        self.email_output.setReadOnly(True)
        layout.addWidget(QLabel("Email Analysis Results:"))
        layout.addWidget(self.email_output)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(QLabel("AI Output:"))
        layout.addWidget(self.ai_output)

    def browse_email_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Email File")
        if file_path:
            self.email_file_path.setText(file_path)
            self.analyze_email(file_path)

    def analyze_email(self, file_path):
        self.email_output.setPlainText("Analyzing email, please wait...")
        self.worker = AIWorker(main.email_ai_processing, file_path)
        self.worker.finished.connect(self.display_analysis_results)
        self.worker.start()

    def display_analysis_results(self, result):
        self.email_output.setPlainText(result)
        # Automatically start AI processing after analysis completes
        self.process_with_ai(result)

    def process_with_ai(self, analysis_result):
        if not analysis_result.strip():
            self.ai_output.setPlainText("No email analysis results to process.")
            return
        self.ai_output.setPlainText("Processing with AI, please wait...")
        self.ai_worker = AIWorker(main.email_ai_processing, analysis_result)
        self.ai_worker.finished.connect(self.display_ai_output)
        self.ai_worker.start()

    def display_ai_output(self, result):
        self.ai_output.setPlainText(result)
