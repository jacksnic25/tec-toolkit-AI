import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTabWidget, QVBoxLayout, QLabel, QPushButton,
    QFileDialog, QTextEdit, QLineEdit, QMessageBox, QComboBox, QHBoxLayout
)
from tools.IOC_extractor_gui import IOCExtractorGUI
from tools.vt_integration import VTAnalyzer
from tools.email_analyzer import EmailAnalyzer
from utils.output import Status, save_report
from utils.config import config

class VTFileTab(QWidget):
    def __init__(self):
        super().__init__()
        self.api_key = config.get("virustotal", "")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select file to scan")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)

        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_button)

        self.scan_button = QPushButton("Scan File")
        self.scan_button.clicked.connect(self.scan_file)

        self.save_button = QPushButton("Save Output")
        self.save_button.clicked.connect(self.save_output)
        self.save_button.setEnabled(False)

        self.format_combo = QComboBox()
        self.format_combo.addItems(["json", "pdf", "html"])

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        layout.addLayout(file_layout)
        layout.addWidget(self.scan_button)
        layout.addWidget(QLabel("Output Format:"))
        layout.addWidget(self.format_combo)
        layout.addWidget(self.save_button)
        layout.addWidget(QLabel("Scan Results:"))
        layout.addWidget(self.result_text)

        self.setLayout(layout)
        self.current_result = None

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_path_edit.setText(file_path)

    def scan_file(self):
        file_path = self.file_path_edit.text()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select a file to scan.")
            return
        if not self.api_key:
            QMessageBox.warning(self, "Input Error", "VirusTotal API key is not configured.")
            return
        try:
            with VTAnalyzer(self.api_key) as vt:
                result = vt.scan_file(file_path, wait_for_analysis=True)
            if result.status == Status.SUCCESS:
                self.current_result = result
                # If analysis data is present, show detailed analysis, else show basic data
                if hasattr(result.data, 'get') and result.data.get("analysis"):
                    self.result_text.setPlainText(str(result.data["analysis"]))
                else:
                    self.result_text.setPlainText(str(result.data))
                self.save_button.setEnabled(True)
            else:
                self.result_text.setPlainText(f"Error: {result.message}")
                self.save_button.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.save_button.setEnabled(False)

    def save_output(self):
        if not self.current_result:
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Output", filter="All Files (*.*)")
        if not file_path:
            return
        file_format = self.format_combo.currentText()
        try:
            save_report(self.current_result, file_path, file_format)
            QMessageBox.information(self, "Success", f"Output saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save output: {e}")

class VTURLTab(QWidget):
    def __init__(self):
        super().__init__()
        self.api_key = config.get("virustotal", "")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("Enter URL to scan")

        self.scan_button = QPushButton("Scan URL")
        self.scan_button.clicked.connect(self.scan_url)

        self.save_button = QPushButton("Save Output")
        self.save_button.clicked.connect(self.save_output)
        self.save_button.setEnabled(False)

        self.format_combo = QComboBox()
        self.format_combo.addItems(["json", "pdf", "html"])

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        layout.addWidget(self.url_edit)
        layout.addWidget(self.scan_button)
        layout.addWidget(QLabel("Output Format:"))
        layout.addWidget(self.format_combo)
        layout.addWidget(self.save_button)
        layout.addWidget(QLabel("Scan Results:"))
        layout.addWidget(self.result_text)

        self.setLayout(layout)
        self.current_result = None

    def scan_url(self):
        url = self.url_edit.text()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scan.")
            return
        if not self.api_key:
            QMessageBox.warning(self, "Input Error", "VirusTotal API key is not configured.")
            return
        try:
            with VTAnalyzer(self.api_key) as vt:
                result = vt.scan_url(url)
            if result.status == Status.SUCCESS:
                self.current_result = result
                self.result_text.setPlainText(str(result.data))
                self.save_button.setEnabled(True)
            else:
                self.result_text.setPlainText(f"Error: {result.message}")
                self.save_button.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.save_button.setEnabled(False)

    def save_output(self):
        if not self.current_result:
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Output", filter="All Files (*.*)")
        if not file_path:
            return
        file_format = self.format_combo.currentText()
        try:
            save_report(self.current_result, file_path, file_format)
            QMessageBox.information(self, "Success", f"Output saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save output: {e}")

class EmailsTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setPlaceholderText("Select email file to analyze")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_file)

        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_button)

        self.analyze_button = QPushButton("Analyze Email")
        self.analyze_button.clicked.connect(self.analyze_email)

        self.save_button = QPushButton("Save Output")
        self.save_button.clicked.connect(self.save_output)
        self.save_button.setEnabled(False)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        layout.addLayout(file_layout)
        layout.addWidget(self.analyze_button)
        layout.addWidget(QLabel("Analysis Results:"))
        layout.addWidget(self.result_text)
        layout.addWidget(self.save_button)

        self.setLayout(layout)
        self.current_result = None

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Email File")
        if file_path:
            self.file_path_edit.setText(file_path)

    def analyze_email(self):
        file_path = self.file_path_edit.text()
        if not file_path:
            QMessageBox.warning(self, "Input Error", "Please select an email file to analyze.")
            return
        try:
            result = EmailAnalyzer.analyze(file_path)
            if result.status == Status.SUCCESS:
                self.current_result = result
                self.result_text.setPlainText(str(result.data))
                self.save_button.setEnabled(True)
            else:
                self.result_text.setPlainText(f"Error: {result.message}")
                self.save_button.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.save_button.setEnabled(False)

    def save_output(self):
        if not self.current_result:
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Output", filter="All Files (*.*)")
        if not file_path:
            return
        file_format = "json"
        try:
            save_report(self.current_result, file_path, file_format)
            QMessageBox.information(self, "Success", f"Output saved to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save output: {e}")

class MainGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Main GUI Application")
        self.setGeometry(100, 100, 900, 700)
        layout = QVBoxLayout()
        self.tabs = QTabWidget()
        self.tabs.addTab(VTFileTab(), "VT File")
        self.tabs.addTab(VTURLTab(), "VT URL")
        self.tabs.addTab(EmailsTab(), "Emails")
        self.tabs.addTab(IOCExtractorGUI(), "IOC Extractor")
        layout.addWidget(self.tabs)
        self.setLayout(layout)

def main():
    app = QApplication(sys.argv)
    window = MainGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
