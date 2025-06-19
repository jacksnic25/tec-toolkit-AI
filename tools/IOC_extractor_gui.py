from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from tools.iocextract_tool import IoCExtractTool
import json
import main  # Assuming main.py contains the AI processing functions

class AIWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, text):
        super().__init__()
        self.text = text

    def run(self):
        # Call the AI processing function for IOC extractor
        result = main.ioc_extractor_tool(self.text)
        self.finished.emit(result)

class IOCExtractorGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IOC Extractor with AI Processing")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        self.iocextract_file_path = QLineEdit()
        self.iocextract_file_path.setPlaceholderText("Select file to extract IOCs from")
        browse_button = QPushButton("Browse")
        browse_button.clicked.connect(self.browse_iocextract_file)

        file_layout = QVBoxLayout()
        file_layout.addWidget(self.iocextract_file_path)
        file_layout.addWidget(browse_button)
        layout.addLayout(file_layout)

        self.iocextract_output = QTextEdit()
        self.iocextract_output.setReadOnly(True)
        layout.addWidget(QLabel("Extraction Results:"))
        layout.addWidget(self.iocextract_output)

        # Removed manual Process with AI button to trigger AI processing automatically after extraction
        # process_button = QPushButton("Process with AI")
        # process_button.clicked.connect(self.process_with_ai)
        # layout.addWidget(process_button)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(QLabel("AI Output:"))
        layout.addWidget(self.ai_output)

    def browse_iocextract_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.iocextract_file_path.setText(file_path)
            self.extract_iocs_from_file(file_path)

    def extract_iocs_from_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            results = IoCExtractTool.extract_iocs(content)
            display_text = json.dumps(results, indent=2)
            self.iocextract_output.setPlainText(display_text)
            # Automatically start AI processing after extraction completes
            self.process_with_ai(display_text)
        except Exception as e:
            self.iocextract_output.setPlainText(f"Failed to extract IOCs: {str(e)}")

    def process_with_ai(self, text=None):
        if text is None:
            text = self.iocextract_output.toPlainText()
        if not text.strip():
            self.ai_output.setPlainText("No IOC extraction results to process.")
            return
        self.ai_output.setPlainText("Processing with AI, please wait...")
        self.worker = AIWorker(text)
        self.worker.finished.connect(self.display_ai_output)
        self.worker.start()

    def display_ai_output(self, result):
        self.ai_output.setPlainText(result)
