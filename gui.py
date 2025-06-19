#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication
from tools.IOC_extractor_gui import IOCExtractorGUI

def main():
    app = QApplication(sys.argv)
    window = IOCExtractorGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
