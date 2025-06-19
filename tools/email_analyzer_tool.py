from tools.email_analyzer import EmailAnalyzer

class EmailAnalyzerTool:
    @staticmethod
    def analyze(file_path):
        return EmailAnalyzer.analyze(file_path)
