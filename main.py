try:
    import groq
except ImportError:
    import sys
    import os
    sys.path.append(os.path.expanduser("~/.local/lib/python3.13/site-packages"))
    import groq
import base64
import time
import requests
import json
import os
from ai_backend import process_virustotal_output, ioc_extractor_tool

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def email_ai_processing(text: str) -> str:
    """
    Stub function for AI processing of email analysis results.
    Replace this with actual AI processing logic as needed.
    """
    return "AI analysis of email content is not yet implemented."
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

if not VT_API_KEY:
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read("config.ini")
        VT_API_KEY = config.get("virustotal", "api_key", fallback="").strip()
    except Exception:
        VT_API_KEY = None

if not VT_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY environment variable or add it to config.ini under [virustotal] section with api_key.")

if not GROQ_API_KEY:
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read("config.ini")
        GROQ_API_KEY = config.get("groq", "api_key", fallback="").strip()
    except Exception:
        GROQ_API_KEY = None

if not GROQ_API_KEY:
    raise ValueError("Groq AI API key not found. Please set GROQ_API_KEY environment variable or add it to config.ini under [groq] section with api_key.")

client = groq.Groq(api_key=GROQ_API_KEY)

# EmailAnalyzer placeholder or import
try:
    from some_email_module import EmailAnalyzer
except ImportError:
    class EmailAnalyzer:
        @staticmethod
        def analyze(file_path):
            return type('Result', (), {'status': 'error', 'message': 'EmailAnalyzer module not found', 'data': None})()

# Add a stub function for email_ai_processing to avoid undefined error
# (imported from ai_backend now)

def vt_file(file_path: str):
    try:
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": VT_API_KEY
        }
        with open(file_path, "rb") as f:
            files = {"file": (file_path, f)}
            response = requests.post(url, headers=headers, files=files)
        if response.status_code == 409:
            # File already scanned, get existing analysis id
            analysis_id = response.json()["meta"]["file_info"]["sha256"]
        else:
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]

        # Poll for analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(10):
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()
            status = analysis_data["data"]["attributes"]["status"]
            if status == "completed":
                return json.dumps(analysis_data)
            time.sleep(3)
        return "Analysis timed out."
    except Exception as e:
        return f"Error scanning file: {str(e)}"

def vt_url(url_to_scan: str):
    try:
        url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": VT_API_KEY
        }
        # URL must be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        response = requests.post(url, headers=headers, data={"url": url_to_scan})
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        # Poll for analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        for _ in range(10):
            analysis_response = requests.get(analysis_url, headers=headers)
            analysis_response.raise_for_status()
            analysis_data = analysis_response.json()
            status = analysis_data["data"]["attributes"]["status"]
            if status == "completed":
                return json.dumps(analysis_data)
            time.sleep(3)
        return "Analysis timed out."
    except Exception as e:
        return f"Error scanning URL: {str(e)}"

tools = [
    {
      "type": "function",
      "function": {
        "name": "calculator",
        "description": "Calculate the values of two numbers",
        "parameters": {
          "type": "object",
          "properties": {
            "operation": {
              "type": "string",
              "description": "The type of operation to perform. Supported operations are add, multiply, divide and subtract"
            },
            "x": {
              "type": "integer",
              "description": "The value of the first number"
            },
            "y": {
              "type": "integer",
              "description": "The value of the second number"
            }
          },
          "required": ["operation", "x", "y"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "read_file",
        "description": "A function to read files. The files it reads will always be in the current directory.",
        "parameters": {
          "type": "object",
          "properties": {
            "filename": {
              "type": "string",
              "description": "The name of the file to read from"
            },
          },
          "required": ["filename"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "create_folder",
        "description": "A function to create folders.",
        "parameters": {
          "type": "object",
          "properties": {
            "foldername": {
              "type": "string",
              "description": "The name of the folder to create"
            },
          },
          "required": ["foldername"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "create_file",
        "description": "A function to create files with its contents.",
        "parameters": {
          "type": "object",
          "properties": {
            "filename": {
              "type": "string",
              "description": "The name of the file to create"
            },
            "content": {
              "type": "string",
              "description": "The contents of the file"
            },
          },
          "required": ["filename", "content"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "process_virustotal_output",
        "description": "Process VirusTotal API output to provide elaboration and solutions.",
        "parameters": {
          "type": "object",
          "properties": {
            "api_output": {
              "type": "string",
              "description": "The JSON string output from VirusTotal API."
            }
          },
          "required": ["api_output"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "ioc_extractor_tool",
        "description": "Extract Indicators of Compromise (IOCs) from text input using IoCExtractTool.",
        "parameters": {
          "type": "object",
          "properties": {
            "text": {
              "type": "string",
              "description": "The text input to extract IOCs from."
            }
          },
          "required": ["text"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "vt_file",
        "description": "Scan a file using VirusTotal API and return the JSON response.",
        "parameters": {
          "type": "object",
          "properties": {
            "file_path": {
              "type": "string",
              "description": "The path to the file to scan."
            }
          },
          "required": ["file_path"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "vt_url",
        "description": "Scan a URL using VirusTotal API and return the JSON response.",
        "parameters": {
          "type": "object",
          "properties": {
            "url_to_scan": {
              "type": "string",
              "description": "The URL to scan."
            }
          },
          "required": ["url_to_scan"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "save_output_to_json",
        "description": "Save output content to a JSON file.",
        "parameters": {
          "type": "object",
          "properties": {
            "filename": {
              "type": "string",
              "description": "The name of the JSON file to save."
            },
            "content": {
              "type": "string",
              "description": "The content to save in JSON format."
            }
          },
          "required": ["filename", "content"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "save_output_to_word",
        "description": "Save output content to a Word document.",
        "parameters": {
          "type": "object",
          "properties": {
            "filename": {
              "type": "string",
              "description": "The name of the Word document to save."
            },
            "content": {
              "type": "string",
              "description": "The content to save in the Word document."
            }
          },
          "required": ["filename", "content"]
        }
      }
    },
    {
      "type": "function",
      "function": {
        "name": "save_output_to_pdf",
        "description": "Save output content to a PDF file.",
        "parameters": {
          "type": "object",
          "properties": {
            "filename": {
              "type": "string",
              "description": "The name of the PDF file to save."
            },
            "content": {
              "type": "string",
              "description": "The content to save in the PDF file."
            }
          },
          "required": ["filename", "content"]
        }
      }
    }
]
