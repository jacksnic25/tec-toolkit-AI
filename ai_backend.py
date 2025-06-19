import json
import iocextract
from tools.iocextract_tool import IoCExtractTool
import os
import configparser
import groq

# Load VirusTotal API key
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    try:
        config = configparser.ConfigParser()
        config.read("config.ini")
        VT_API_KEY = config.get("virustotal", "api_key", fallback="").strip()
        print(f"Loaded VirusTotal API key: {VT_API_KEY}")  # Debug log
    except Exception as e:
        print(f"Error loading VirusTotal API key: {e}")  # Debug log
        VT_API_KEY = None

if not VT_API_KEY:
    raise ValueError("VirusTotal API key not found. Please set VIRUSTOTAL_API_KEY environment variable or add it to config.ini under [virustotal] section with api_key.")

# Load Groq AI API key for AI model interaction
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
if not GROQ_API_KEY:
    try:
        config = configparser.ConfigParser()
        config.read("config.ini")
        GROQ_API_KEY = config.get("groq", "api_key", fallback="").strip()
        print(f"Loaded Groq AI API key: {GROQ_API_KEY}")  # Debug log
    except Exception as e:
        print(f"Error loading Groq AI API key: {e}")  # Debug log
        GROQ_API_KEY = None

if not GROQ_API_KEY:
    raise ValueError("Groq AI API key not found. Please set GROQ_API_KEY environment variable or add it to config.ini under [groq] section with api_key.")

client = groq.Groq(api_key=GROQ_API_KEY)

def process_virustotal_output(api_output: str):
    try:
        messages = [
            {"role": "system", "content": "You are a helpful AI assistant that analyzes VirusTotal scan results and provides elaboration, insights, and solutions."},
            {"role": "user", "content": api_output}
        ]
        response = client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile"
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Failed to process VirusTotal output: {str(e)}"

def ioc_extractor_tool(text: str):
    try:
        messages = [
            {"role": "system", "content": "You are a helpful AI assistant that analyzes extracted Indicators of Compromise (IOCs) and provides elaboration and insights."},
            {"role": "user", "content": text}
        ]
        response = client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile"
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Failed to extract IOCs: {str(e)}"

def email_ai_processing(text: str):
    try:
        messages = [
            {"role": "system", "content": "You are a helpful AI assistant that analyzes email analysis results and provides elaboration and insights."},
            {"role": "user", "content": text}
        ]
        response = client.chat.completions.create(
            messages=messages,
            model="llama-3.3-70b-versatile"
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Failed to process email analysis: {str(e)}"
