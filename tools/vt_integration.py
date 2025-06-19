import vt
import requests
import os
from typing import Optional, Dict, Any
from utils.output import Result, Status, display_results
from utils.config import config

__all__ = ['VTAnalyzer']

class VTAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.client = None

    def __enter__(self):
        if not self.api_key:
            raise ValueError("Missing VirusTotal API key")
        self.client = vt.Client(self.api_key)
        return self

    def __exit__(self, *args):
        if self.client:
            self.client.close()

    def file_report(self, file_hash: str) -> Result:
        try:
            file = self.client.get_object(f"/files/{file_hash}")
            return Result(
                status=Status.SUCCESS,
                data={
                    "sha256": file.sha256,
                    "malicious": file.last_analysis_stats["malicious"],
                    "analysis": file.last_analysis_results
                }
            )
        except vt.APIError as e:
            return Result(status=Status.ERROR, message=str(e))

    def scan_url(self, url: str) -> Result:
        import time
        try:
            if not self.api_key:
                return Result(status=Status.ERROR, message="VirusTotal API key is missing.")
            if not url:
                return Result(status=Status.ERROR, message="Invalid URL provided for scanning.")
            api_key = self.api_key
            headers = {
                "x-apikey": api_key,
                "Content-Type": "application/x-www-form-urlencoded"
            }
            # Submit URL for scanning using form data
            response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url}
            )
            response.raise_for_status()
            response_json = response.json()
            analysis_id = response_json["data"]["id"]
            # Poll for analysis report
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(10):
                analysis_response = requests.get(analysis_url, headers={"x-apikey": api_key})
                analysis_response.raise_for_status()
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    break
                time.sleep(3)
            else:
                return Result(status=Status.ERROR, message="Analysis timed out")
            return Result(
                status=Status.SUCCESS,
                data={
                    "id": analysis_id,
                    "status": status,
                    "url": url,
                    "analysis": analysis_data
                }
            )
        except (vt.APIError, requests.RequestException) as e:
            return Result(status=Status.ERROR, message=str(e))

    def scan_file(self, file_path: str, wait_for_analysis: bool = False) -> Result:
        import time
        try:
            if not self.api_key:
                return Result(status=Status.ERROR, message="VirusTotal API key is missing.")
            if not file_path or not os.path.isfile(file_path):
                return Result(status=Status.ERROR, message="Invalid file path provided for scanning.")
            api_key = self.api_key
            headers = {
                "x-apikey": api_key
            }
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                response = requests.post(
                    "https://www.virustotal.com/api/v3/files",
                    headers=headers,
                    files=files
                )
            response.raise_for_status()
            response_json = response.json()
            # Debug logging of full response
            print("VirusTotal API response:", response_json)
            analysis_id = response_json.get("data", {}).get("id")
            if analysis_id is None:
                return Result(status=Status.ERROR, message=f"Unexpected API response: missing 'id'. Full response: {response_json}")
            if not wait_for_analysis:
                return Result(
                    status=Status.SUCCESS,
                    data={
                        "id": analysis_id,
                        "file_path": file_path,
                        "message": "File uploaded successfully. Analysis in progress."
                    }
                )
            # Poll for analysis report
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(20):
                analysis_response = requests.get(analysis_url, headers={"x-apikey": api_key})
                analysis_response.raise_for_status()
                analysis_data = analysis_response.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return Result(
                        status=Status.SUCCESS,
                        data={
                            "id": analysis_id,
                            "status": status,
                            "file_path": file_path,
                            "analysis": analysis_data
                        }
                    )
                time.sleep(6)
            return Result(status=Status.ERROR, message="Analysis timed out")
        except (vt.APIError, requests.RequestException) as e:
            return Result(status=Status.ERROR, message=str(e))
