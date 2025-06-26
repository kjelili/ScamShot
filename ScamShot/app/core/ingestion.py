import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY")

def scan_file(file_path):
    with open(file_path, "rb") as f:
        response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers={"x-apikey": VT_API_KEY},
            files={"file": (os.path.basename(file_path), f)}
        )
        if response.status_code == 200:
            result = response.json()
            analysis_id = result["data"]["id"]
            # Poll the analysis result
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(10):
                res = requests.get(analysis_url, headers={"x-apikey": VT_API_KEY})
                data = res.json()
                if data["data"]["attributes"]["status"] == "completed":
                    stats = data["data"]["attributes"]["stats"]
                    if stats["malicious"] > 0:
                        return "❌ Infected"
                    return "✅ Clean"
            return "❌ Timed Out"
        return "❌ Upload Failed"
from app.utils.alerts import send_slack_alert, send_email_alert

def handle_uploaded_attachment(file_path, email_address=None):
    scan_result = scan_file(file_path)

    if "Infected" in scan_result:
        msg = f"❌ Threat detected in file: {os.path.basename(file_path)}\nResult: {scan_result}"
        if email_address:
            msg += f"\nReported from: {email_address}"
        send_slack_alert(msg)
        send_email_alert("Scamshot Alert - Infected File", msg)

        # Optionally quarantine file (move to a separate directory)
        quarantine_dir = "quarantine"
        os.makedirs(quarantine_dir, exist_ok=True)
        os.rename(file_path, os.path.join(quarantine_dir, os.path.basename(file_path)))
        return "❌ Infected"

    return "✅ Clean"
