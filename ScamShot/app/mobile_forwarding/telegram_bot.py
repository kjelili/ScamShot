from flask import Flask, request
import os

app = Flask(__name__)
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_CHAT_ID = os.getenv("TELEGRAM_ADMIN_CHAT_ID")

@app.route(f"/{TELEGRAM_TOKEN}", methods=["POST"])
def webhook():
    data = request.get_json()
    message = data.get("message", {}).get("text", "")
    sender = data.get("message", {}).get("from", {}).get("username", "")
    if message:
        print(f"Scam report from @{sender}: {message}")
    return "OK", 200
