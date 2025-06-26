import os
import requests
import smtplib
from email.message import EmailMessage

def send_slack_alert(message):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if webhook_url:
        requests.post(webhook_url, json={"text": message})

def send_email_alert(subject, content):
    email = os.getenv("ALERT_EMAIL")
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if not all([email, smtp_server, smtp_user, smtp_pass]):
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = email
    msg.set_content(content)
    with smtplib.SMTP_SSL(smtp_server, 465) as smtp:
        smtp.login(smtp_user, smtp_pass)
        smtp.send_message(msg)
