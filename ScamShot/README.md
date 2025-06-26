# 🛡️ Scamshot — Threat Intelligence & Anti-Phishing Scanner

**Scamshot** is a full-stack AI-driven application that detects scam emails, malicious attachments, and phishing links using:
- 📎 ClamAV scanning
- 🌐 VirusTotal + PhishTank threat intelligence
- 📡 Gmail & Telegram file ingestion
- 🧠 AI classification and feedback loop
- 💬 Slack/email alerts
- 📊 Streamlit dashboard

---

## 🚀 Features

- ✅ **Attachment Scanning** (ClamAV integration)
- 🌍 **URL Intelligence Check** (VirusTotal, PhishTank)
- 📬 **Gmail Bot** for incoming threats
- 💬 **Telegram Bot** for mobile forwarding
- 📈 **Crowdsourced Reporting Dashboard**
- 🧠 **ML Feedback Loop** with auto-retraining
- ☁️ **Docker & Render Ready**
- 📊 Streamlit-based preview/report interface
- 📤 Slack + Email alerting

---

## 🐳 Local Development

1. **Clone & unzip:**
   ```bash
   git clone https://github.com/kjelili/Scamshot.git
   cd Scamshot
   ```

2. **Setup environment variables:**
   ```bash
   cp .env.template .env
   ```

3. **Run with Docker Compose:**
   ```bash
   docker-compose up --build
   ```

4. **Access Dashboard**:  
   [http://localhost:8501](http://localhost:8501)

---

## ☁️ Deploy on Render

1. Push to your GitHub repo
2. Login to [https://render.com](https://render.com) and click **New Web Service**
3. Select your repo, use:
   - **Docker** as environment
   - `render.yaml` for setup
4. Add environment variables from `.env`

---

## 🔐 Environment Variables (.env)

```
OPENAI_API_KEY=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE_NUMBER=
GMAIL_USER=
GMAIL_PASS=
TELEGRAM_BOT_TOKEN=
VIRUSTOTAL_API_KEY=
PHISHTANK_API_KEY=
SLACK_WEBHOOK_URL=
ALERT_EMAIL=
SMTP_SERVER=
SMTP_USER=
SMTP_PASS=
```

---

## 🧪 How to Test

| Feature                | Test Method                                         |
|------------------------|-----------------------------------------------------|
| Attachment Scanning    | Upload EICAR test file via UI/Telegram              |
| URL Checks             | Submit known phishing URL                           |
| Telegram Forwarding    | Send file to bot, check Streamlit scan result       |
| Gmail Ingestion        | Email with doc to inbox, monitor if processed       |
| Alerting               | Expect Slack + Email on threat detection            |
| Retraining             | Run `python cron/retrain_model.py`                 |
| Dashboard              | Review infection status, CSV export                 |

---

## 📂 Project Structure

```
scamshot/
├── app/
│   ├── core/             # AI, scanning, threat intel
│   ├── mobile_forwarding/
│   ├── ui/
│   └── utils/
├── cron/                 # Auto-retraining logic
├── scripts/              # CLI tools
├── data/                 # Sample/testing data
├── Dockerfile
├── render.yaml
├── .env.template
```

---

## 📜 License
MIT License

## 👥 Contributors
Maintained by [@kjelili](https://github.com/kjelili) and contributors

## 📌 Changelog
See `CHANGELOG.md` for feature additions and patch logs.