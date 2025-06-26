import re
import tldextract
from textstat import flesch_reading_ease
from nltk.sentiment import SentimentIntensityAnalyzer
from typing import Dict, Any
from config import settings

class EmailAnalyzer:
    def __init__(self):
        self.sia = SentimentIntensityAnalyzer()
        self.extractor = tldextract.TLDExtract()
        
    def analyze(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        analysis = {
            "sender": self._analyze_sender(email_data["from"]),
            "content": self._analyze_content(email_data["body"]),
            "links": self._analyze_links(email_data["body"]),
            "attachments": self._analyze_attachments(email_data.get("attachments", []))
        }
        analysis["risk_score"] = self._calculate_risk(analysis)
        return analysis

    def _analyze_sender(self, email_from: str) -> Dict[str, Any]:
        # SPF/DKIM validation logic here
        domain = email_from.split("@")[-1]
        return {
            "domain": domain,
            "spf_valid": self._check_spf(domain),
            "dkim_valid": self._check_dkim(domain),
            "typosquatting_score": self._calculate_typosquatting(domain)
        }
    
    # Additional analysis methods...