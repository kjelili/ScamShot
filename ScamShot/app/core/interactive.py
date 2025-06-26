# scamguard_streamlit.py
import streamlit as st
import re
import tldextract
from textstat import flesch_reading_ease
import nltk
from nltk.sentiment import SentimentIntensityAnalyzer
import requests
from email import policy
from email.parser import BytesParser
import pandas as pd
import os
from dotenv import load_dotenv

# Initialize environment variables
load_dotenv()

# Initialize ClamAV scanner

# Initialize NLTK
nltk.download('vader_lexicon')
sia = SentimentIntensityAnalyzer()

# Configure Streamlit
st.set_page_config(page_title="ScamGuard - Email Fraud Detector", layout="wide")

def check_sender_address(email_from):
    """Analyze sender email domain"""
    domain = email_from.split('@')[-1]
    extracted = tldextract.extract(domain)
    return {
        'domain': domain,
        'is_suspicious': not (extracted.registered_domain == domain),
        'typosquatting_score': sum(1 for c in domain if c in ['0', '1', 'l'])/len(domain)
    }

def check_links(content):
    """Extract and analyze URLs in content"""
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)
    suspicious_urls = []
    
    for url in urls:
        domain = tldextract.extract(url).registered_domain
        if domain in KNOWN_PHISHING_DOMAINS:
            suspicious_urls.append(url)
        # Placeholder for VirusTotal API check
        # response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": os.getenv('VIRUSTOTAL_API')})
    
    return {
        'total_links': len(urls),
        'suspicious_links': suspicious_urls,
        'shortened_links': [url for url in urls if 'bit.ly' in url or 'tinyurl' in url]
    }

def analyze_content(content):
    """Perform NLP analysis on email content"""
    readability = flesch_reading_ease(content)
    sentiment = sia.polarity_scores(content)
    
    return {
        'readability_score': readability,
        'urgency_keywords': len(re.findall(r'\b(urgent|immediately|alert|action required)\b', content, re.I)),
        'threat_keywords': len(re.findall(r'\b(fine|suspended|legal|police)\b', content, re.I)),
        'sentiment': sentiment
    }

def scan_attachments(email):
    """Check attachments for malware"""
    malware_results = []
    for part in email.iter_attachments():
        if part.get_filename():
            result = cd.instream(part.get_payload(decode=True))
            malware_results.append({
                'filename': part.get_filename(),
                'malware_detected': result['stream'][1] == 'FOUND'
            })
    return malware_results

def calculate_risk_score(analysis):
    """Calculate overall risk score"""
    score = 0
    if analysis['sender']['is_suspicious']: score += 30
    if analysis['links']['suspicious_links']: score += 20 * len(analysis['links']['suspicious_links'])
    if analysis['content']['urgency_keywords'] > 3: score += 25
    if analysis['attachments']: score += 35
    return min(score, 100)

# Streamlit UI
st.title("🛡️ ScamGuard - Email Fraud Detector")
st.write("Upload an email (.eml) or paste content to analyze for potential scams")

upload_method = st.radio("Select input method:", ("Upload .eml file", "Paste email content"))

email_content = ""
email = None

if upload_method == "Upload .eml file":
    uploaded_file = st.file_uploader("Choose an .eml file", type="eml")
    if uploaded_file:
        email = BytesParser(policy=policy.default).parse(uploaded_file)
        email_content = email.get_body(preferencelist=('plain')).get_content()
else:
    email_content = st.text_area("Paste email content here:", height=200)

if st.button("Analyze Email") and email_content:
    with st.spinner("Analyzing email..."):
        # Perform analysis
        analysis = {
            'sender': check_sender_address("test@amaz0n.com"),  # Replace with actual email from
            'links': check_links(email_content),
            'content': analyze_content(email_content),
            'attachments': scan_attachments(email) if email else []
        }
        
        risk_score = calculate_risk_score(analysis)
        
        # Display results
        st.subheader("Analysis Results")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Overall Risk Score", f"{risk_score}%", 
                    help="Higher score indicates higher likelihood of scam")
            
        with col2:
            if risk_score > 70:
                st.error("⚠️ High probability of scam")
            elif risk_score > 40:
                st.warning("⚠️ Moderate risk detected")
            else:
                st.success("✅ Low risk detected")
        
        # Detailed findings
        with st.expander("Detailed Red Flags"):
            red_flags = []
            
            if analysis['sender']['is_suspicious']:
                red_flags.append("Suspicious sender domain")
                
            if analysis['links']['suspicious_links']:
                red_flags.append(f"{len(analysis['links']['suspicious_links']} suspicious links found")
                
            if analysis['content']['urgency_keywords'] > 3:
                red_flags.append("High urgency language detected")
                
            if analysis['attachments']:
                red_flags.append("Potentially dangerous attachments")
            
            df = pd.DataFrame({"Red Flags": red_flags})
            st.dataframe(df, use_container_width=True)
        
        # Technical details
        with st.expander("Technical Analysis"):
            st.write("### Sender Analysis")
            st.json(analysis['sender'])
            
            st.write("### Link Analysis")
            st.json(analysis['links'])
            
            st.write("### Content Analysis")
            st.json(analysis['content'])

# Sidebar configuration
with st.sidebar:
    st.header("Configuration")
    VIRUSTOTAL_API = st.text_input("VirusTotal API Key", type="password")
    GOOGLE_SAFE_BROWSING_API = st.text_input("Google Safe Browsing API Key", type="password")
    st.info("Add API keys for enhanced detection capabilities")

# How to Run:
# 1. Install requirements: pip install -r requirements.txt
# 2. Run Streamlit: streamlit run scamguard_streamlit.py