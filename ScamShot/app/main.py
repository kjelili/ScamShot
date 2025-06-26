import streamlit as st
from config import settings
from app.core.detector import EmailAnalyzer
from app.core.security import rate_limit
import redis

# Initialize services
analyzer = EmailAnalyzer()
r = redis.Redis.from_url(settings.REDIS_URL)

@rate_limit(r, "user_ip", settings.RATE_LIMIT)
def main():
    st.set_page_config(page_title="ScamGuard Pro", layout="wide")
    
    # Enterprise-grade UI
    with st.container():
        st.title("🔒 ScamGuard Enterprise Email Security")
        st.markdown("""
            <style>
            .stAlert { padding: 20px; border-radius: 10px; }
            .high-risk { background-color: #ff4444!important; }
            </style>
        """, unsafe_allow_html=True)
        
    # Advanced file upload
    email_data = st.file_uploader("Upload Email", type=["eml", "msg"],
                                 help="Supported formats: .eml, .msg")
    
    if email_data:
        with st.spinner("Analyzing with enterprise-grade security..."):
            try:
                analysis = analyzer.analyze(parse_email(email_data))
                display_results(analysis)
                log_analysis(analysis)
            except Exception as e:
                st.error(f"Security analysis failed: {str(e)}")
                send_alert_to_admins(e)

def display_results(analysis: dict):
    # Professional dashboard with multiple tabs
    tab1, tab2, tab3 = st.tabs(["Summary", "Technical Details", "Threat Intelligence"])
    
    with tab1:
        col1, col2 = st.columns([1, 3])
        with col1:
            display_risk_score(analysis["risk_score"])
        with col2:
            display_threat_matrix(analysis)
    
    with tab2:
        show_technical_analysis(analysis)
    
    with tab3:
        show_threat_intel(analysis)

if __name__ == "__main__":
    main()