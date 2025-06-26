import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="Scamshot Threat Report", layout="wide")
st.title("📊 Scamshot Threat Analysis Dashboard")

report_file = "reports/report_log.csv"
if not os.path.exists(report_file):
    st.warning("No reports found yet.")
else:
    df = pd.read_csv(report_file)
    df['threat_level'] = df['scan_status'].apply(lambda x: "High ❌" if "Infected" in x else "Low ✅")
    st.dataframe(df, use_container_width=True)
    st.download_button("Download CSV", df.to_csv(index=False), "scamshot_report.csv")
