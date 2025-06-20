import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
from fpdf import FPDF
import base64
import os

st.set_page_config(page_title="Network Intrusion Detector", page_icon="🛡️", layout="centered")

st.image("images/intrusion_logo.jpg", use_column_width=True)

@st.cache_resource
def load_assets():
    model = joblib.load("gb_model_final.pkl")
    scaler = joblib.load("scaler_final.pkl")
    with open("feature_columns.json") as f:
        feature_columns = json.load(f)
    return model, scaler, feature_columns

model, scaler, feature_columns = load_assets()

st.title("🛡️ Network Intrusion Detection System")
st.markdown("Enter known traffic features below. The rest will be filled with default values (0).")

# User input fields for top 15 known features
user_input = {}
col1, col2 = st.columns(2)

with col1:
    user_input['src_bytes'] = st.number_input("Source Bytes", min_value=0)
    user_input['same_srv_rate'] = st.slider("Same Service Rate", 0.0, 1.0, 0.5)
    user_input['flag_SF'] = st.selectbox("Flag SF", [0, 1])
    user_input['level'] = st.number_input("Level", min_value=0)
    user_input['count'] = st.number_input("Count", min_value=0)
    user_input['logged_in'] = st.selectbox("Logged In", [0, 1])
    user_input['dst_host_diff_srv_rate'] = st.slider("Host Diff SRV Rate", 0.0, 1.0, 0.5)

with col2:
    user_input['dst_bytes'] = st.number_input("Destination Bytes", min_value=0)
    user_input['dst_host_same_srv_rate'] = st.slider("Host Same Service Rate", 0.0, 1.0, 0.5)
    user_input['dst_host_srv_serror_rate'] = st.slider("Host SRV Serror Rate", 0.0, 1.0, 0.5)
    user_input['diff_srv_rate'] = st.slider("Different SRV Rate", 0.0, 1.0, 0.5)
    user_input['dst_host_srv_count'] = st.number_input("Host SRV Count", min_value=0)
    user_input['serror_rate'] = st.slider("Serror Rate", 0.0, 1.0, 0.5)
    user_input['protocol_type_icmp'] = st.selectbox("Protocol ICMP", [0, 1])

# Safe string conversion
def safe_str(text):
    return str(text).encode('latin-1', 'ignore').decode('latin-1')

# PDF report generation
def generate_pdf_report(data_dict, result):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Network Intrusion Detection Report", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.ln(10)
    pdf.cell(200, 10, safe_str(f"Prediction Result: {result}"), ln=True)
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, "Entered Features:", ln=True)
    pdf.set_font("Arial", size=12)
    for k, v in data_dict.items():
        pdf.cell(200, 10, safe_str(f"{k}: {v}"), ln=True)
    pdf.output("intrusion_report.pdf")

if st.button("🔍 Predict Intrusion"):
    # Create full input dict with all features = 0
    full_input = {feature: 0 for feature in feature_columns}
    full_input.update(user_input)

    # Create DataFrame
    input_df = pd.DataFrame([full_input])

    # Scale and predict
    scaled_input = scaler.transform(input_df)
    prediction = model.predict(scaled_input)[0]

    # Result
    result = "✅ Normal Traffic" if prediction == 0 else "🚨 Attack Detected"
    st.subheader(f"Prediction: {result}")

    # Generate and download PDF
    generate_pdf_report(user_input, result)
    with open("intrusion_report.pdf", "rb") as f:
        b64_pdf = base64.b64encode(f.read()).decode("utf-8")
        st.markdown(
            f'<a href="data:application/pdf;base64,{b64_pdf}" download="Intrusion_Report.pdf">📥 Download Report</a>',
            unsafe_allow_html=True
        )
