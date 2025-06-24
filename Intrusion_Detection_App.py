import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json

st.set_page_config(page_title="Network Intrusion Detector", page_icon="🛡️", layout="centered")

# Sidebar navigation
page = st.selectbox("Navigate", ["🔍 Detection", "ℹ️ About"])

# Display logo
st.image("images/intrusion_logo.jpg", use_container_width=True)

@st.cache_resource
def load_assets():
    model = joblib.load("gb_model_final.pkl")
    scaler = joblib.load("scaler_final.pkl")
    with open("feature_columns.json") as f:
        feature_columns = json.load(f)
    return model, scaler, feature_columns

model, scaler, feature_columns = load_assets()

# Detection page
if page == "🔍 Detection":
    st.title("🛡️ Network Intrusion Detection System")
    st.markdown("Enter known traffic features below. The rest will be filled with default values (0).")

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

    if st.button("🔍 Predict Intrusion"):
        full_input = {feature: 0 for feature in feature_columns}
        full_input.update(user_input)

        input_df = pd.DataFrame([full_input])
        scaled_input = scaler.transform(input_df)
        prediction = model.predict(scaled_input)[0]

        result = "✅ Normal Traffic" if prediction == 0 else "🚨 Attack Detected"
        st.subheader(f"Prediction: {result}")

# About page
elif page == "ℹ️ About":
    st.title("ℹ️ About This Project")
    st.markdown('''
**Network Intrusion Detection System** is a machine learning-powered app designed to detect malicious activity 
in network traffic using Gradient Boosting.

Trained on preprocessed KDD dataset features, it provides accurate, fast, and interpretable detection of potential threats.

- 🛡️ **Model**: Gradient Boosting (F1 ≈ 0.84, AUC ≈ 0.97)  
- 👩🏽‍💻 **Developer**: Olaide Kareem  
- 🏛️ **Institution**: Caleb University  
- 📌 **Purpose**: Data + AI for Cybersecurity Impact
''')
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>Made with 🔐 by Olaide Kareem | Powered by Streamlit + Gradient Boosting</div>",
        unsafe_allow_html=True
    )
