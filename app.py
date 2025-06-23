# ✅ app.py — Full MVP with GPT Summary, PDF, Email, SoD, Audit Logs

import streamlit as st
import pandas as pd
import hashlib
import datetime
import base64
import os
import glob
from fpdf import FPDF
from openai import OpenAI
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
import matplotlib.pyplot as plt
import seaborn as sns

# --- LOGIN SYSTEM ---
USER_CREDENTIALS = {
    "admin": "audit123",
    "client": "secure2024"
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login():
    st.sidebar.title("🔐 Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        if username in USER_CREDENTIALS and hash_password(password) == hash_password(USER_CREDENTIALS[username]):
            st.session_state["authenticated"] = True
            st.session_state["username"] = username
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid username or password")

if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    login()
    st.stop()

# --- PAGE SETUP ---
st.set_page_config(page_title="AuditProof.AI", page_icon="🛡️")
st.title("🛡️ AuditProof.AI")
st.subheader("AI-Powered SAP Audit Assistant with Tamper-Proof Verification")
# --- LOGIN SYSTEM ---
USER_CREDENTIALS = {
    "admin": "audit123",
    "client": "secure2024"
}

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login():
    st.sidebar.title("🔐 Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        if username in USER_CREDENTIALS and hash_password(password) == hash_password(USER_CREDENTIALS[username]):
            st.session_state["authenticated"] = True
            st.session_state["username"] = username
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid username or password")

# --- SECURE CHECK ---
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    login()
    st.stop()


# --- ENV SETUP ---
os.makedirs("archive/uploads", exist_ok=True)
os.makedirs("archive/reports", exist_ok=True)
os.makedirs("archive/logs", exist_ok=True)

# --- INPUTS ---
openai_api_key = st.text_input("🔑 Enter your OpenAI API Key", type="password")
user_email = st.text_input("📧 Enter email to receive report (optional)")
sod_rules_file = st.file_uploader("📥 Upload SoD Ruleset (CSV)", type=["csv"])

sod_df = None
if sod_rules_file:
    try:
        sod_df = pd.read_csv(sod_rules_file)
        st.success(f"✅ Loaded {len(sod_df)} SoD rules.")
        st.dataframe(sod_df.head())
    except Exception as e:
        st.error(f"❌ Failed to load SoD ruleset: {e}")

# --- HELPERS ---
def strip_unicode(text):
    return text.encode("ascii", "ignore").decode()

def save_activity_log(user, filename, action):
    log_path = "archive/logs/activity_log.csv"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = pd.DataFrame([[now, user, filename, action]], columns=["Timestamp", "User", "File", "Action"])
    if os.path.exists(log_path):
        existing = pd.read_csv(log_path)
        log_df = pd.concat([existing, entry], ignore_index=True)
    else:
        log_df = entry
    log_df.to_csv(log_path, index=False)

def show_risk_dashboard(df):
    if "Risk Category" in df.columns:
        st.subheader("📊 Risk Category Dashboard")
        fig, ax = plt.subplots()
        sns.countplot(x="Risk Category", data=df, palette="Set2", ax=ax)
        ax.set_title("Distribution by Risk Category")
        st.pyplot(fig)

        if "TCode" in df.columns:
            st.subheader("📌 Top Transaction Codes")
            tcode_counts = df["TCode"].value_counts().head(5)
            st.bar_chart(tcode_counts)
    else:
        st.info("Upload data with 'Risk Category' column to see dashboard.")

def generate_pdf(summary, file_hash, file_name, violations=None):
    pdf = FPDF()
    pdf.add_page()
    try:
        pdf.image("assets/logo.png", x=10, y=8, w=33)
    except:
        pdf.set_font("Arial", "I", 10)
        pdf.set_text_color(255, 0, 0)
        pdf.cell(0, 10, "Logo not found - skipped", ln=True)

    pdf.set_xy(50, 10)
    pdf.set_font("Arial", "B", 16)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(100, 10, "AuditProof.AI - SAP Audit Report", ln=True)

    pdf.set_xy(10, 30)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"File: {file_name}", ln=True)
    pdf.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Audit Findings:", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.multi_cell(0, 10, strip_unicode(summary))
    pdf.ln(5)

    if violations is not None and not violations.empty:
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Detected SoD Violations:", ln=True)
        pdf.set_font("Arial", "", 10)
        for _, row in violations.iterrows():
            line = f"User: {row['User ID']} | TCode: {row['TCode']} | Risk: {row['Risk Level']} | Desc: {row['Description']}"
            pdf.multi_cell(0, 10, strip_unicode(line))

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Tamper-Proof File Hash (SHA256):", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.multi_cell(0, 10, strip_unicode(file_hash))

    return pdf.output(dest='S').encode('latin-1')

def send_email_with_attachment(to_email, subject, body, attachment_bytes, filename):
    try:
        from_email = "auditbot.ai@gmail.com"
        app_password = "nzsf ycfr ijap ozyt"
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        attachment = MIMEApplication(attachment_bytes, _subtype="pdf")
        attachment.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(attachment)
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(from_email, app_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        st.error(f"📧 Email sending failed: {e}")
        return False
# --- FILE UPLOAD ---
uploaded_file = st.file_uploader("📤 Upload your SAP audit report (.csv or .xlsx)", type=['csv', 'xlsx'])

if uploaded_file:
    file_name = uploaded_file.name
    st.success(f"✅ File Uploaded: {file_name}")

    try:
        if file_name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)

        st.subheader("📋 File Preview:")
        st.dataframe(df.head(10))

        uploaded_file.seek(0)
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        st.subheader("🔐 Tamper-Proof File Hash:")
        st.code(file_hash)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(file_name)[0]
        upload_path = f"archive/uploads/{base_name}_{timestamp}.csv"
        with open(upload_path, "wb") as f:
            f.write(file_bytes)

        save_activity_log(st.session_state["username"], file_name, "Uploaded")
   


        # --- SOD CHECK ---
        violations = pd.DataFrame()
        if sod_df is not None:
            st.subheader("🔍 SoD Violation Check:")
            merged = pd.merge(df, sod_df, how="inner", left_on="TCode", right_on="TCode")
            violations = merged[merged["Status"] == "Active"]
            if not violations.empty:
                st.dataframe(violations[["User ID", "TCode", "Authorization Object_x", "Risk Level", "Description", "Risk Type", "Business Process"]].rename(columns={"Authorization Object_x": "Authorization Object"}))
            else:
                st.success("✅ No SoD violations found.")

                # --- GPT SUMMARY ---
        ai_summary = ""
        if openai_api_key:
            try:
                client = OpenAI(api_key=openai_api_key)

                # Defensive check: make sure data exists
                if df.empty:
                    st.warning("⚠️ Uploaded file is empty or invalid for audit.")
                else:
                    df_summary = df.to_markdown(index=False)

                    prompt = f"""
You are an SAP security audit assistant. Review this SAP user access log.

Provide:
1. Row-wise access risk analysis
2. Mention critical TCodes (e.g. FB60, SU01)
3. Identify potential SoD (Segregation of Duties) violations
4. End with a short executive summary

Access log:
{df_summary}
"""

                    with st.spinner("🧠 GPT analyzing SAP log..."):
                        response = client.chat.completions.create(
                            model="gpt-3.5-turbo",
                            messages=[
                                {"role": "system", "content": "You are a security auditor for SAP logs."},
                                {"role": "user", "content": prompt}
                            ],
                            temperature=0.3
                        )

                        ai_summary = response.choices[0].message.content.strip()

                    if not ai_summary:
                        st.warning("⚠️ GPT did not return any analysis.")
                        st.text("🧪 Prompt sent:")
                        st.code(prompt)
                    else:
                        st.subheader("🧠 GPT Audit Summary:")
                        st.success(ai_summary)

            except Exception as e:
                st.error(f"❌ OpenAI Error: {e}")
                ai_summary = "⚠️ GPT summary failed. Please check your key or retry."
        else:
            ai_summary = "**Mock Summary:**\n- SAPUSER1 has FB60 (High Risk)\n- SAPUSER2 uses ME21N (Medium Risk)\n- SAPUSER3 has VA01 + S_DATASET (SoD Violation)"

        if not ai_summary.startswith("⚠️"):
            st.subheader("🧠 GPT Audit Summary:")
            st.success(ai_summary)

        pdf_bytes = generate_pdf(ai_summary, file_hash, file_name, violations)
        pdf_path = f"archive/reports/{base_name}_{timestamp}.pdf"
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)

        b64 = base64.b64encode(pdf_bytes).decode()
        st.subheader("📥 Download PDF Report:")
        st.markdown(f"""
            <a href="data:application/octet-stream;base64,{b64}" download="{base_name}_{timestamp}.pdf">
                <button style="padding:10px; border:none; background:#4CAF50; color:white; border-radius:5px;">
                    ⬇️ Download PDF
                </button>
            </a>
        """, unsafe_allow_html=True)

        # --- EMAIL DELIVERY ---
        if user_email:
            with st.spinner("📧 Sending report via email..."):
                sent = send_email_with_attachment(
                    to_email=user_email,
                    subject="Your AuditProof.AI SAP Report",
                    body="Attached is your audit report from AuditProof.AI.",
                    attachment_bytes=pdf_bytes,
                    filename=os.path.basename(pdf_path)
                )
                if sent:
                    st.success(f"✅ Sent to {user_email}")

    except Exception as e:
        st.error(f"❌ Error processing file: {e}")

# --- AUDIT DASHBOARD ---
st.markdown("---")
st.subheader("📊 App Dashboard")

def count_files(folder, ext):
    return len(glob.glob(f"{folder}/*.{ext}"))

num_reports = count_files("archive/reports", "pdf")
num_uploads = count_files("archive/uploads", "csv")

upload_files = sorted(glob.glob("archive/uploads/*.csv"), key=os.path.getmtime)
last_upload_time = datetime.datetime.fromtimestamp(os.path.getmtime(upload_files[-1])).strftime('%Y-%m-%d %H:%M:%S') if upload_files else "—"

col1, col2 = st.columns(2)
col1.metric("📄 Reports", num_reports)
col2.metric("📥 Uploads", num_uploads)
st.info(f"🕒 Last upload: {last_upload_time}")

# --- ACTIVITY LOG ---
log_file = "archive/logs/activity_log.csv"
if os.path.exists(log_file):
    st.markdown("---")
    st.subheader("📌 Recent Activity Log")
    logs_df = pd.read_csv(log_file).tail(10)
    st.dataframe(logs_df)

# --- REPORT HISTORY ---
st.markdown("---")
st.subheader("📁 Archived Reports")
report_files = sorted(os.listdir("archive/reports"), reverse=True)
if report_files:
    for report in report_files:
        report_path = f"archive/reports/{report}"
        with open(report_path, "rb") as f:
            b64_report = base64.b64encode(f.read()).decode()
        st.markdown(f"""
            <p>{report}</p>
            <a href="data:application/octet-stream;base64,{b64_report}" download="{report}">
                <button style="margin-bottom:10px;">⬇️ Download</button>
            </a>
        """, unsafe_allow_html=True)
else:
    st.info("No reports available yet.")

# --- AUDIT HASH VALIDATION ---
st.markdown("---")
st.subheader("📁 Audit Log Validation")
existing_uploads = sorted(glob.glob("archive/uploads/*.csv"), key=os.path.getmtime, reverse=True)
if existing_uploads:
    latest = existing_uploads[0]
    st.info(f"Most recent file: {os.path.basename(latest)}")
    with open(latest, "rb") as f:
        hash_val = hashlib.sha256(f.read()).hexdigest()
        st.code(hash_val, language="text")
    st.caption("Use this hash to confirm your log file wasn't tampered with after upload.")
else:
    st.warning("No audit files uploaded yet.")

