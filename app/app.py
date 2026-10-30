"""
SCAMLENS AI — Intelligent Scam and Phishing Detection System
Streamlit Web Application — Product-Level UI (Phase 9 Polish)
"""

import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import streamlit as st
import pandas as pd

from src.config import BASE_DIR, SAVED_MODELS_DIR, PROCESSED_DATA_DIR, RISK_CONFIG
from src.models.predictor import get_predictor, ScamLensPredictor
from src.utils.database import fetch_recent_scans

# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SCAMLENS AI — Intelligent Scam & Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State
if "nav_page" not in st.session_state:
    st.session_state["nav_page"] = "Dashboard"
if "analyzer_input" not in st.session_state:
    st.session_state["analyzer_input"] = ""


# -----------------------------------------------------------------------------
# Cached Model Loader
# -----------------------------------------------------------------------------
@st.cache_resource
def load_cached_predictor() -> ScamLensPredictor:
    """Load and cache ScamLensPredictor once to optimize performance."""
    return get_predictor()


# -----------------------------------------------------------------------------
# Custom CSS
# -----------------------------------------------------------------------------
def inject_custom_css():
    st.markdown("""
    <style>
    /* Layout */
    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1280px;
    }

    /* Brand Title */
    .brand-title {
        font-size: 2rem;
        font-weight: 800;
        color: #f1f5f9;
        letter-spacing: -0.02em;
        margin-bottom: 0.1rem;
        line-height: 1.2;
    }
    .brand-subtitle {
        color: #94a3b8;
        font-size: 1rem;
        margin-bottom: 1.4rem;
    }

    /* Hero Section */
    .hero-section {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid rgba(59, 130, 246, 0.25);
        border-radius: 16px;
        padding: 3rem 2.5rem;
        margin-bottom: 2rem;
        text-align: center;
    }
    .hero-logo {
        font-size: 3rem;
        font-weight: 900;
        color: #f1f5f9;
        letter-spacing: -0.03em;
        margin-bottom: 0.3rem;
    }
    .hero-logo span { color: #3b82f6; }
    .hero-tagline {
        font-size: 1.3rem;
        color: #93c5fd;
        font-style: italic;
        margin-bottom: 0.8rem;
    }
    .hero-desc {
        font-size: 1rem;
        color: #94a3b8;
        margin-bottom: 1.8rem;
        max-width: 520px;
        margin-left: auto;
        margin-right: auto;
    }

    /* Product Cards */
    .product-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.09);
        border-radius: 12px;
        padding: 1.1rem 1rem;
        min-height: 90px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        box-sizing: border-box;
        margin-bottom: 0.6rem;
    }
    .card-label {
        font-size: 0.7rem;
        font-weight: 700;
        letter-spacing: 0.07em;
        text-transform: uppercase;
        color: #64748b;
        margin-bottom: 0.3rem;
    }
    .card-value {
        font-size: 1rem;
        font-weight: 600;
        color: #e2e8f0;
        line-height: 1.3;
        white-space: normal !important;
        word-wrap: break-word !important;
        overflow-wrap: break-word !important;
    }

    /* Step Flow Cards */
    .step-card {
        background: rgba(59,130,246,0.05);
        border: 1px solid rgba(59,130,246,0.2);
        border-radius: 12px;
        padding: 1.2rem 0.9rem;
        text-align: center;
        min-height: 110px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        box-sizing: border-box;
    }
    .step-number { font-size: 1.6rem; margin-bottom: 0.25rem; }
    .step-title { font-size: 0.9rem; font-weight: 700; color: #e2e8f0; margin-bottom: 0.15rem; }
    .step-desc  { font-size: 0.78rem; color: #64748b; }

    /* Feature Highlight Cards */
    .feature-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1.4rem 1.2rem;
        text-align: center;
        box-sizing: border-box;
        min-height: 120px;
    }
    .feature-icon  { font-size: 1.8rem; margin-bottom: 0.5rem; }
    .feature-title { font-size: 0.95rem; font-weight: 700; color: #e2e8f0; margin-bottom: 0.2rem; }
    .feature-desc  { font-size: 0.78rem; color: #64748b; }

    /* Trust Section */
    .trust-section {
        background: rgba(34,197,94,0.05);
        border: 1px solid rgba(34,197,94,0.2);
        border-radius: 12px;
        padding: 1.4rem 1.8rem;
        margin-top: 1rem;
    }
    .trust-title { font-size: 1rem; font-weight: 700; color: #22c55e; margin-bottom: 0.7rem; }
    .trust-point { font-size: 0.88rem; color: #94a3b8; margin: 0.3rem 0; padding-left: 0.3rem; }

    /* Analyzer */
    .offline-badge {
        display: inline-block;
        background: rgba(34,197,94,0.1);
        border: 1px solid rgba(34,197,94,0.3);
        color: #22c55e;
        font-size: 0.8rem;
        font-weight: 600;
        padding: 3px 12px;
        border-radius: 20px;
        margin-bottom: 0.8rem;
    }
    .url-notice {
        font-size: 0.8rem;
        color: #64748b;
        margin-top: 0.4rem;
        margin-bottom: 0.8rem;
        padding: 6px 10px;
        background: rgba(255,255,255,0.03);
        border-left: 3px solid #3b82f6;
        border-radius: 0 6px 6px 0;
    }

    /* Result Card */
    .result-card {
        border-radius: 12px;
        padding: 1.4rem 1.6rem;
        margin-bottom: 1.2rem;
    }
    .result-card-safe {
        background: rgba(34,197,94,0.06);
        border-left: 5px solid #22c55e;
        border-top: 1px solid rgba(34,197,94,0.2);
        border-right: 1px solid rgba(34,197,94,0.2);
        border-bottom: 1px solid rgba(34,197,94,0.2);
    }
    .result-card-warning {
        background: rgba(251,191,36,0.06);
        border-left: 5px solid #fbbf24;
        border-top: 1px solid rgba(251,191,36,0.2);
        border-right: 1px solid rgba(251,191,36,0.2);
        border-bottom: 1px solid rgba(251,191,36,0.2);
    }
    .result-card-danger {
        background: rgba(239,68,68,0.06);
        border-left: 5px solid #ef4444;
        border-top: 1px solid rgba(239,68,68,0.2);
        border-right: 1px solid rgba(239,68,68,0.2);
        border-bottom: 1px solid rgba(239,68,68,0.2);
    }
    .result-verdict  { font-size: 1.3rem; font-weight: 800; color: #f1f5f9; margin-bottom: 0.3rem; }
    .result-sub      { font-size: 0.9rem; color: #94a3b8; }
    .result-meta-row { display: flex; gap: 2rem; flex-wrap: wrap; margin-top: 0.9rem; }
    .result-meta-item  { display: flex; flex-direction: column; }
    .result-meta-label { font-size: 0.72rem; font-weight: 700; letter-spacing: 0.07em; text-transform: uppercase; color: #64748b; }
    .result-meta-value { font-size: 1.1rem; font-weight: 700; color: #e2e8f0; }

    /* Guidance Boxes */
    .guidance-safe {
        background: rgba(34,197,94,0.06);
        border: 1px solid rgba(34,197,94,0.25);
        border-radius: 10px;
        padding: 1rem 1.3rem;
        margin-top: 0.8rem;
    }
    .guidance-suspicious {
        background: rgba(251,191,36,0.06);
        border: 1px solid rgba(251,191,36,0.25);
        border-radius: 10px;
        padding: 1rem 1.3rem;
        margin-top: 0.8rem;
    }
    .guidance-danger {
        background: rgba(239,68,68,0.06);
        border: 1px solid rgba(239,68,68,0.25);
        border-radius: 10px;
        padding: 1rem 1.3rem;
        margin-top: 0.8rem;
    }
    .guidance-title { font-size: 0.85rem; font-weight: 700; color: #e2e8f0; margin-bottom: 0.3rem; }
    .guidance-text  { font-size: 0.85rem; color: #94a3b8; line-height: 1.5; }

    /* Indicator Chips */
    .indicator-chip {
        display: inline-block;
        background: rgba(59,130,246,0.1);
        border: 1px solid rgba(59,130,246,0.3);
        color: #cbd5e1;
        padding: 5px 13px;
        border-radius: 20px;
        font-size: 0.83rem;
        margin: 3px;
        white-space: normal !important;
        word-wrap: break-word !important;
    }

    /* Disclaimer */
    .disclaimer-text {
        font-size: 0.76rem;
        color: #475569;
        margin-top: 1rem;
        font-style: italic;
    }

    /* KPI Cards (Model Performance) */
    .kpi-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px 12px;
        text-align: center;
        min-height: 130px;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }
    </style>
    """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Sidebar
# -----------------------------------------------------------------------------
def render_sidebar():
    with st.sidebar:
        st.markdown("""
        <div style="text-align:center; padding:0.5rem 0;">
            <div style="font-size:1.6rem; font-weight:800; color:#f1f5f9;">
                SCAM<span style="color:#3b82f6;">LENS</span> AI
            </div>
            <div style="font-size:1.1rem; margin:0.1rem 0;">🛡️</div>
            <div style="font-size:0.78rem; color:#64748b; font-style:italic;">
                "See the risk before you click."
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        nav_options = ["Dashboard", "Scam Analyzer", "Model Performance", "Scan History", "About"]
        current_idx = nav_options.index(st.session_state["nav_page"]) if st.session_state["nav_page"] in nav_options else 0

        selected = st.radio("Navigation", options=nav_options, index=current_idx, key="sidebar_radio")
        st.session_state["nav_page"] = selected

        st.divider()
        st.markdown("**⚙️ System Status**")
        st.markdown("""
        **Model:** Random Forest
        **Mode:** Offline Inference
        **Status:** <span style='color:#22c55e; font-weight:bold;'>● Ready</span>
        """, unsafe_allow_html=True)

        st.divider()
        st.markdown(
            "<p style='text-align:center; color:#475569; font-size:0.72rem;'>"
            "BCA Major Project © 2026<br>Intelligent Scam &amp; Phishing Detection System</p>",
            unsafe_allow_html=True,
        )


# -----------------------------------------------------------------------------
# Page 1: Dashboard
# -----------------------------------------------------------------------------
def render_dashboard():
    # Hero
    st.markdown("""
    <div class="hero-section">
        <div class="hero-logo">SCAM<span>LENS</span> AI</div>
        <div class="hero-tagline">"See the risk before you click."</div>
        <div class="hero-desc">Check suspicious messages and links before interacting with them.</div>
    </div>
    """, unsafe_allow_html=True)

    if st.button("🔍 Analyze Now", type="primary"):
        st.session_state["nav_page"] = "Scam Analyzer"
        st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # How it works
    st.markdown("#### How SCAMLENS AI Works")
    step_cols = st.columns(4)
    steps = [
        ("📋", "1. Paste",     "Copy in your message, email, or URL"),
        ("🔬", "2. Analyze",   "AI processes the text instantly"),
        ("📊", "3. Understand","See the risk score and reasons"),
        ("🛡️", "4. Stay Safe", "Know before you click or respond"),
    ]
    for col, (icon, title, desc) in zip(step_cols, steps):
        with col:
            st.markdown(f"""
            <div class="step-card">
                <div class="step-number">{icon}</div>
                <div class="step-title">{title}</div>
                <div class="step-desc">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Feature cards
    feat_cols = st.columns(4)
    features = [
        ("🤖", "AI Powered",       "Random Forest trained on real-world scam messages"),
        ("🔒", "Offline Analysis",  "All predictions run locally — no internet required"),
        ("⚡", "Instant Results",   "Risk score and explanation in under a second"),
        ("🎯", "Risk Assessment",   "0–100 risk score with four clear risk levels"),
    ]
    for col, (icon, title, desc) in zip(feat_cols, features):
        with col:
            st.markdown(f"""
            <div class="feature-card">
                <div class="feature-icon">{icon}</div>
                <div class="feature-title">{title}</div>
                <div class="feature-desc">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Trust section
    st.markdown("""
    <div class="trust-section">
        <div class="trust-title">🔐 Built for Safe Analysis</div>
        <div class="trust-point">✔ Machine-learning detection trained on 5,574 labelled SMS messages</div>
        <div class="trust-point">✔ Fully offline prediction — the model runs on your machine</div>
        <div class="trust-point">✔ Static URL structure analysis — submitted links are never opened or visited</div>
        <div class="trust-point">✔ No external API calls or network requests during analysis</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Live scan stats (real data only, skip silently if no history)
    try:
        scans = fetch_recent_scans(limit=500)
        if scans:
            df_scans = pd.DataFrame(scans)
            total    = len(df_scans)
            scam_cnt = int((df_scans["prediction_label"] == "Scam/Phishing").sum())
            legit_cnt= int((df_scans["prediction_label"] == "Legitimate").sum())
            avg_risk = float(df_scans["risk_score"].mean())

            st.markdown("#### 📊 Session Scan Statistics")
            s1, s2, s3, s4 = st.columns(4)
            s1.metric("Total Scans", total)
            s2.metric("Scam Detected", scam_cnt)
            s3.metric("Legitimate", legit_cnt)
            s4.metric("Avg Risk Score", f"{avg_risk:.1f} / 100")
    except Exception:
        pass


# -----------------------------------------------------------------------------
# Page 2: Scam Analyzer
# -----------------------------------------------------------------------------
def render_analyzer():
    st.markdown("<div class='brand-title'>Check a Message or Link</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='brand-subtitle'>Paste a suspicious message, SMS, email text or URL below.</div>",
        unsafe_allow_html=True,
    )

    st.markdown(
        "<span class='offline-badge'>🔒 Offline Analysis — Predictions are generated locally using the trained model.</span>",
        unsafe_allow_html=True,
    )

    # Preset buttons
    st.markdown("##### ⚡ Quick Test Examples")
    preset_cols = st.columns(4)
    if preset_cols[0].button("💬 Normal Message", use_container_width=True):
        st.session_state["analyzer_input"] = "Hi, I will reach college at 10 AM tomorrow. Please wait for me."
    if preset_cols[1].button("🔗 Suspicious URL", use_container_width=True):
        st.session_state["analyzer_input"] = "Your account needs verification. Click http://example.com/login now to continue."
    if preset_cols[2].button("🎁 Prize Scam", use_container_width=True):
        st.session_state["analyzer_input"] = "Congratulations! You have won a free cash prize. Claim your reward at http://example.com/claim-prize now!"
    if preset_cols[3].button("🏦 Account Warning", use_container_width=True):
        st.session_state["analyzer_input"] = "URGENT! Your bank account will be blocked. Verify your account immediately."

    # Text input
    input_text = st.text_area(
        label="Enter content to analyze",
        value=st.session_state["analyzer_input"],
        placeholder="Paste a suspicious message, email text, or URL here...",
        height=140,
        key="analyzer_text_area",
    )

    char_cnt = len(input_text)
    word_cnt = len(input_text.split())
    st.caption(f"📏 Characters: `{char_cnt}` | Words: `{word_cnt}`")

    st.markdown(
        "<div class='url-notice'>🔗 URL analysis is performed using the structure of the submitted URL. "
        "SCAMLENS AI does not open or visit the link.</div>",
        unsafe_allow_html=True,
    )

    btn_col1, btn_col2 = st.columns([3, 1])
    with btn_col1:
        analyze_clicked = st.button("🔍 Analyze with SCAMLENS AI", type="primary", use_container_width=True)
    with btn_col2:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state["analyzer_input"] = ""
            st.rerun()

    if not analyze_clicked:
        return

    if not input_text.strip():
        st.warning("⚠️ Please enter a text message or URL to analyze.")
        return

    with st.spinner("Analyzing content…"):
        try:
            predictor = load_cached_predictor()
            result = predictor.predict(input_text)
        except Exception as e:
            st.error(f"Predictor Engine Error: {e}")
            return

    if not result.get("valid", True):
        st.error(result.get("error", "Invalid input."))
        return

    st.divider()

    pred_label = result["prediction"]
    risk_score = result["risk_score"]
    risk_level = result["risk_level"]
    p_scam     = result["phishing_probability"] * 100.0
    p_legit    = result["legitimate_probability"] * 100.0

    # Result card
    if pred_label == "Legitimate":
        card_class   = "result-card-safe"
        verdict_icon = "✅"
        verdict_text = "Legitimate"
        sub_text     = "This content does not show strong scam or phishing indicators."
    elif risk_level in ("High", "Very High"):
        card_class   = "result-card-danger"
        verdict_icon = "🚨"
        verdict_text = "Scam / Phishing"
        sub_text     = "Strong scam or phishing indicators were detected in this content."
    else:
        card_class   = "result-card-warning"
        verdict_icon = "⚠️"
        verdict_text = "Suspicious"
        sub_text     = "Some suspicious indicators were detected. Review carefully."

    st.markdown(f"""
    <div class="result-card {card_class}">
        <div class="result-verdict">{verdict_icon} {verdict_text}</div>
        <div class="result-sub">{sub_text}</div>
        <div class="result-meta-row">
            <div class="result-meta-item">
                <div class="result-meta-label">Prediction</div>
                <div class="result-meta-value">{pred_label}</div>
            </div>
            <div class="result-meta-item">
                <div class="result-meta-label">Risk Level</div>
                <div class="result-meta-value">{risk_level}</div>
            </div>
            <div class="result-meta-item">
                <div class="result-meta-label">Risk Score</div>
                <div class="result-meta-value">{risk_score:.1f} / 100</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.progress(min(max(risk_score / 100.0, 0.0), 1.0))
    st.caption("Risk Scale: `0–24` Low  |  `25–49` Suspicious  |  `50–74` High  |  `75–100` Very High")

    # Probability bars
    st.markdown("#### Probability Distribution")
    p_col1, p_col2 = st.columns(2)
    with p_col1:
        st.markdown(f"**✅ Legitimate:** `{p_legit:.2f}%`")
        st.progress(min(max(p_legit / 100.0, 0.0), 1.0))
    with p_col2:
        st.markdown(f"**🚨 Scam / Phishing:** `{p_scam:.2f}%`")
        st.progress(min(max(p_scam / 100.0, 0.0), 1.0))

    # Detected indicators
    indicators = result.get("indicators", [])
    if indicators:
        st.markdown("#### Why was this detected?")
        for ind in indicators:
            st.markdown(f"<span class='indicator-chip'>🔸 {ind}</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

    # Guidance
    if risk_level == "Low":
        guidance_class = "guidance-safe"
        guidance_title = "✅ What should I do?"
        guidance_text  = (
            "The risk score is low. Continue to verify the sender before taking important actions. "
            "No automated tool can guarantee a message is completely safe."
        )
    elif risk_level == "Suspicious":
        guidance_class = "guidance-suspicious"
        guidance_title = "⚠️ What should I do?"
        guidance_text  = (
            "Some suspicious signals were detected. Be careful. Avoid clicking links or sharing personal "
            "information until the message is verified through the original source."
        )
    elif risk_level == "High":
        guidance_class = "guidance-danger"
        guidance_title = "🚨 What should I do?"
        guidance_text  = (
            "High-risk indicators detected. Do not click links or provide passwords, OTPs, or financial "
            "information. Verify the message through an official channel before responding."
        )
    else:  # Very High
        guidance_class = "guidance-danger"
        guidance_title = "🚨 What should I do?"
        guidance_text  = (
            "Very high risk detected. Do not click suspicious links or provide passwords, OTPs, or "
            "financial information. Verify through an official source such as the institution's "
            "official website or helpline."
        )

    st.markdown(f"""
    <div class="{guidance_class}">
        <div class="guidance-title">{guidance_title}</div>
        <div class="guidance-text">{guidance_text}</div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("ℹ️ How to interpret this result"):
        st.markdown("""
        SCAMLENS AI uses a trained **Random Forest** classifier with **10,043 features**
        (TF-IDF word/character n-grams + 43 statistical and URL indicators) to classify the input.

        - **Prediction** — Binary classification: Legitimate vs Scam/Phishing
        - **Risk Score** — Derived from the model's scam probability (0 = no risk, 100 = very high risk)
        - **Detected Indicators** — Human-readable feature flags explaining the result
        - **URL Analysis** — Static structural analysis only; SCAMLENS AI never opens or visits any URL
        """)

    st.markdown(
        "<div class='disclaimer-text'>⚠️ SCAMLENS AI provides a machine-learning-based risk assessment. "
        "It should not be treated as a guarantee that a message or URL is safe or malicious.</div>",
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------------------------
# Page 3: Model Performance
# -----------------------------------------------------------------------------
def render_model_performance():
    st.markdown("<div class='brand-title'>Model Performance</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='brand-subtitle'>Evaluation of the machine-learning models used in SCAMLENS AI.</div>",
        unsafe_allow_html=True,
    )

    csv_path = BASE_DIR / "reports" / "model_results" / "model_comparison.csv"

    st.markdown("""
    <div style="background:rgba(34,197,94,0.07);border:1px solid rgba(34,197,94,0.3);
                border-left:5px solid #22c55e;border-radius:10px;
                padding:16px 20px;margin-bottom:18px;">
        <div style="font-size:1rem;color:#22c55e;font-weight:700;margin-bottom:4px;">
            🏆 Selected Model: Random Forest
        </div>
        <div style="color:#94a3b8;font-size:0.9rem;">
            Random Forest was selected after comparing four machine-learning models.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if csv_path.exists():
        df_comp = pd.read_csv(csv_path)
        rf_row  = df_comp[df_comp["model"].str.lower().str.replace(" ", "_") == "random_forest"]
        if rf_row.empty:
            rf_row = df_comp.iloc[0:1]

        accuracy  = float(rf_row["accuracy"].values[0])  * 100
        precision = float(rf_row["precision"].values[0]) * 100
        recall    = float(rf_row["recall"].values[0])    * 100
        f1        = float(rf_row["f1_score"].values[0])  * 100

        kpi_descriptions = [
            ("Accuracy",  f"{accuracy:.1f}%",  "Out of every 100 messages, this many were classified correctly."),
            ("Precision", f"{precision:.1f}%", "When the model flags a scam, this is how often it is right."),
            ("Recall",    f"{recall:.1f}%",    "Out of all real scam messages, this many were caught."),
            ("F1 Score",  f"{f1:.1f}%",        "A balanced score combining Precision and Recall."),
        ]

        kpi_cols = st.columns(4)
        for col, (label, value, desc) in zip(kpi_cols, kpi_descriptions):
            with col:
                st.markdown(f"""
                <div class="kpi-card">
                    <div style="font-size:1.8rem;font-weight:800;color:#22c55e;">{value}</div>
                    <div style="font-size:0.9rem;font-weight:600;color:#e2e8f0;margin:4px 0;">{label}</div>
                    <div style="font-size:0.76rem;color:#64748b;">{desc}</div>
                </div>
                """, unsafe_allow_html=True)

        st.divider()

        st.subheader("📋 Model Comparison Table")
        display_cols = ["model", "accuracy", "precision", "recall", "f1_score"]
        avail_cols   = [c for c in display_cols if c in df_comp.columns]
        df_display   = df_comp[avail_cols].copy()
        df_display.columns = [c.replace("_", " ").title() for c in df_display.columns]
        for col in df_display.columns:
            if col != "Model":
                df_display[col] = df_display[col].apply(
                    lambda x: f"{float(x)*100:.2f}%" if pd.notna(x) else x
                )
        st.dataframe(df_display, use_container_width=True, hide_index=True)

    else:
        st.warning("Model comparison data not found.")

    st.divider()

    st.subheader("🔍 Confusion Matrix — Random Forest")
    eval_dir = BASE_DIR / "reports" / "evaluation"
    rf_cm    = eval_dir / "random_forest_confusion_matrix.png"

    if rf_cm.exists():
        img_col, text_col = st.columns([1, 1])
        with img_col:
            st.image(str(rf_cm), caption="Random Forest — Held-Out Test Set", use_container_width=True)
        with text_col:
            st.markdown("""
            **How to read this chart:**

            The confusion matrix shows how the model classified 1,115 real messages
            it had never seen before.

            | | |
            |---|---|
            | ✅ **Top-left** | Legitimate messages correctly identified |
            | ✅ **Bottom-right** | Scam messages correctly caught |
            | ⚠️ **Top-right** | Legitimate messages wrongly flagged as scam |
            | ❌ **Bottom-left** | Scam messages that slipped through |

            The model correctly caught **141 out of 149 scam messages** and
            correctly cleared **964 out of 966 legitimate messages**.
            """)
    else:
        st.warning("Confusion matrix image not found.")

    st.divider()

    st.info(
        "📂 **Test Dataset:** All metrics are measured on **1,115 messages** "
        "held out and never used during training — ensuring real-world performance."
    )

    with st.expander("💡 What does this mean?", expanded=False):
        st.markdown("""
        SCAMLENS AI trained four machine-learning algorithms on 5,574 labelled SMS messages.
        Each model was tested on 1,115 unseen messages. **Random Forest** performed best.

        - **Accuracy (99.1%)** — the model gets the answer right almost every time.
        - **Precision (98.6%)** — when it says "scam", it is nearly always correct.
        - **Recall (94.6%)** — it catches the vast majority of real scam messages.
        - **F1 Score (96.6%)** — an overall balanced score combining Precision and Recall.
        """)


# -----------------------------------------------------------------------------
# Page 4: Scan History
# -----------------------------------------------------------------------------
def render_scan_history():
    st.markdown("<div class='brand-title'>Scan History</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='brand-subtitle'>Audit trail of scan records stored in the local SQLite database.</div>",
        unsafe_allow_html=True,
    )

    try:
        scans = fetch_recent_scans(limit=500)
        if not scans:
            st.info("No scans recorded yet. Use the Scam Analyzer to test a message!")
            return

        df_scans = pd.DataFrame(scans)

        total_scans = len(df_scans)
        scam_cnt    = int((df_scans["prediction_label"] == "Scam/Phishing").sum())
        legit_cnt   = int((df_scans["prediction_label"] == "Legitimate").sum())
        avg_risk    = float(df_scans["risk_score"].mean()) if total_scans > 0 else 0.0

        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
        with kpi_col1:
            st.metric("Total Scans Recorded", total_scans)
        with kpi_col2:
            st.metric("Scam / Phishing Flagged", scam_cnt)
        with kpi_col3:
            st.metric("Legitimate", legit_cnt)
        with kpi_col4:
            st.metric("Average Risk Score", f"{avg_risk:.1f} / 100")

        st.divider()

        f_col1, f_col2, f_col3 = st.columns([2, 2, 1])
        with f_col1:
            pred_filter = st.selectbox("Filter by Prediction", ["All", "Legitimate", "Scam/Phishing"])
        with f_col2:
            risk_filter = st.selectbox("Filter by Risk Level", ["All", "Low", "Suspicious", "High", "Very High"])
        with f_col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()

        filtered_df = df_scans.copy()
        if pred_filter != "All":
            filtered_df = filtered_df[filtered_df["prediction_label"] == pred_filter]
        if risk_filter != "All":
            filtered_df = filtered_df[filtered_df["risk_level"] == risk_filter]

        cols_to_show = ["id", "timestamp", "prediction_label", "risk_score", "risk_level", "content", "explanation_summary"]
        avail_cols   = [c for c in cols_to_show if c in filtered_df.columns]
        st.dataframe(filtered_df[avail_cols], use_container_width=True)

    except Exception as e:
        st.error(f"Could not read scan history from database: {e}")


# -----------------------------------------------------------------------------
# Page 5: About
# -----------------------------------------------------------------------------
def render_about():
    st.markdown("<div class='brand-title'>About SCAMLENS AI</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='brand-subtitle'>BCA Major Academic Project — Intelligent Scam and Phishing Detection System</div>",
        unsafe_allow_html=True,
    )

    st.markdown("""
    ### 📌 Project Overview
    **SCAMLENS AI** is an intelligent cybersecurity platform engineered to detect, classify, and explain
    scam text messages, email phishing attempts, and suspicious URLs using machine learning.

    ### 🎓 Academic Context
    - **Degree:** Bachelor of Computer Applications (BCA)
    - **Academic Title:** Intelligent Scam and Phishing Detection System
    - **Domain:** Data Science / Artificial Intelligence / Machine Learning / Cybersecurity

    ### 🎯 Core Objectives
    1. Establish a leak-free NLP feature extraction pipeline combining TF-IDF N-Grams and static lexical indicators.
    2. Train and evaluate 4 baseline ML classifiers: Logistic Regression, Decision Tree, Random Forest, SVM.
    3. Select the optimal classifier using Macro F1 score with ROC-AUC tie-breaking.
    4. Provide 100% offline static analysis with human-readable explanatory indicators.

    ### 🛠️ Technology Stack
    - **Core Language:** Python 3.12
    - **Data Processing & ML:** Pandas, NumPy, Scikit-learn, NLTK
    - **Primary Model:** Random Forest Classifier (Class-Balanced)
    - **Web Framework:** Streamlit
    - **Database:** SQLite3

    ### 🔮 Future Scope
    - Multilingual scam text detection
    - Real-time email header parsing
    - Deep learning / transformer architectures (BERT / RoBERTa)
    - Browser extension integration
    """)

    st.divider()

    st.markdown("""
    <div style="background:rgba(251,191,36,0.06);border:1px solid rgba(251,191,36,0.25);
                border-left:4px solid #fbbf24;border-radius:10px;padding:1rem 1.4rem;">
        <div style="font-size:0.85rem;font-weight:700;color:#fbbf24;margin-bottom:0.4rem;">
            ⚠️ Disclaimer
        </div>
        <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6;">
            SCAMLENS AI provides a machine-learning-based risk assessment. It should be used as an
            assistive tool and does not guarantee that content is safe or malicious. Submitted URLs are
            analyzed strictly as static text strings — SCAMLENS AI does not open, visit, or execute
            any submitted URL.
        </div>
    </div>
    """, unsafe_allow_html=True)


# -----------------------------------------------------------------------------
# Main Controller
# -----------------------------------------------------------------------------
def main():
    inject_custom_css()
    render_sidebar()

    current_page = st.session_state["nav_page"]

    if current_page == "Dashboard":
        render_dashboard()
    elif current_page == "Scam Analyzer":
        render_analyzer()
    elif current_page == "Model Performance":
        render_model_performance()
    elif current_page == "Scan History":
        render_scan_history()
    elif current_page == "About":
        render_about()


if __name__ == "__main__":
    main()
