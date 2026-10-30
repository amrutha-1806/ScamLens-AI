# SCAMLENS AI — Intelligent Scam and Phishing Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6.svg)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-38B2AC.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/License-Academic%20Project-green.svg)]()

**SCAMLENS AI** is an intelligent full-stack cybersecurity platform designed to detect, analyze, and explain deceptive text messages, email phishing attacks, and malicious URLs in real time. Powered by an ensemble Random Forest classifier evaluating **10,043 lexical and statistical features**, the system provides interpretable risk scores, human-readable detection indicators, and actionable security guidance.

---

## Key Features

- **Message Analyzer**: Real-time natural language inspection detecting urgency language, credential harvesting, financial fraud patterns, and suspicious lures.
- **Static URL Analyzer**: Zero-execution structural and lexical inspection evaluating domain entropy, IP address hosts, deceptive subdomains, and protocol security without visiting or triggering malicious links.
- **Batch CSV Scanner**: High-throughput file inspection supporting custom dataset column mapping and live classification exports.
- **Learn & Practise**: Interactive cybersecurity quiz featuring 44 randomized phishing scenarios with token-level explanations and scoring.
- **Security Audit Reports**: Standalone report generation with multi-page PDF audit downloads and CSV exports.
- **Enterprise Dual Theme**: Seamless switching between **Dark Mode** (cyber command center), **Light Mode** (high-contrast enterprise layout), and **System Mode**.
- **Cross-Device Responsiveness**: Fully optimized for mobile viewports (down to 320px) and wide desktop displays.

---

## Machine Learning Architecture

```text
[Input Text / URL]
        │
        ▼
[Preprocessing & Normalization]
        │
        ▼
[Feature Extraction Engine (10,043 Features)]
   ├── TF-IDF Word N-grams (5,000 features)
   ├── TF-IDF Character N-grams (5,000 features)
   └── Statistical & Lexical Heuristics (43 features)
        │
        ▼
[Random Forest Classifier (Class-Balanced Ensemble)]
        │
        ├── Prediction: Legitimate vs. Scam/Phishing
        ├── Risk Tier: Low | Suspicious | High | Very High
        ├── Risk Score: 0.0 – 100.0%
        └── Detection Indicators & Actionable Guidance
        │
        ▼
[FastAPI REST API (Port 8001)] ──► [TanStack React Frontend (Port 5173)]
        │
        ▼
[SQLite Audit Logger (`scamlens.db`)]
```

### Model Performance Metrics (UCI SMS Corpus — 5,574 Samples)

| Metric | Random Forest (Selected Model) | SVM | Logistic Regression | Decision Tree |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | **99.10%** | 98.74% | 97.49% | 96.50% |
| **Precision** | **98.60%** | 98.40% | 96.80% | 92.10% |
| **Recall (Sensitivity)** | **94.63%** | 91.20% | 84.50% | 88.00% |
| **F1 Score** | **96.58%** | 94.66% | 90.24% | 90.00% |
| **ROC AUC** | **0.9936** | 0.9880 | 0.9750 | 0.9320 |

---

## Repository Structure

```text
ScamLens-AI/
├── frontend/                     # Modern React & TanStack web application
│   ├── src/                      # TypeScript components, routes, state hooks
│   ├── public/                   # Static assets, logos, and icons
│   ├── package.json              # Frontend npm dependencies
│   ├── tsconfig.json             # TypeScript strict configuration
│   ├── vite.config.ts            # Vite & Nitro SSR configuration
│   └── .env.example              # Frontend environment template
│
├── backend/                      # FastAPI REST service
│   ├── main.py                   # API routes (/api/analyze, /api/health, etc.)
│   ├── schemas.py                # Pydantic validation schemas
│   └── services/                 # ML and audit logging services
│
├── saved_models/                 # Pre-trained scikit-learn model artifacts
│   ├── random_forest.pkl         # Trained Random Forest classifier
│   ├── svm.pkl                   # Support Vector Machine benchmark
│   └── feature_extractor.pkl     # Fitted 10,043-feature vectorizer
│
├── src/                          # Core Python ML training & evaluation modules
│   ├── features/                 # Word/char n-grams and URL extractors
│   ├── models/                   # Training and evaluation routines
│   ├── preprocessing/            # Text cleaning and tokenizers
│   └── utils/                    # SQLite database persistence
│
├── app/                          # Streamlit companion demo interface
├── data/                         # Processed datasets and samples
├── reports/                      # Confusion matrices and evaluation plots
├── scripts/                      # Desktop launcher automation scripts
├── requirements.txt              # Python pip dependencies
├── SCAMLENS_AI_Launcher.bat      # 1-Click launcher for both backend & frontend
├── SCAMLENS_AI_Stop.bat          # 1-Click shutdown script
├── .gitignore                    # Comprehensive secrets & build exclusions
└── README.md                     # Project documentation
```

---

## Quickstart Guide

### Prerequisites

- **Python**: Version 3.10, 3.11, or 3.12 installed ([python.org](https://www.python.org/downloads/))
- **Node.js**: Version 18+ or 20+ installed ([nodejs.org](https://nodejs.org/))

### Method 1: One-Click Desktop Launch (Windows)

Double-click `SCAMLENS_AI_Launcher.bat` in the repository root. This will:
1. Validate backend and frontend dependencies.
2. Start the FastAPI backend on `http://127.0.0.1:8001`.
3. Start the Vite React frontend on `http://127.0.0.1:5173`.
4. Open the application directly in your default browser.

To stop both services cleanly, double-click `SCAMLENS_AI_Stop.bat`.

---

### Method 2: Manual Terminal Startup

#### 1. Start the Python Backend

```bash
# Install Python dependencies
pip install -r requirements.txt

# Launch FastAPI server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8001 --reload
```

- API Health Check: `http://127.0.0.1:8001/api/health`
- Interactive Swagger Docs: `http://127.0.0.1:8001/docs`

#### 2. Start the Frontend Application

```bash
cd frontend

# Install Node dependencies
npm install

# Start development server
npm run dev
```

- Web App: `http://127.0.0.1:5173`

---

## API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Model readiness and health status |
| `POST` | `/api/analyze/message` | Analyzes SMS/email text for phishing indicators |
| `POST` | `/api/analyze/url` | Performs zero-execution static lexical URL inspection |
| `POST` | `/api/analyze/batch` | High-throughput batch processing of CSV files |
| `GET` | `/api/history` | Retrieves recent scan records from SQLite |
| `GET` | `/api/model-info` | Returns verified holdout evaluation metrics |

---

## Security & Privacy Notice

- **Zero-Execution URL Inspection**: URLs evaluated by SCAMLENS AI are never fetched, visited, or executed.
- **Privacy First**: Analysis is performed locally through the machine learning pipeline; user inputs are not transmitted to third-party tracking services.
- **Open Standards**: Fully reproducible machine learning pipeline backed by automated unit tests (`pytest`).
