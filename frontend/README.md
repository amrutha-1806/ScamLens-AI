# SCAMLENS AI Dashboard

Build a professional web application called:

SCAMLENS AI
Intelligent Scam and Phishing Detection System

This is a final-year BCA major project based on Machine Learning.

IMPORTANT:
This phase is for building the professional frontend and application structure.
Do NOT invent or fake machine-learning results.
Do NOT create a fake AI model.
The real ML backend will be Python/FastAPI and will be connected later.

The application should look like a professional cybersecurity analysis platform, not a simple student demo.

TECHNOLOGY:
- React
- TypeScript
- Modern responsive web UI
- Component-based architecture
- Professional cybersecurity dashboard
- Charts and visualizations

BRAND:
SCAMLENS AI

Tagline:
"See the risk before you click."

DESIGN:
- Professional cybersecurity/SaaS appearance
- Dark navy/charcoal interface
- Blue primary accent
- Green for legitimate/safe
- Orange for suspicious
- Red for high-risk/scam
- Excellent spacing
- Rounded cards
- Subtle animations
- No excessive gradients
- No childish graphics
- No unnecessary neon effects
- Responsive on laptop and desktop screens

MAIN NAVIGATION:

1. Dashboard
2. Message Analyzer
3. URL Analyzer
4. Batch CSV Scanner
5. Analytics
6. AI & Models
7. Scan History
8. Reports
9. About Project

DASHBOARD:

Create a professional security dashboard.

Show:
- Total Scans
- Scam/Phishing Detected
- Legitimate Detected
- High-Risk Scans

Add:
- Risk distribution chart
- Legitimate vs Scam chart
- Recent scan activity
- Quick action buttons

Quick actions:
"Analyze Message"
"Analyze URL"
"Batch Scan CSV"

Include a project overview explaining:

SCAMLENS AI uses Machine Learning to analyze suspicious messages and URLs and provide:
- Prediction
- Risk probability
- Risk level
- Detection indicators
- Security guidance

MESSAGE ANALYZER:

Create a professional analysis screen.

Input:
Large text box for message/email content.

Buttons:
Analyze
Clear
Use Example

Example buttons:
- Normal Message
- Prize Scam
- Account Warning
- Suspicious URL

Result section should support:

Prediction:
LEGITIMATE / SCAM-PHISHING

Risk Score:
0–100%

Risk Level:
Low / Suspicious / High / Very High

Show:
- Probability
- Detection indicators
- Explanation
- Security recommendation

Do not hard-code fake prediction results.
Use clearly marked demo/mock states until the Python API is connected.

URL ANALYZER:

Create a separate URL security analysis module.

Input:
URL text field

Display:
- HTTPS
- URL length
- Domain
- Number of subdomains
- IP address detection
- @ symbol detection
- suspicious keyword detection
- URL shortener detection
- special character indicators

Show:
URL Risk Score
Risk Level
Detected Indicators
Security Guidance

IMPORTANT:
The system must NOT visit or open the submitted URL.
The actual backend will perform static URL analysis only.

BATCH CSV SCANNER:

Create a CSV upload page.

User should be able to upload a CSV containing messages.

Show:
- File name
- Number of records
- Preview table
- Scan button

After backend integration, the page should display:
- Total scanned
- Legitimate
- Scam/Phishing
- High Risk
- Very High Risk

Include:
- Result table
- Filters
- Search
- Download results button

For now use a clean empty/demo state rather than fake ML results.

ANALYTICS:

Create a security analytics dashboard.

Include:
- Total scans
- Scam detection rate
- Risk distribution
- Legitimate vs scam
- Scan trends
- Message statistics
- URL statistics

Use chart components but structure them so real backend data can replace mock data later.

AI & MODELS:

Create a professional ML information page.

Show:

Dataset:
UCI SMS Spam Collection

Dataset size:
5,574 messages

Classes:
Legitimate
Scam/Phishing

Models evaluated:
- Logistic Regression
- Decision Tree
- Random Forest
- Linear SVM

Final model:
Random Forest

Explain:
"Models are evaluated using standard classification metrics. The final model is selected based on the project's evaluation process."

Do not invent performance values.

Include:
- Dataset
- Feature Engineering
- Model Comparison
- Final Model
- Confusion Matrix
- How Prediction Works

SCAN HISTORY:

Create a searchable and filterable table.

Columns:
- Date/Time
- Input Type
- Input Preview
- Prediction
- Risk Score
- Risk Level

Filters:
All
Legitimate
Scam
Low
Suspicious
High
Very High

REPORTS:

Create a report generation page.

Allow the user to select a scan and view:

SCAMLENS AI Security Analysis Report

- Submitted input
- Prediction
- Risk score
- Risk level
- Detection indicators
- URL analysis if applicable
- Timestamp
- Model used

Include:
Generate Report
Download Report

ABOUT:

Explain:
- Project objective
- Problem statement
- Dataset
- Machine Learning approach
- Technologies
- Limitations
- Future enhancements

IMPORTANT UI REQUIREMENTS:

Make every page visually complete.

Do not leave large empty areas.

Use loading states.

Use error states.

Use empty states.

Use responsive layouts.

Create reusable components for:
- KPI cards
- Risk badges
- Risk meter
- Analysis result
- Charts
- Tables
- Navigation
- Page headers

Create a clear API service layer so the frontend can later communicate with a Python FastAPI backend.

Use environment configuration for the API base URL.

For now, keep backend calls clearly separated and use mock/empty states only where necessary.

Do not fake real ML predictions.

Build the complete frontend structure now.

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/857b96c7-4763-4802-8738-04f05b9f9e3c).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
