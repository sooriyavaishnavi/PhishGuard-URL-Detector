# PhishGuard v2.0 — Enhanced Setup & Run Guide

A production-grade 5-stage phishing URL detection system.

---

## 🧠 Detection Pipeline (v2.0)

```
URL Input
   │
   ▼
① Trusted Domain Allowlist  ── Known-good brands (Google, GitHub, etc.) → LEGITIMATE (risk: 0%)
   │
   ▼
② OpenPhish Blacklist        ── 42,000+ known phishing URLs → PHISHING (risk: 100%)
   │
   ▼
③ Brand Impersonation Guard  ── Detects spoofed brand keywords in domain/path
   │  (Paypal, Apple, Microsoft, Bank names, etc.)
   ▼
④ XGBoost ML Model           ── 14 features + 2000 TF-IDF tokens → blended with heuristics
   │  (Blended score: 65% ML + 35% heuristics)
   ▼
⑤ Advanced Heuristics (30+ checks):
   • IP address in URL          • Unicode homoglyphs (IDN attacks)
   • @ symbol in URL            • Open redirect parameters
   • Suspicious TLDs (.tk/.ml)  • URL encoding obfuscation
   • Domain entropy (DGA check) • Executable files in path
   • Brand keywords in URL      • Non-standard ports
   • HTTPS missing              • Excessive hyphens/dots/length
   • Deep subdomain nesting     • High digit ratio in domain
   │
   ▼
PHISHING / SUSPICIOUS / LEGITIMATE + risk score %
```

---

## ⚡ Step-by-Step: How to Run

### Step 1 — Prerequisites

```bash
python --version   # Requires Python 3.9, 3.10, 3.11, or 3.12
```

Create a virtual environment (recommended):

```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# Mac/Linux:
source venv/bin/activate
```

---

### Step 2 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 3 — Train the ML Model (Optional but Recommended)

Without the ML model, the app uses 5-stage advanced heuristics (still very effective).

#### 3a. Download datasets from Kaggle:

1. **Dataset 1:** https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
   - File: `malicious_phish.csv`

2. **Dataset 2:** https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls
   - File: `phishing_site_urls.csv`

#### 3b. Open the notebook:

```bash
jupyter lab Ml_model_blacklistCheck.ipynb
# OR upload to Google Colab (free GPU): https://colab.research.google.com
```

#### 3c. Run all cells → it produces:
- `best_model.pkl` — trained XGBoost classifier
- `tfidf.pkl` — fitted TF-IDF vectorizer

#### 3d. Copy model files into the `models/` folder:

```
phishguard_enhanced/
└── models/
    ├── best_model.pkl    ← trained model
    └── tfidf.pkl         ← vectorizer
```

```bash
mkdir -p models
# Then copy best_model.pkl and tfidf.pkl here
```

---

### Step 4 — Start the Flask Backend

**Terminal 1:**

```bash
python flask_backend.py
```

Expected output:
```
✅ Model loaded: XGBClassifier
✅ Blacklist loaded: 42,500 URLs
 * Running on http://0.0.0.0:5000
```

> ✅ Without model files: runs in heuristic-only mode (still detects via stages 1-3 + 5)

---

### Step 5 — Start the Streamlit Frontend

**Terminal 2:**

```bash
streamlit run app.py
```

Then open: **http://localhost:8501**

---

## 🔍 What's New in v2.0

| Feature | v1.0 | v2.0 |
|---------|-------|-------|
| Detection stages | 3 | **5** |
| URL features extracted | 14 | **33** |
| Brand impersonation detection | ❌ | ✅ |
| IDN homoglyph attack detection | ❌ | ✅ |
| Domain entropy (DGA detection) | ❌ | ✅ |
| Open redirect detection | ❌ | ✅ |
| Trusted domain allowlist | ❌ | ✅ |
| ML + heuristic score blending | ❌ | ✅ |
| SUSPICIOUS verdict | ❌ | ✅ |
| Confidence rating | ❌ | ✅ |
| Flag severity levels | ❌ | ✅ |
| Offline advanced mode | Basic | **Advanced 30+ checks** |

---

## 🌐 API Endpoints

```bash
# Health check
curl http://localhost:5000/api/status

# Single URL detect
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://paypal-secure.login.tk/verify"}'

# Batch detect (up to 50 URLs)
curl -X POST http://localhost:5000/api/detect/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://phish.tk/login"]}'

# Detailed feature analysis (no verdict)
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Refresh OpenPhish blacklist
curl -X POST http://localhost:5000/api/blacklist/refresh

# View scan history (last 100)
curl http://localhost:5000/api/history
```

---

## 🗂️ Project Structure

```
phishguard_enhanced/
├── app.py                    ← Streamlit frontend (enhanced UI)
├── flask_backend.py          ← Flask REST API + 5-stage detection engine
├── requirements.txt          ← All dependencies
├── README.md                 ← This file
├── Ml_model_blacklistCheck.ipynb ← Jupyter notebook to train ML model
└── models/
    ├── best_model.pkl        ← Trained XGBoost (from notebook)
    ├── tfidf.pkl             ← TF-IDF vectorizer (from notebook)
    └── blacklist_cache.json  ← Auto-generated OpenPhish cache
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| Backend shows "Model files not found" | Copy `best_model.pkl` + `tfidf.pkl` into `models/` |
| Streamlit shows "Backend Offline" | Start Flask with `python flask_backend.py` |
| Port 5000 in use | Change port in `flask_backend.py` last line |
| Port 8501 in use | `streamlit run app.py --server.port 8502` |
| Blacklist fetch fails | Check internet; app works with ML + heuristics only |

---

## 🚀 Production Deployment

```bash
# Install Gunicorn
pip install gunicorn

# Start Flask (4 workers)
gunicorn -w 4 -b 0.0.0.0:5000 flask_backend:app

# Start Streamlit
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
```
