"""
PhishGuard AI — Enhanced Flask Backend v2.0
URL Phishing Detection: Blacklist + ML Model + Advanced Heuristics
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os
import json
import math
import joblib
import numpy as np
import requests
import tldextract
from huggingface_hub import download_bucket_files
from urllib.parse import urlparse, unquote
from scipy.sparse import hstack, csr_matrix
from datetime import datetime
import hashlib

app = Flask(__name__)
CORS(app)

MODEL_PATH     = os.path.join("models", "best_model.pkl")
TFIDF_PATH     = os.path.join("models", "tfidf.pkl")
BLACKLIST_PATH = os.path.join("models", "blacklist_cache.json")
# Download the large ML model from Hugging Face Bucket if it is not available locally
if not os.path.exists(MODEL_PATH):
    os.makedirs("models", exist_ok=True)
    print("⬇️ Downloading best_model.pkl from Hugging Face...")
    download_bucket_files(
        "sooriyavaishnavi/PhishGuard-URL-Detector",
        files=[
            ("best_model.pkl", MODEL_PATH)
        ],
    )
    print("✅ best_model.pkl downloaded successfully")

best_model = None
tfidf      = None
blacklist  = set()
scan_history = []

TRUSTED_DOMAINS = {
    "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","reddit.com","github.com","wikipedia.org","amazon.com",
    "microsoft.com","apple.com","netflix.com","spotify.com","dropbox.com",
    "adobe.com","paypal.com","ebay.com","yahoo.com","bing.com",
    "stackoverflow.com","medium.com","wordpress.com","shopify.com",
    "cloudflare.com","twitch.tv","discord.com","slack.com","zoom.us",
    "notion.so","figma.com","canva.com",
}

SUSPICIOUS_TLDS = {
    "tk","ml","ga","cf","gq","xyz","top","club","work","click","link","pw","cc","su"
}

BRAND_KEYWORDS = [
    "paypal","apple","microsoft","google","amazon","netflix","facebook",
    "instagram","twitter","linkedin","dropbox","chase","wellsfargo","bankofamerica",
    "citibank","hsbc","ebay","walmart","target","fedex","ups","dhl",
    "irs","gov","verify","secure","login","signin","account","update",
    "confirm","banking","support","credential","password","validate",
]

SUSPICIOUS_WORDS = [
    'login','secure','bank','verify','update','account','confirm','password',
    'paypal','signin','webscr','submit','access','validate','authorization',
    'credential','reset','unlock','alert','urgent','limited','suspend'
]

HOMOGLYPH_CHARS = set("аеорсухАВСЕКМНОРТХ")


def load_model():
    global best_model, tfidf
    if os.path.exists(MODEL_PATH) and os.path.exists(TFIDF_PATH):
        best_model = joblib.load(MODEL_PATH)
        tfidf      = joblib.load(TFIDF_PATH)
        print(f"✅ Model loaded: {type(best_model).__name__}")
    else:
        print("⚠️  Model files not found. ML detection unavailable.")


def load_blacklist():
    global blacklist
    if os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH) as f:
            blacklist = set(json.load(f))
        print(f"✅ Blacklist loaded: {len(blacklist):,} URLs")
        return
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=10)
        if resp.status_code == 200:
            blacklist = set(resp.text.splitlines())
            with open(BLACKLIST_PATH, "w") as f:
                json.dump(list(blacklist), f)
            print(f"✅ Blacklist fetched: {len(blacklist):,} URLs")
    except Exception as e:
        print(f"⚠️  Blacklist fetch error: {e}")


def calculate_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    n = len(s)
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def count_vowel_ratio(domain):
    vowels = sum(1 for c in domain.lower() if c in "aeiou")
    consonants = sum(1 for c in domain.lower() if c.isalpha() and c not in "aeiou")
    if consonants == 0:
        return 1.0
    return round(vowels / consonants, 3)


def detect_brand_impersonation(url, domain, subdomain):
    ext = tldextract.extract(url)
    root_domain = f"{ext.domain}.{ext.suffix}".lower()
    if root_domain in TRUSTED_DOMAINS:
        return {"impersonating": False, "brand": None, "technique": None}
    for brand in BRAND_KEYWORDS:
        if brand in subdomain.lower() or brand in domain.lower():
            return {"impersonating": True, "brand": brand, "technique": "brand_keyword_in_domain"}
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    for brand in BRAND_KEYWORDS[:10]:
        if brand in parsed.path.lower():
            return {"impersonating": True, "brand": brand, "technique": "brand_keyword_in_path"}
    return {"impersonating": False, "brand": None, "technique": None}


def check_domain_signals(url):
    ext = tldextract.extract(url)
    tld = ext.suffix.lower()
    domain = ext.domain.lower()
    signals = []
    score = 0
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"Suspicious TLD (.{tld})")
        score += 25
    if len(domain) <= 4:
        signals.append(f"Very short domain ({len(domain)} chars)")
        score += 10
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    if digit_ratio > 0.4:
        signals.append(f"High digit ratio ({digit_ratio:.0%})")
        score += 15
    entropy = calculate_entropy(domain)
    if entropy > 3.5:
        signals.append(f"High entropy ({entropy:.2f}) — possible DGA")
        score += 20
    return {"signals": signals, "score": score, "entropy": entropy}


def extract_advanced_features(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    ext    = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    tld    = ext.suffix
    path   = parsed.path

    return {
        "url_length":            len(url),
        "domain_length":         len(domain),
        "dot_count":             url.count('.'),
        "dash_count":            url.count('-'),
        "at_sign":               1 if '@' in url else 0,
        "query_params":          url.count('?'),
        "equals_count":          url.count('='),
        "digit_count":           sum(c.isdigit() for c in url),
        "has_https":             1 if parsed.scheme == 'https' else 0,
        "path_length":           len(path),
        "query_length":          len(parsed.query),
        "subdomain_depth":       len(subdomain.split('.')) if subdomain else 0,
        "suspicious_words":      1 if any(w in url.lower() for w in SUSPICIOUS_WORDS) else 0,
        "has_ip":                1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        "has_double_slash":      1 if '//' in path else 0,
        "has_url_encoding":      1 if '%' in url else 0,
        "tilde_in_url":          1 if '~' in url else 0,
        "slash_count":           url.count('/'),
        "underscore_count":      url.count('_'),
        "ampersand_count":       url.count('&'),
        "fragment_present":      1 if '#' in url else 0,
        "port_in_url":           1 if re.search(r':\d{2,5}/', url) else 0,
        "multiple_subdomains":   1 if len(subdomain.split('.')) > 2 else 0,
        "domain_entropy":        calculate_entropy(domain),
        "has_homoglyphs":        1 if any(c in HOMOGLYPH_CHARS for c in url) else 0,
        "tld_suspicious":        1 if tld in SUSPICIOUS_TLDS else 0,
        "domain_digit_ratio":    round(sum(c.isdigit() for c in domain) / max(len(domain), 1), 3),
        "vowel_ratio":           count_vowel_ratio(domain),
        "has_redirect":          1 if re.search(r'redirect|redir|url=|next=|goto=', url.lower()) else 0,
        "path_has_exe":          1 if re.search(r'\.(exe|bat|cmd|sh|msi|dmg|apk)($|\?)', url.lower()) else 0,
        "path_has_php":          1 if '.php' in url.lower() else 0,
        "brand_count":           sum(1 for b in BRAND_KEYWORDS if b in url.lower()),
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in url.lower()),
    }


def extract_ml_vector(url):
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    ext    = tldextract.extract(url)
    return [
        len(url), len(ext.domain), url.count('.'), url.count('-'),
        url.count('@'), url.count('?'), url.count('='),
        sum(c.isdigit() for c in url),
        1 if parsed.scheme == 'https' else 0,
        len(parsed.path), len(parsed.query),
        len(ext.subdomain.split('.')) if ext.subdomain else 0,
        1 if any(w in url.lower() for w in SUSPICIOUS_WORDS) else 0,
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
    ]


def heuristic_score(url, features):
    score = 0
    flags = []
    severity = {}

    def add(points, msg, level="medium"):
        nonlocal score
        score += points
        flags.append(msg)
        severity[msg] = level

    if features["has_ip"]:
        add(40, "IP address used as domain", "high")
    if features["at_sign"]:
        add(30, "@ symbol in URL", "high")
    if features["has_homoglyphs"]:
        add(35, "Unicode homoglyph characters (IDN attack)", "high")
    if not features["has_https"]:
        add(20, "No HTTPS — unencrypted", "high")
    if features["tld_suspicious"]:
        add(25, "Suspicious TLD (.tk/.ml/.ga etc.)", "high")
    if features["domain_entropy"] > 3.5:
        add(20, f"High domain entropy ({features['domain_entropy']:.2f}) — DGA?", "high")
    if features["suspicious_word_count"] >= 2:
        add(20, f"{features['suspicious_word_count']} phishing keywords in URL", "medium")
    elif features["suspicious_words"]:
        add(10, "Phishing keyword in URL", "medium")
    if features["subdomain_depth"] > 2:
        add(15, f"Deep subdomain nesting ({features['subdomain_depth']} levels)", "medium")
    if features["has_redirect"]:
        add(20, "Open redirect parameter (url=, goto=, next=)", "medium")
    if features["dash_count"] > 3:
        add(10, f"Excessive hyphens ({features['dash_count']})", "medium")
    if features["url_length"] > 100:
        add(10, f"Long URL ({features['url_length']} chars)", "medium")
    if features["url_length"] > 150:
        add(10, "Extremely long URL — obfuscation?", "medium")
    if features["has_url_encoding"]:
        add(10, "URL percent-encoding — possible obfuscation", "medium")
    if features["has_double_slash"]:
        add(10, "Double slash in path", "medium")
    if features["domain_digit_ratio"] > 0.4:
        add(15, f"High digit ratio in domain ({features['domain_digit_ratio']:.0%})", "medium")
    if features["path_has_exe"]:
        add(15, "Executable file extension in path", "medium")
    if features["port_in_url"]:
        add(10, "Non-standard port in URL", "low")
    if features["tilde_in_url"]:
        add(5, "Tilde (~) in URL", "low")
    if features["dot_count"] > 5:
        add(10, f"Excessive dots ({features['dot_count']})", "low")

    return min(score, 100), flags, severity


def is_valid_url(url):
    pattern = re.compile(r'^(https?://)?([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}')
    return bool(re.match(pattern, url))


def is_trusted_domain(url):
    ext = tldextract.extract(url)
    root = f"{ext.domain}.{ext.suffix}".lower()
    return root in TRUSTED_DOMAINS


def detect(url):
    timestamp = datetime.utcnow().isoformat() + "Z"

    if not is_valid_url(url):
        return {
            "url": url, "verdict": "INVALID_URL", "detection_source": None,
            "risk_score": None, "features": None, "heuristic_flags": [],
            "brand_info": None, "domain_signals": None,
            "timestamp": timestamp, "error": "Invalid URL format"
        }

    adv_features   = extract_advanced_features(url)
    ext            = tldextract.extract(url)
    brand_info     = detect_brand_impersonation(url, ext.domain, ext.subdomain)
    domain_signals = check_domain_signals(url)
    h_score, h_flags, h_severity = heuristic_score(url, adv_features)

    base = {
        "url": url, "features": adv_features, "heuristic_flags": h_flags,
        "heuristic_severity": h_severity, "heuristic_score": h_score,
        "brand_info": brand_info, "domain_signals": domain_signals,
        "timestamp": timestamp
    }

    # Stage 1: Trusted allowlist
    if is_trusted_domain(url):
        return {**base, "verdict": "LEGITIMATE", "detection_source": "trusted_domain",
                "detection_label": "Trusted Domain (Allowlist)", "risk_score": 0.0, "confidence": "HIGH"}

    # Stage 2: Blacklist
    if url in blacklist:
        return {**base, "verdict": "PHISHING", "detection_source": "blacklist",
                "detection_label": "OpenPhish Blacklist", "risk_score": 100.0, "confidence": "HIGH"}

    # Stage 3: Brand impersonation + heuristic
    if brand_info["impersonating"] and h_score >= 40:
        return {**base, "verdict": "PHISHING",
                "detection_source": "brand_heuristic",
                "detection_label": f"Brand Impersonation ({brand_info['brand'].title()})",
                "risk_score": min(h_score + 20, 100), "confidence": "HIGH"}

    # Stage 4: ML model
    if best_model is not None and tfidf is not None:
        raw = extract_ml_vector(url)
        feat_sparse = csr_matrix(np.array(raw).reshape(1, -1))
        tfidf_feat  = tfidf.transform([url])
        X           = hstack([feat_sparse, tfidf_feat])
        prediction  = best_model.predict(X)[0]
        try:
            prob = best_model.predict_proba(X)[0][1]
            ml_risk = round(float(prob) * 100, 1)
        except:
            ml_risk = 100.0 if prediction == 1 else 0.0

        final_risk = round(0.65 * ml_risk + 0.35 * h_score, 1)
        verdict    = "PHISHING" if prediction == 1 else "LEGITIMATE"

        if verdict == "LEGITIMATE" and h_score >= 70:
            verdict, final_risk = "PHISHING", max(final_risk, 75.0)
            source, label, conf = "ml_heuristic_override", "ML + Heuristic Override", "MEDIUM"
        elif verdict == "PHISHING":
            source, label, conf = "ml_model", "ML Model (XGBoost)", "HIGH"
        else:
            source, label, conf = "ml_model", "ML Model (XGBoost)", "HIGH"

        result = {**base, "verdict": verdict, "detection_source": source,
                  "detection_label": label, "risk_score": final_risk,
                  "ml_score": ml_risk, "confidence": conf}
        _add_history(result)
        return result

    # Stage 5: Heuristic-only
    if h_score >= 50:
        verdict, conf = "PHISHING", "MEDIUM" if h_score < 75 else "HIGH"
    elif h_score >= 30:
        verdict, conf = "SUSPICIOUS", "LOW"
    else:
        verdict, conf = "LEGITIMATE", "MEDIUM"

    result = {**base, "verdict": verdict, "detection_source": "heuristic",
              "detection_label": "Advanced Heuristics (No ML)", "risk_score": float(h_score),
              "confidence": conf, "error": "ML model not loaded — heuristic mode"}
    _add_history(result)
    return result


def _add_history(result):
    scan_history.insert(0, result)
    if len(scan_history) > 500:
        scan_history.pop()


@app.route("/")
def index():
    return jsonify({"message": "PhishGuard AI v2.0", "status": "ok"})

@app.route("/api/detect", methods=["POST"])
def api_detect():
    data = request.get_json(force=True)
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(detect(url))

@app.route("/api/detect/batch", methods=["POST"])
def api_detect_batch():
    data = request.get_json(force=True)
    urls = data.get("urls", [])[:50]
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    results = [detect(url) for url in urls]
    phishing = sum(1 for r in results if r.get("verdict") == "PHISHING")
    return jsonify({"results": results, "total": len(results),
                    "phishing": phishing, "legitimate": len(results) - phishing})

@app.route("/api/history", methods=["GET"])
def api_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    return jsonify({"history": scan_history[:limit], "total": len(scan_history)})

@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    scan_history.clear()
    return jsonify({"message": "History cleared"})

@app.route("/api/blacklist/refresh", methods=["POST"])
def api_blacklist_refresh():
    if os.path.exists(BLACKLIST_PATH):
        os.remove(BLACKLIST_PATH)
    load_blacklist()
    return jsonify({"message": "Blacklist refreshed", "count": len(blacklist)})

@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({
        "status": "ok", "version": "2.0",
        "model_loaded": best_model is not None,
        "model_type": type(best_model).__name__ if best_model else None,
        "blacklist_size": len(blacklist),
        "trusted_domains": len(TRUSTED_DOMAINS),
        "scans_in_memory": len(scan_history),
        "feature_count": 33,
        "detection_stages": ["trusted_allowlist","blacklist","brand_heuristic","ml_model","heuristic_fallback"]
    })

if __name__ == "__main__":
    load_model()
    load_blacklist()
    app.run(debug=True, host="0.0.0.0", port=5000)
