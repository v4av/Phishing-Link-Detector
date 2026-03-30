"""
URL Threat Scanner - Flask Backend
===================================
HOW TO RUN:
1. Install dependencies:
   pip install flask flask-cors requests dnspython
2. Start the server:
   python app.py
3. Visit http://localhost:5000 in your browser
"""

import re
import urllib.parse
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__, static_folder=".")
CORS(app)

import joblib
try:
    ML_DATA = joblib.load('phishing_model.pkl')
    ML_MODEL = ML_DATA['model']
    ML_FEATURES = ML_DATA['features']
    print("[+] Loaded Machine Learning Threat Engine.")
except Exception as e:
    ML_MODEL = None
    ML_FEATURES = None
    print("[-] ML Model not found. Falling back to dummy heuristics. Run train_model.py first.")


# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

# Drop your keys here to enable live threat intelligence
VIRUSTOTAL_API_KEY = ""          # https://www.virustotal.com/gui/my-apikey
GOOGLE_SAFE_BROWSING_KEY = ""   # https://developers.google.com/safe-browsing

# ──────────────────────────────────────────────
# HEURISTIC DATA
# ──────────────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".gq", ".cf", ".ml", ".ga",
    ".tk", ".pw", ".cc", ".su", ".ru", ".cn", ".info",
    ".biz", ".work", ".loan", ".download", ".stream"
}

PHISHING_KEYWORDS = [
    "verify", "login", "secure", "account", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "ebay", "netflix", "instagram", "facebook", "signin", "password",
    "credential", "alert", "suspended", "unusual", "unauthorized",
    "free", "winner", "prize", "claim", "limited", "offer",
    "click-here", "redirect", "locked", "recover", "support"
]

SAFE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "linkedin.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "apple.com", "microsoft.com", "amazon.com", "netflix.com",
    "instagram.com", "reddit.com", "medium.com", "openai.com"
}

# ──────────────────────────────────────────────
# ANALYSIS ENGINE
# ──────────────────────────────────────────────

def analyze_url(raw_url: str) -> dict:
    """
    Core URL analysis engine. Routes to the Machine Learning model if loaded,
    otherwise falls back to hardcoded dummy heuristics.
    """
    if ML_MODEL is not None and ML_FEATURES is not None:
        return analyze_url_ml(raw_url)
        
    findings = []
    score = 0

    # ── Normalize ──────────────────────────────
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().strip()
        path   = parsed.path.lower()
        query  = parsed.query.lower()
        full   = url.lower()
    except Exception:
        return _build_response(100, "Malicious",
                               [{"label": "Parse Error",
                                 "detail": "Could not parse URL.",
                                 "severity": "high"}])

    # Strip port for TLD checks
    bare_domain = domain.split(":")[0]
    tld = "." + bare_domain.rsplit(".", 1)[-1] if "." in bare_domain else ""

    # ── 1. Whitelist check ─────────────────────
    apex = ".".join(bare_domain.split(".")[-2:])
    if apex in SAFE_DOMAINS:
        findings.append({
            "label": "Trusted Domain",
            "detail": f"'{apex}' is a well-known, trusted domain.",
            "severity": "safe"
        })
        score = max(score - 15, 0)

    # ── 2. HTTPS check ─────────────────────────
    if parsed.scheme == "https":
        findings.append({
            "label": "HTTPS Enabled",
            "detail": "Connection is encrypted via TLS/SSL.",
            "severity": "safe"
        })
    else:
        findings.append({
            "label": "No HTTPS",
            "detail": "The URL uses plain HTTP — data is transmitted unencrypted.",
            "severity": "medium"
        })
        score += 20

    # ── 3. IP address as domain ────────────────
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(bare_domain):
        findings.append({
            "label": "IP Address Domain",
            "detail": "Domain is a raw IP address — a common phishing tactic.",
            "severity": "high"
        })
        score += 35

    # ── 4. Suspicious TLD ──────────────────────
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "label": "Suspicious TLD",
            "detail": f"Top-level domain '{tld}' is frequently abused by threat actors.",
            "severity": "high"
        })
        score += 25

    # ── 5. Phishing keywords ───────────────────
    hits = [kw for kw in PHISHING_KEYWORDS if kw in full]
    if hits:
        findings.append({
            "label": "Phishing Keywords Detected",
            "detail": f"Found suspicious terms: {', '.join(hits[:5])}.",
            "severity": "high" if len(hits) >= 3 else "medium"
        })
        score += min(len(hits) * 6, 30)

    # ── 6. URL length ──────────────────────────
    length = len(url)
    if length > 100:
        findings.append({
            "label": "Abnormally Long URL",
            "detail": f"URL is {length} characters — long URLs may conceal malicious destinations.",
            "severity": "medium"
        })
        score += 15
    elif length > 75:
        findings.append({
            "label": "Long URL",
            "detail": f"URL is {length} characters, slightly above average.",
            "severity": "low"
        })
        score += 5

    # ── 7. Excessive subdomains ────────────────
    parts = bare_domain.split(".")
    if len(parts) > 4:
        findings.append({
            "label": "Excessive Subdomains",
            "detail": f"Domain has {len(parts) - 2} subdomains — used to mimic trusted sites.",
            "severity": "medium"
        })
        score += 15

    # ── 8. Obfuscated characters ───────────────
    if "%" in url or "@" in domain or "//" in path:
        findings.append({
            "label": "Obfuscated Characters",
            "detail": "URL contains percent-encoding, @ symbols, or double slashes that hide the true destination.",
            "severity": "high"
        })
        score += 25

    # ── 9. Redirect indicators ────────────────
    redirect_params = ["url=", "redirect=", "next=", "goto=", "redir=", "link=", "target="]
    if any(p in query for p in redirect_params):
        findings.append({
            "label": "Open Redirect Indicator",
            "detail": "URL contains redirect parameters that may forward users to a malicious site.",
            "severity": "medium"
        })
        score += 20

    # ── 10. Numeric domain heuristic ──────────
    if re.search(r"\d{5,}", bare_domain):
        findings.append({
            "label": "Numeric Domain Pattern",
            "detail": "Domain contains a long numeric sequence, common in auto-generated phishing domains.",
            "severity": "medium"
        })
        score += 10

    # ── Clamp and classify ────────────────────
    score = min(score, 100)

    if apex in SAFE_DOMAINS and not ip_pattern.match(bare_domain):
        score = min(score, 20)

    if score <= 25:
        status = "Safe"
    elif score <= 60:
        status = "Suspicious"
    else:
        status = "Malicious"

    if not findings:
        findings.append({
            "label": "No Threats Detected",
            "detail": "This URL passed all heuristic checks.",
            "severity": "safe"
        })

    return _build_response(score, status, findings)


def analyze_url_ml(raw_url: str) -> dict:
    import pandas as pd
    from train_model import extract_features
    
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    try:
        feat = extract_features(url)
        df = pd.DataFrame([feat])[ML_FEATURES]
        prob = ML_MODEL.predict_proba(df)[0][1]
    except Exception as e:
        return _build_response(50, "Suspicious", [{"label": "ML Error", "detail": str(e), "severity": "high"}])
        
    score = int(prob * 100)
    
    if score <= 25:
        status = "Safe"
    elif score <= 60:
        status = "Suspicious"
    else:
        status = "Malicious"
        
    findings = []
    
    # Feature-based visual findings to explain the ML score
    if feat.get("url_length", 0) > 75:
        findings.append({"label": "Long URL", "detail": f"URL is {feat['url_length']} chars long.", "severity": "medium"})
    if feat.get("has_ip", 0):
        findings.append({"label": "IP Address", "detail": "URL uses an IP instead of a domain name.", "severity": "high"})
    if feat.get("keyword_count", 0) > 0:
        findings.append({"label": "Suspicious Keywords", "detail": f"Found {feat['keyword_count']} phishing keywords.", "severity": "high"})
    if feat.get("num_subdomains", 0) > 2:
        findings.append({"label": "Multiple Subdomains", "detail": "Contains many subdomains, standard in phishing.", "severity": "medium"})
    if not feat.get("is_https", 1):
        findings.append({"label": "No HTTPS", "detail": "Communication is unencrypted.", "severity": "medium"})
        
    severity_val = "safe" if status == "Safe" else ("high" if status == "Malicious" else "medium")
    findings.append({
        "label": "AI Machine Learning Engine",
        "detail": f"Random Forest model processed {len(ML_FEATURES)} features and predicted a {score}% threat probability.",
        "severity": severity_val
    })
    
    if len(findings) == 1 and status == "Safe":
        findings.append({
            "label": "No Threats Detected",
            "detail": "URL structure is clean and safe.",
            "severity": "safe"
        })
        
    return _build_response(score, status, findings)


def _build_response(score: int, status: str, findings: list) -> dict:
    return {
        "score":    score,
        "status":   status,
        "findings": findings
    }


# ──────────────────────────────────────────────
# OPTIONAL: VIRUSTOTAL INTEGRATION
# ──────────────────────────────────────────────

def check_virustotal(url: str) -> dict | None:
    """
    Checks a URL against VirusTotal's API.
    Requires VIRUSTOTAL_API_KEY to be set.
    Returns None if key is missing.
    """
    if not VIRUSTOTAL_API_KEY:
        return None

    try:
        import requests, base64
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            headers=headers, timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            return {"malicious_vendors": malicious, "stats": stats}
    except Exception as e:
        print(f"VirusTotal error: {e}")
    return None


# ──────────────────────────────────────────────
# OPTIONAL: GOOGLE SAFE BROWSING INTEGRATION
# ──────────────────────────────────────────────

def check_google_safe_browsing(url: str) -> dict | None:
    """
    Checks a URL against Google Safe Browsing API v4.
    Requires GOOGLE_SAFE_BROWSING_KEY to be set.
    Returns None if key is missing or URL is safe.
    """
    if not GOOGLE_SAFE_BROWSING_KEY:
        return None

    try:
        import requests
        payload = {
            "client": {"clientId": "url-threat-scanner", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}",
            json=payload, timeout=10
        )
        if resp.status_code == 200:
            matches = resp.json().get("matches", [])
            return {"flagged": len(matches) > 0, "matches": matches}
    except Exception as e:
        print(f"Google Safe Browsing error: {e}")
    return None


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided."}), 400

    result = analyze_url(url)

    # Enrich with VirusTotal (if key is set)
    vt = check_virustotal(url)
    if vt and vt.get("malicious_vendors", 0) > 0:
        result["score"] = min(result["score"] + vt["malicious_vendors"] * 5, 100)
        result["findings"].append({
            "label":    "VirusTotal Flagged",
            "detail":   f"{vt['malicious_vendors']} security vendors flagged this URL.",
            "severity": "high"
        })
        if result["score"] > 60:
            result["status"] = "Malicious"

    # Enrich with Google Safe Browsing (if key is set)
    gsb = check_google_safe_browsing(url)
    if gsb and gsb.get("flagged"):
        result["score"] = 100
        result["status"] = "Malicious"
        result["findings"].insert(0, {
            "label":    "Google Safe Browsing Alert",
            "detail":   "Google has flagged this URL as dangerous.",
            "severity": "high"
        })

    return jsonify(result)


if __name__ == "__main__":
    print("=" * 50)
    print("  URL Threat Scanner running at http://localhost:5005")
    print("=" * 50)
    app.run(debug=False, host='0.0.0.0', port=5005, threaded=True)
