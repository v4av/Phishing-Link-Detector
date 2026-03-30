import os
import re
import urllib.parse
import urllib.request
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Expanded list of phishing keywords
KEYWORDS = [
    "verify", "login", "secure", "account", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "google",
    "ebay", "netflix", "instagram", "facebook", "signin", "password",
    "credential", "alert", "suspended", "unusual", "unauthorized",
    "free", "winner", "prize", "claim", "limited", "offer",
    "click-here", "redirect", "locked", "recover", "support"
]

def extract_features(url):
    """ Extract structural features from a URL for ML training """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        path = parsed.path.lower()
    except Exception:
        domain = ""
        path = ""

    # Feature engineering
    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_at": url.count('@'),
        "num_query_params": url.count('?'),
        "num_equals": url.count('='),
        "num_subdomains": max(0, len(domain.split('.')) - 2),
        "has_ip": 1 if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", domain) else 0,
        "is_https": 1 if url.startswith("https") else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "keyword_count": sum(1 for kw in KEYWORDS if kw in url.lower())
    }
    return features


def get_dataset():
    """ Fetch real-time phishing URLs from OpenPhish and combine with safe examples. """
    print("Fetching real phishing data from OpenPhish...")
    phishing_urls = []
    try:
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            phishing_urls = response.read().decode('utf-8').splitlines()
            phishing_urls = [u.strip() for u in phishing_urls if u.strip()]
        print(f"Downloaded {len(phishing_urls)} real phishing URLs.")
    except Exception as e:
        print(f"Failed to fetch OpenPhish: {e}")
        # Fallback dataset
        phishing_urls = [
            "http://verify-account-update.secure-login.xyz",
            "http://192.168.1.1/paypal/recover.php",
            "http://netflix.account-suspended.com/login",
            "https://apple-id-verify.locked-alert.com",
            # Add some synthetic if openphish fails
        ] * 10 

    print("Generating benign dataset...")
    base_benign = [
        "https://google.com/", "https://youtube.com/watch", "https://facebook.com/profile",
        "https://twitter.com/search", "https://linkedin.com/in/", "https://github.com/explore",
        "https://stackoverflow.com/questions", "https://wikipedia.org/wiki/Main_Page",
        "https://apple.com/macbook", "https://microsoft.com/windows", "https://amazon.com/dp",
        "https://netflix.com/browse", "https://instagram.com/p", "https://reddit.com/r/technology",
        "https://medium.com/topic/technology", "https://openai.com/research",
        "https://news.ycombinator.com/", "https://weather.com/forecast",
        "https://en.wikipedia.org/wiki/Phishing", "https://docs.python.org/3/library/urllib.html"
    ]
    # Multiply and add variations to match length of phishing
    benign_urls = base_benign * max(1, len(phishing_urls) // len(base_benign))
    
    # Trim to balance
    min_len = min(len(phishing_urls), len(benign_urls))
    if min_len < 20: 
        min_len = len(phishing_urls)
    
    dataset = []
    for u in phishing_urls[:min_len]:
        feat = extract_features(u)
        feat['is_phishing'] = 1
        dataset.append(feat)
        
    for u in benign_urls[:min_len]:
        feat = extract_features(u)
        feat['is_phishing'] = 0
        dataset.append(feat)

    if not dataset:
        raise ValueError("Failed to create dataset.")
        
    return pd.DataFrame(dataset)

def train_model():
    df = get_dataset()
    print(f"Dataset shape: {df.shape}")
    
    X = df.drop('is_phishing', axis=1)
    y = df['is_phishing']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")
    
    # Save model and feature names
    joblib.dump({
        'model': model,
        'features': X.columns.tolist()
    }, 'phishing_model.pkl')
    print("Saved trained model to 'phishing_model.pkl'")

if __name__ == "__main__":
    train_model()
