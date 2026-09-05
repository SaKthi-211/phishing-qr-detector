"""
train_model.py
----------------
Running this script generates a labeled synthetic dataset (legitimate +
phishing URL patterns) and uses it to train a RandomForestClassifier.
The trained model + scaler are saved to the `model/` folder
(phishing_model.pkl, scaler.pkl).

In a real-world scenario we could use a real dataset (PhishTank / UCI
Phishing dataset), but since this is an offline academic demo project,
we generate a synthetic dataset using realistic heuristic patterns -
it follows the same feature engineering pipeline, so the trained model's
logic is still representative of production-style detection.

Run: python3 train_model.py
"""

import random
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler

from feature_extractor import extract_features, features_to_vector, FEATURE_ORDER

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "stackoverflow.com",
    "amazon.com", "flipkart.com", "microsoft.com", "apple.com",
    "nytimes.com", "bbc.com", "linkedin.com", "python.org",
    "anna.univ.edu.in", "ieee.org", "nature.com", "coursera.org",
    "khanacademy.org", "mozilla.org", "reddit.com", "spotify.com",
    "netflix.com", "adobe.com", "dropbox.com", "twitter.com", "medium.com",
]

LEGIT_PATHS = [
    "", "/", "/about", "/products", "/docs/guide", "/search?q=python",
    "/user/profile", "/blog/2026/tech-trends", "/watch?v=abcd1234",
    "/articles/machine-learning", "/course/data-structures",
]

PHISHING_BRANDS = ["paypal", "amazon", "apple", "microsoft", "netflix",
                   "bankofamerica", "instagram", "flipkart", "google"]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "loan"]

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update",
                     "confirm", "signin", "billing", "suspend", "unlock",
                     "recover", "wallet", "authenticate"]

SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rebrand.ly"]


def random_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"  # legitimate sites almost always use https
    return f"{scheme}://www.{domain}{path}"


def random_phishing_url():
    style = random.choice(["ip", "shortener", "brand_subdomain", "long_suspicious", "hyphen_typo"])

    if style == "ip":
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        word = random.choice(SUSPICIOUS_WORDS)
        return f"http://{ip}/{word}/{random.choice(PHISHING_BRANDS)}-account"

    if style == "shortener":
        short = random.choice(SHORTENERS)
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
        return f"http://{short}/{code}"

    if style == "brand_subdomain":
        brand = random.choice(PHISHING_BRANDS)
        word = random.choice(SUSPICIOUS_WORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{brand}-{word}.secure-{random.randint(100,999)}.{tld}"

    if style == "long_suspicious":
        brand = random.choice(PHISHING_BRANDS)
        words = "-".join(random.sample(SUSPICIOUS_WORDS, 3))
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{words}-{brand}.{tld}/{words}?session={random.randint(10000,99999)}&id=1"

    # hyphen_typo
    brand = random.choice(PHISHING_BRANDS)
    word = random.choice(SUSPICIOUS_WORDS)
    return f"http://www.{brand}-{word}-support.com/{word}.php?user=1@2"


def build_dataset(n_per_class: int = 1500) -> pd.DataFrame:
    rows = []
    for _ in range(n_per_class):
        feats = extract_features(random_legit_url())
        feats["label"] = 0  # 0 = legitimate
        rows.append(feats)

    for _ in range(n_per_class):
        feats = extract_features(random_phishing_url())
        feats["label"] = 1  # 1 = phishing
        rows.append(feats)

    df = pd.DataFrame(rows)
    return df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle


def main():
    print("[*] Generating synthetic dataset...")
    df = build_dataset(n_per_class=2000)
    print(f"[*] Dataset ready: {len(df)} rows, {df['label'].value_counts().to_dict()}")

    X = df[FEATURE_ORDER]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[*] Training RandomForestClassifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    print(f"[+] Test Accuracy: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    joblib.dump(model, "phishing_model.pkl")
    joblib.dump(scaler, "scaler.pkl")
    print("[+] Model saved -> phishing_model.pkl")
    print("[+] Scaler saved -> scaler.pkl")


if __name__ == "__main__":
    main()
