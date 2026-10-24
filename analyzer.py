
import re
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from suspicious_terms import SUSPICIOUS_TERMS
from training_data import TRAINING_DATA


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_PATH = DATA_DIR / "training_messages.csv"
MODEL_PATH = BASE_DIR / "phishshift_model_v2.joblib"


def create_model():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(
        TRAINING_DATA,
        columns=["message", "label"]
    )

    df["message"] = df["message"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.lower()
    df = df[df["message"] != ""]

    if set(df["label"].unique()) != {"phishing", "safe"}:
        raise ValueError(
            "Training data must contain both 'phishing' and 'safe' labels."
        )

    df.to_csv(DATA_PATH, index=False)

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                sublinear_tf=True
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1500,
                class_weight="balanced",
                random_state=42
            )
        )
    ])

    model.fit(df["message"], df["label"])
    joblib.dump(model, MODEL_PATH)

    print(f"Training examples: {len(df)}")
    print(f"Model saved to: {MODEL_PATH}")

    return model


MODEL = create_model()


# Strong signals: requests or threats that deserve extra scrutiny.
STRONG_PHRASES = [
    "send your otp",
    "share your otp",
    "tell me your password",
    "provide your password",
    "share your password",
    "wallet recovery phrase",
    "private key",
    "avoid account closure",
    "account will be deleted",
    "account will be suspended",
    "pay a small fee to release",
    "claim your prize now",
    "verify your account immediately",
    "confirm your password immediately",
]

SENSITIVE_TERMS = [
    "password",
    "otp",
    "verification code",
    "card number",
    "recovery phrase",
    "private key",
    "pin number",
    "bank details",
]

URL_PATTERN = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>]+"
)

IP_URL_PATTERN = re.compile(
    r"(?i)(?:https?://|www\.)"
    r"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#][^\s]*)?"
)


def analyze_message(message):
    message = (message or "").strip()

    if not message:
        return {
            "score": 0,
            "risk": "Low",
            "reasons": ["Please enter a message to scan."],
            "prediction": "No message",
            "confidence": 0
        }

    text = message.lower()

    # 1. Machine-learning prediction.
    probabilities = MODEL.predict_proba([message])[0]
    classes = list(MODEL.classes_)
    phishing_probability = float(
        probabilities[classes.index("phishing")]
    )

    ml_score = round(phishing_probability * 100)

    # 2. Rule-based signals.
    matched_terms = [
        term for term in SUSPICIOUS_TERMS
        if term.lower() in text
    ]

    matched_strong = [
        phrase for phrase in STRONG_PHRASES
        if phrase in text
    ]

    matched_sensitive = [
        term for term in SENSITIVE_TERMS
        if term in text
    ]

    urls = URL_PATTERN.findall(message)
    ip_urls = IP_URL_PATTERN.findall(message)

    # Detect messages that combine a link with a request to act.
    action_terms = [
        "click", "verify", "confirm", "login",
        "sign in", "update", "claim", "pay"
    ]

    has_action = any(term in text for term in action_terms)
    link_with_action = bool(urls) and has_action

    # 3. Compute a rule score.
    # These weights are initial heuristic settings, not validated probabilities.
    rule_score = 0

    rule_score += min(len(matched_terms) * 8, 32)
    rule_score += min(len(matched_strong) * 20, 40)

    if urls:
        rule_score += 12

    if ip_urls:
        rule_score += 20

    if matched_sensitive:
        rule_score += 10

    if link_with_action:
        rule_score += 15

    rule_score = min(rule_score, 100)

    # 4. Combine ML and rule signals.
    # Strong rule signals can raise the result even if the small
    # demonstration model has a low phishing probability.
    score = round(
        0.55 * ml_score + 0.45 * rule_score
    )

    if matched_strong:
        score = max(score, 70)

    if ip_urls and link_with_action:
        score = max(score, 75)

    score = min(score, 100)

    # 5. Assign risk category.
    if score >= 65:
        risk = "High"
    elif score >= 35:
        risk = "Medium"
    else:
        risk = "Low"

    # 6. Explain the warning signals.
    reasons = []

    if matched_terms:
        reasons.append(
            "Suspicious phrases: "
            + ", ".join(matched_terms[:5])
        )

    if matched_strong:
        reasons.append(
            "Strong warning signals: "
            + ", ".join(matched_strong[:3])
        )

    if urls:
        reasons.append(
            "Contains a URL. Check the destination before opening it."
        )

    if ip_urls:
        reasons.append(
            "The link uses an IP address instead of a typical domain name."
        )

    if matched_sensitive:
        reasons.append(
            "Mentions sensitive information such as passwords, OTPs, or PINs."
        )

    if not reasons:
        reasons.append(
            "No configured warning signals were detected."
        )

    prediction = (
        "Phishing-like"
        if phishing_probability >= 0.5
        else "Likely safe"
    )

    return {
        "score": score,
        "risk": risk,
        "reasons": reasons,
        "prediction": prediction,
        "confidence": round(
            max(probabilities) * 100
        )
    }
