import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from feature_extraction import vectorize_url_list


import os

# output path can be overridden via env var or defaults to models/phishing_model.pkl
MODEL_OUTPUT_PATH = os.environ.get("MODEL_OUTPUT_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")))


def load_and_prepare(csv_path):
    df = pd.read_csv(csv_path)
    # assume label column is 1 for phishing, 0 for legitimate
    urls = df["url"].astype(str).tolist()
    X_dicts = vectorize_url_list(urls)
    X = pd.DataFrame(X_dicts)
    y = df["label"].astype(int)
    return train_test_split(X, y, test_size=0.2, random_state=42)


def train_and_select(csv_path):
    X_train, X_test, y_train, y_test = load_and_prepare(csv_path)

    models = {
        "random_forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "logistic_regression": LogisticRegression(max_iter=1000),
        "xgboost": XGBClassifier(use_label_encoder=False, eval_metric="logloss")
    }
    best_model = None
    best_score = 0
    results = {}

    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        acc = accuracy_score(y_test, preds)
        results[name] = acc
        print(f"{name} accuracy: {acc:.4f}")
        if acc > best_score:
            best_score = acc
            best_model = model

    if best_model is not None:
        # ensure directory exists
        os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)
        joblib.dump(best_model, MODEL_OUTPUT_PATH)
        print(f"Saved best model ({best_score:.4f}) to {MODEL_OUTPUT_PATH}")
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train phishing detection models")
    parser.add_argument("--data", required=True, help="Path to CSV dataset")
    args = parser.parse_args()

    stats = train_and_select(args.data)
    print("Training complete. Accuracy scores:", stats)
