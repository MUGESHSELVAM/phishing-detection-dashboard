import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

from feature_extraction import vectorize_url_list


import os

MODEL_PATH = os.environ.get("MODEL_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl")))


def evaluate(csv_path):
    df = pd.read_csv(csv_path)
    urls = df["url"].astype(str).tolist()
    X_dicts = vectorize_url_list(urls)
    X = pd.DataFrame(X_dicts)
    y = df["label"].astype(int)

    model = joblib.load(MODEL_PATH)
    preds = model.predict(X)
    probs = model.predict_proba(X)[:, 1]

    print("Accuracy:", accuracy_score(y, preds))
    print("Precision:", precision_score(y, preds))
    print("Recall:", recall_score(y, preds))
    print("F1 Score:", f1_score(y, preds))
    print("Confusion Matrix:\n", confusion_matrix(y, preds))

    # Optionally return dictionary
    return {
        "accuracy": accuracy_score(y, preds),
        "precision": precision_score(y, preds),
        "recall": recall_score(y, preds),
        "f1": f1_score(y, preds),
        "confusion_matrix": confusion_matrix(y, preds).tolist(),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate trained phishing model")
    parser.add_argument("--data", required=True, help="Path to CSV dataset for evaluation")
    args = parser.parse_args()

    evaluate(args.data)
