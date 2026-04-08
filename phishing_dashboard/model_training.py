"""
model_training.py — Machine Learning Model Training
Phishing Detection Dashboard

Downloads a real phishing URL dataset (PhiUSIIIT, 235k+ URLs from UCI),
trains a Random Forest classifier, evaluates it with proper metrics,
and persists the model.

Run once before starting the Flask app:
    python model_training.py

Options:
    python model_training.py --samples 5000  # URLs per class (default 3000)
    python model_training.py --whois         # include WHOIS features (slower)
    python model_training.py --compare       # also train Logistic Regression
"""
import os, sys, json, argparse, logging
import joblib, numpy as np, pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report,
    confusion_matrix, average_precision_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.inspection import permutation_importance

from config import config
from dataset_loader import load_dataset
from feature_extraction import get_feature_names

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)
SEED = 42
np.random.seed(SEED)


def build_random_forest() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=300, max_depth=20,
            min_samples_split=3, min_samples_leaf=1,
            max_features="sqrt", class_weight="balanced",
            random_state=SEED, n_jobs=-1,
        )),
    ])


def build_logistic_regression() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            C=1.0, max_iter=1000, class_weight="balanced",
            random_state=SEED, solver="lbfgs",
        )),
    ])


MODELS = {
    "RandomForest":       build_random_forest,
    "LogisticRegression": build_logistic_regression,
}


def evaluate(pipeline, X_train, X_test, y_train, y_test,
             feature_names, X_all=None, y_all=None) -> dict:
    pipeline.fit(X_train, y_train)
    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy":         round(accuracy_score(y_test, y_pred)  * 100, 2),
        "precision":        round(precision_score(y_test, y_pred, zero_division=0) * 100, 2),
        "recall":           round(recall_score(y_test, y_pred, zero_division=0) * 100, 2),
        "f1_score":         round(f1_score(y_test, y_pred, zero_division=0) * 100, 2),
        "auc_roc":          round(roc_auc_score(y_test, y_proba) * 100, 2),
        "avg_precision":    round(average_precision_score(y_test, y_proba) * 100, 2),
        "train_samples":    int(len(X_train)),
        "test_samples":     int(len(X_test)),
        "feature_count":    int(len(feature_names)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    if X_all is not None and y_all is not None:
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
        cv_res = cross_validate(pipeline, X_all, y_all, cv=cv,
                                scoring=["accuracy","f1","roc_auc"], n_jobs=-1)
        metrics["cv_accuracy_mean"] = round(cv_res["test_accuracy"].mean() * 100, 2)
        metrics["cv_accuracy_std"]  = round(cv_res["test_accuracy"].std()  * 100, 2)
        metrics["cv_f1_mean"]       = round(cv_res["test_f1"].mean()       * 100, 2)
        metrics["cv_auc_mean"]      = round(cv_res["test_roc_auc"].mean()  * 100, 2)

    clf = pipeline.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        raw_imp = clf.feature_importances_
    else:
        X_scaled = pipeline.named_steps["scaler"].transform(X_test)
        perm = permutation_importance(clf, X_scaled, y_test, n_repeats=5, random_state=SEED)
        raw_imp = perm.importances_mean

    feat_imp = sorted(zip(feature_names, raw_imp), key=lambda x: x[1], reverse=True)
    metrics["top_features"] = [
        {"name": n, "importance": round(float(i), 6)} for n, i in feat_imp[:15]
    ]
    return metrics


def train(samples_per_class: int = 3000, use_whois: bool = False,
          compare_models: bool = False) -> dict:
    logger.info("Loading dataset (samples_per_class=%d, whois=%s) …", samples_per_class, use_whois)
    df = load_dataset(sample_per_class=samples_per_class, use_whois=use_whois)

    feature_names = get_feature_names()
    for f in feature_names:
        if f not in df.columns:
            df[f] = 0

    X = df[feature_names].fillna(0).values
    y = df["label"].values
    logger.info("Dataset: %d samples | Phishing: %d | Legit: %d", len(y), y.sum(), (y==0).sum())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y)

    results    = {}
    model_keys = list(MODELS.keys()) if compare_models else ["RandomForest"]

    for name in model_keys:
        logger.info("Training %s …", name)
        pipeline = MODELS[name]()
        metrics  = evaluate(pipeline, X_train, X_test, y_train, y_test,
                             feature_names, X, y)
        results[name] = (pipeline, metrics)

        sep = "=" * 56
        print(f"\n{sep}\n  {name}\n{sep}")
        print(f"  Accuracy  : {metrics['accuracy']}%")
        print(f"  Precision : {metrics['precision']}%")
        print(f"  Recall    : {metrics['recall']}%")
        print(f"  F1 Score  : {metrics['f1_score']}%")
        print(f"  AUC-ROC   : {metrics['auc_roc']}%")
        if "cv_accuracy_mean" in metrics:
            print(f"  CV Accuracy: {metrics['cv_accuracy_mean']}% ± {metrics['cv_accuracy_std']}%")
            print(f"  CV AUC     : {metrics['cv_auc_mean']}%")
        print(sep)
        print(classification_report(y_test, pipeline.predict(X_test),
                                    target_names=["Legitimate","Phishing"]))

    best_name = max(results, key=lambda n: results[n][1]["auc_roc"])
    best_pipeline, best_metrics = results[best_name]
    best_metrics["model_name"] = best_name
    logger.info("Best model: %s  (AUC=%.2f%%)", best_name, best_metrics["auc_roc"])

    os.makedirs(os.path.dirname(config.MODEL_PATH), exist_ok=True)
    joblib.dump(best_pipeline, config.MODEL_PATH)
    joblib.dump(feature_names, config.FEATURES_PATH)
    metrics_path = config.MODEL_PATH.replace(".pkl", "_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(best_metrics, f, indent=2)

    print(f"\n  ✓ Model saved    → {config.MODEL_PATH}")
    print(f"  ✓ Features saved → {config.FEATURES_PATH}")
    print(f"  ✓ Metrics saved  → {metrics_path}\n")
    return best_metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the PhishyGuard ML model")
    parser.add_argument("--samples", type=int, default=3000)
    parser.add_argument("--whois",   action="store_true")
    parser.add_argument("--compare", action="store_true")
    args = parser.parse_args()
    train(samples_per_class=args.samples, use_whois=args.whois, compare_models=args.compare)
