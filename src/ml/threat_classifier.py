"""Threat Classifier — ML-based alert scoring using scikit-learn.

Trains on historical alert data (triage scores + analyst feedback) to build
a fast, offline threat classifier that can:
  1. Pre-screen alerts before Claude (reduces API costs)
  2. Provide a second opinion alongside Claude's triage
  3. Detect drift between ML and LLM scores
  4. Run when Claude API is unavailable (fallback mode)

Models:
  - RandomForestClassifier (primary): Good with mixed feature types
  - GradientBoostingClassifier (secondary): Better calibrated probabilities
  - Ensemble: Average of both for final score

Usage:
  # Train from database
  python -m src.ml.threat_classifier train

  # Evaluate with cross-validation
  python -m src.ml.threat_classifier evaluate

  # Predict on a single alert
  from src.ml.threat_classifier import ThreatClassifier
  clf = ThreatClassifier.load()
  score, label = clf.predict(normalized_data, raw_data)
"""

import os
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import structlog

logger = structlog.get_logger()

MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "threat_classifier.joblib"
DATA_DIR = Path("data")
TRAINING_DATA_PATH = DATA_DIR / "training_data.csv"


class ThreatClassifier:
    """Ensemble ML classifier for threat scoring.

    Uses RandomForest + GradientBoosting ensemble trained on
    historical alert data from the SOC database.
    """

    LABELS = ["false_positive", "info", "low", "medium", "high", "critical"]
    SCORE_MAP = {"false_positive": 0.05, "info": 0.10, "low": 0.30,
                 "medium": 0.55, "high": 0.80, "critical": 0.95}

    def __init__(self):
        self.rf_model = None
        self.gb_model = None
        self.scaler = None
        self.is_trained = False
        self.training_stats = {}

    def train(self, X: np.ndarray, y: np.ndarray, labels: Optional[List[str]] = None):
        """Train the ensemble classifier.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Target scores (float 0.0-1.0) — will be binned into severity labels
            labels: Optional pre-assigned severity labels (overrides score binning)
        """
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.preprocessing import StandardScaler, LabelEncoder
        from sklearn.model_selection import cross_val_score

        start = time.time()

        # Bin scores into severity labels if not provided
        if labels is None:
            labels = [self._score_to_label(s) for s in y]

        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(labels)

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train RandomForest
        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.rf_model.fit(X_scaled, y_encoded)

        # Train GradientBoosting
        self.gb_model = GradientBoostingClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.1,
            min_samples_split=5,
            subsample=0.8,
            random_state=42,
        )
        self.gb_model.fit(X_scaled, y_encoded)

        # Cross-validate
        rf_cv = cross_val_score(self.rf_model, X_scaled, y_encoded, cv=min(5, len(X)), scoring="accuracy")
        gb_cv = cross_val_score(self.gb_model, X_scaled, y_encoded, cv=min(5, len(X)), scoring="accuracy")

        self.is_trained = True
        elapsed = round(time.time() - start, 2)

        self.training_stats = {
            "samples": len(X),
            "features": X.shape[1],
            "classes": list(self.label_encoder.classes_),
            "rf_cv_accuracy": round(float(np.mean(rf_cv)), 4),
            "rf_cv_std": round(float(np.std(rf_cv)), 4),
            "gb_cv_accuracy": round(float(np.mean(gb_cv)), 4),
            "gb_cv_std": round(float(np.std(gb_cv)), 4),
            "training_time_sec": elapsed,
        }

        logger.info("ml_model_trained", **self.training_stats)
        return self.training_stats

    def predict(self, normalized: Dict[str, Any], raw_data: Dict[str, Any]) -> Tuple[float, str]:
        """Predict threat score and severity label for a single alert.

        Returns: (score: float 0.0-1.0, label: str)
        """
        if not self.is_trained:
            raise RuntimeError("Model not trained. Call train() or load() first.")

        from src.ml.feature_engineering import extract_features

        features = extract_features(normalized, raw_data).reshape(1, -1)
        X_scaled = self.scaler.transform(features)

        # Ensemble prediction: average probabilities from both models
        rf_proba = self.rf_model.predict_proba(X_scaled)[0]
        gb_proba = self.gb_model.predict_proba(X_scaled)[0]
        avg_proba = (rf_proba + gb_proba) / 2.0

        predicted_idx = np.argmax(avg_proba)
        label = self.label_encoder.inverse_transform([predicted_idx])[0]
        confidence = float(avg_proba[predicted_idx])

        # Convert label to score
        score = self.SCORE_MAP.get(label, 0.5)

        # Adjust score by confidence
        score = score * 0.7 + confidence * 0.3

        return round(score, 3), label

    def predict_batch(self, feature_matrix: np.ndarray) -> List[Tuple[float, str]]:
        """Predict on a batch of pre-extracted features."""
        if not self.is_trained:
            raise RuntimeError("Model not trained.")

        X_scaled = self.scaler.transform(feature_matrix)
        rf_proba = self.rf_model.predict_proba(X_scaled)
        gb_proba = self.gb_model.predict_proba(X_scaled)
        avg_proba = (rf_proba + gb_proba) / 2.0

        results = []
        for proba in avg_proba:
            idx = np.argmax(proba)
            label = self.label_encoder.inverse_transform([idx])[0]
            score = self.SCORE_MAP.get(label, 0.5) * 0.7 + float(proba[idx]) * 0.3
            results.append((round(score, 3), label))
        return results

    def get_feature_importance(self) -> Dict[str, float]:
        """Return feature importance rankings from RandomForest."""
        if not self.is_trained:
            return {}
        from src.ml.feature_engineering import get_feature_names
        names = get_feature_names()
        importances = self.rf_model.feature_importances_
        ranked = sorted(zip(names, importances), key=lambda x: x[1], reverse=True)
        return {name: round(float(imp), 4) for name, imp in ranked[:20]}

    def evaluate_detailed(self, X: np.ndarray, y_true: np.ndarray) -> Dict[str, Any]:
        """Run detailed evaluation with confusion matrix and classification report."""
        from sklearn.metrics import classification_report, confusion_matrix

        labels_true = [self._score_to_label(s) for s in y_true]
        y_encoded = self.label_encoder.transform(labels_true)
        X_scaled = self.scaler.transform(X)

        rf_pred = self.rf_model.predict(X_scaled)
        gb_pred = self.gb_model.predict(X_scaled)

        # Ensemble
        rf_proba = self.rf_model.predict_proba(X_scaled)
        gb_proba = self.gb_model.predict_proba(X_scaled)
        ensemble_pred = np.argmax((rf_proba + gb_proba) / 2.0, axis=1)

        report = classification_report(y_encoded, ensemble_pred,
                                       target_names=self.label_encoder.classes_,
                                       output_dict=True, zero_division=0)
        cm = confusion_matrix(y_encoded, ensemble_pred)

        return {
            "classification_report": report,
            "confusion_matrix": cm.tolist(),
            "ensemble_accuracy": float(np.mean(ensemble_pred == y_encoded)),
            "rf_accuracy": float(np.mean(rf_pred == y_encoded)),
            "gb_accuracy": float(np.mean(gb_pred == y_encoded)),
        }

    def save(self, path: Optional[str] = None):
        """Save trained model to disk."""
        import joblib
        path = Path(path or MODEL_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "rf_model": self.rf_model,
            "gb_model": self.gb_model,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "training_stats": self.training_stats,
            "is_trained": self.is_trained,
        }, path)
        logger.info("ml_model_saved", path=str(path))

    @classmethod
    def load(cls, path: Optional[str] = None) -> "ThreatClassifier":
        """Load a trained model from disk."""
        import joblib
        path = Path(path or MODEL_PATH)
        if not path.exists():
            raise FileNotFoundError(f"No trained model at {path}. Run training first.")
        data = joblib.load(path)
        obj = cls()
        obj.rf_model = data["rf_model"]
        obj.gb_model = data["gb_model"]
        obj.scaler = data["scaler"]
        obj.label_encoder = data["label_encoder"]
        obj.training_stats = data["training_stats"]
        obj.is_trained = data["is_trained"]
        logger.info("ml_model_loaded", path=str(path), stats=obj.training_stats)
        return obj

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 0.90:
            return "critical"
        if score >= 0.70:
            return "high"
        if score >= 0.40:
            return "medium"
        if score >= 0.16:
            return "low"
        if score >= 0.06:
            return "info"
        return "false_positive"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Training Pipeline — Export from DB → Train → Save
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def export_training_data_from_db() -> Tuple[np.ndarray, np.ndarray]:
    """Export processed alerts from database as training data.

    Returns: (X, y) feature matrix and score vector
    """
    from src.ml.feature_engineering import extract_features
    from src.database import get_db
    from src.models import Alert
    from sqlalchemy import select

    X_list = []
    y_list = []

    async with get_db() as db:
        result = await db.execute(
            select(Alert).where(Alert.triage_score.isnot(None))
        )
        alerts = result.scalars().all()

    for alert in alerts:
        try:
            normalized = alert.normalized or {}
            raw_data = alert.raw_data or {}
            features = extract_features(normalized, raw_data)
            X_list.append(features)

            # Use analyst feedback label if available, otherwise use AI score
            if alert.feedback_label and alert.feedback_label == "false_positive":
                y_list.append(0.05)
            else:
                y_list.append(alert.triage_score or 0.5)
        except Exception as e:
            logger.warning("feature_extraction_failed", alert_id=alert.id, error=str(e))
            continue

    if not X_list:
        raise ValueError("No training data available. Process some alerts first.")

    return np.array(X_list), np.array(y_list)


def generate_synthetic_training_data(n_samples: int = 500) -> Tuple[np.ndarray, np.ndarray]:
    """Generate synthetic training data for initial model bootstrap.

    Creates realistic-looking alert features with known severity labels.
    Use this when you don't have enough real alerts in the database.
    """
    from src.ml.feature_engineering import extract_features

    np.random.seed(42)
    X_list = []
    y_list = []

    # Alert templates with known severity levels
    templates = [
        # Critical alerts
        (0.95, {"event_type": "mass_file_encryption", "hostname": "FS-01",
                "message": "Mass file encryption detected — ransomware activity", "files_affected": 2847}),
        (0.92, {"event_type": "c2_beacon", "src_ip": "10.0.3.5", "dest_ip": "185.220.101.1",
                "message": "C2 beacon to known APT infrastructure", "interval_sec": 60}),
        (0.94, {"event_type": "credential_dump", "hostname": "DC-01",
                "message": "Mimikatz credential harvesting detected", "technique": "T1003.001"}),
        (0.93, {"event_type": "golden_ticket", "hostname": "DC-01",
                "message": "Kerberos golden ticket attack detected", "technique": "T1558.001"}),
        # High alerts
        (0.82, {"event_type": "ssh_brute_force", "src_ip": "45.33.32.156", "dest_ip": "10.0.1.20",
                "message": "342 failed SSH login attempts", "count": 342}),
        (0.80, {"event_type": "sql_injection", "src_ip": "103.245.67.89", "dest_ip": "10.0.1.50",
                "message": "SQL injection attempt with sqlmap detected", "dest_port": 443}),
        (0.78, {"event_type": "data_exfiltration", "src_ip": "10.0.5.30",
                "message": "4.2GB data transfer via DNS tunneling", "bytes_transferred": 4509715660}),
        (0.75, {"event_type": "suspicious_download", "hostname": "WS-HR-02",
                "message": "Executable downloaded from malicious domain", "dest_ip": "91.215.85.120"}),
        # Medium alerts
        (0.55, {"event_type": "port_scan", "src_ip": "10.0.2.100",
                "message": "Internal port scan detected — 500 ports in 30 seconds", "count": 500}),
        (0.50, {"event_type": "policy_violation", "hostname": "WS-DEV-03",
                "message": "Unauthorized software installation detected"}),
        (0.45, {"event_type": "network_anomaly", "src_ip": "10.0.4.15",
                "message": "Unusual outbound traffic volume at 3AM", "bytes_transferred": 500000000}),
        # Low alerts
        (0.25, {"event_type": "ssh_auth_failure", "src_ip": "10.0.1.100", "dest_ip": "10.0.1.20",
                "message": "Failed SSH login from internal host", "count": 3}),
        (0.20, {"event_type": "account_lockout", "hostname": "WS-ACCT-01",
                "message": "Account locked after 5 failed attempts"}),
        # Info / False Positive
        (0.08, {"event_type": "policy_violation", "hostname": "WS-IT-01",
                "message": "Scheduled Windows Update download detected"}),
        (0.05, {"event_type": "network_anomaly", "src_ip": "10.0.1.1",
                "message": "Routine backup traffic spike during maintenance window"}),
        (0.03, {"event_type": "ssh_auth_failure", "src_ip": "10.0.1.50", "dest_ip": "10.0.1.20",
                "message": "Single SSH failure — likely mistyped password", "count": 1}),
    ]

    for _ in range(n_samples):
        score, base_data = templates[np.random.randint(len(templates))]

        # Add random noise to make each sample unique
        data = dict(base_data)
        noise = np.random.normal(0, 0.03)
        noisy_score = np.clip(score + noise, 0.0, 1.0)

        # Randomly vary some fields
        if "count" in data:
            data["count"] = max(1, int(data["count"] * np.random.uniform(0.5, 1.5)))
        if "bytes_transferred" in data:
            data["bytes_transferred"] = int(data["bytes_transferred"] * np.random.uniform(0.3, 2.0))

        normalized = {"event_type": data.get("event_type", "other"),
                      "source_ip": data.get("src_ip", ""),
                      "dest_ip": data.get("dest_ip", ""),
                      "description": data.get("message", ""),
                      "hostname": data.get("hostname", ""),
                      "indicators": {}}

        features = extract_features(normalized, data)
        X_list.append(features)
        y_list.append(noisy_score)

    return np.array(X_list), np.array(y_list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI Entry Point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if __name__ == "__main__":
    import sys
    import asyncio

    cmd = sys.argv[1] if len(sys.argv) > 1 else "train"

    if cmd == "train":
        print("\n" + "=" * 60)
        print("  Autonomous SOC — ML Threat Classifier Training")
        print("=" * 60)

        clf = ThreatClassifier()

        # Try to load from DB first
        try:
            X, y = asyncio.run(export_training_data_from_db())
            print(f"\n  Loaded {len(X)} alerts from database")
        except Exception as e:
            print(f"\n  DB export failed ({e}), using synthetic data...")
            X, y = generate_synthetic_training_data(500)
            print(f"  Generated {len(X)} synthetic training samples")

        stats = clf.train(X, y)
        clf.save()

        print(f"\n  ✅ Model trained successfully!")
        print(f"     Samples:       {stats['samples']}")
        print(f"     Features:      {stats['features']}")
        print(f"     RF CV Acc:     {stats['rf_cv_accuracy']:.1%} ± {stats['rf_cv_std']:.1%}")
        print(f"     GB CV Acc:     {stats['gb_cv_accuracy']:.1%} ± {stats['gb_cv_std']:.1%}")
        print(f"     Training time: {stats['training_time_sec']}s")
        print(f"     Saved to:      {MODEL_PATH}\n")

        # Show top features
        importance = clf.get_feature_importance()
        print("  Top 10 Features:")
        for i, (name, imp) in enumerate(list(importance.items())[:10], 1):
            bar = "█" * int(imp * 100)
            print(f"    {i:2d}. {name:<30s} {imp:.4f} {bar}")
        print()

    elif cmd == "evaluate":
        print("\n  Evaluating model...")
        clf = ThreatClassifier.load()
        X, y = generate_synthetic_training_data(200)
        results = clf.evaluate_detailed(X, y)
        print(f"  Ensemble Accuracy: {results['ensemble_accuracy']:.1%}")
        print(f"  RF Accuracy:       {results['rf_accuracy']:.1%}")
        print(f"  GB Accuracy:       {results['gb_accuracy']:.1%}")
        print(f"\n  Classification Report:")
        for cls_name, metrics in results["classification_report"].items():
            if isinstance(metrics, dict):
                print(f"    {cls_name:<16s} P={metrics.get('precision',0):.2f} "
                      f"R={metrics.get('recall',0):.2f} F1={metrics.get('f1-score',0):.2f}")

    else:
        print(f"Unknown command: {cmd}")
        print("Usage: python -m src.ml.threat_classifier [train|evaluate]")