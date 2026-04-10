"""ML Training Pipeline — Train threat classifier from SOC alert data.

Workflow:
  1. Export processed alerts from the database (or use synthetic data if < 50 alerts)
  2. Extract features using the feature engineering module
  3. Train RandomForest + GradientBoosting ensemble
  4. Evaluate with cross-validation
  5. Save model to models/threat_classifier.joblib
  6. Compare ML predictions vs Claude's triage scores

Usage:
  python scripts/train_ml.py              # Train from DB + synthetic augmentation
  python scripts/train_ml.py --synthetic  # Use only synthetic data
  python scripts/train_ml.py --evaluate   # Evaluate existing model against DB
  python scripts/train_ml.py --compare    # Compare ML vs Claude scores
"""

import asyncio
import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np


async def train_from_database():
    """Train model using real alerts from the database."""
    from src.ml.threat_classifier import (
        ThreatClassifier, export_training_data_from_db,
        generate_synthetic_training_data
    )
    from src.ml.feature_engineering import extract_features, get_feature_names

    print("\n" + "=" * 65)
    print("  Autonomous SOC — ML Threat Classifier Training Pipeline")
    print("=" * 65)

    # Step 1: Export from DB
    print("\n  [1/5] Exporting training data from database...")
    db_samples = 0
    X_db, y_db = None, None

    try:
        X_db, y_db = await export_training_data_from_db()
        db_samples = len(X_db)
        print(f"         ✅ Exported {db_samples} alerts from database")
    except Exception as e:
        print(f"         ⚠️  DB export failed: {e}")
        print(f"         Using synthetic data only")

    # Step 2: Generate synthetic data to augment
    print("\n  [2/5] Generating synthetic training data...")
    synthetic_count = max(200, 500 - db_samples)  # Always at least 200 synthetic
    X_syn, y_syn = generate_synthetic_training_data(synthetic_count)
    print(f"         ✅ Generated {synthetic_count} synthetic samples")

    # Step 3: Combine datasets
    print("\n  [3/5] Preparing combined dataset...")
    if X_db is not None and len(X_db) > 0:
        # Repeat real data 3x so the model learns from actual Claude scores
        X_real = np.tile(X_db, (3, 1))
        y_real = np.tile(y_db, 3)
        X = np.vstack([X_real, X_syn])
        y = np.concatenate([y_real, y_syn])
        print(f"         Combined: {db_samples}x3 real + {synthetic_count} synthetic = {len(X)} total")
    else:
        X, y = X_syn, y_syn
        print(f"         Using {len(X)} synthetic samples")

    # Show label distribution
    labels = [_score_to_label(s) for s in y]
    from collections import Counter
    dist = Counter(labels)
    print(f"         Distribution:")
    for label in ["critical", "high", "medium", "low", "info", "false_positive"]:
        count = dist.get(label, 0)
        bar = "█" * int(count / max(dist.values()) * 30)
        print(f"           {label:<16s} {count:4d} {bar}")

    # Step 4: Train
    print(f"\n  [4/5] Training ensemble model...")
    clf = ThreatClassifier()
    stats = clf.train(X, y)

    print(f"         ✅ Training complete!")
    print(f"         RandomForest  CV: {stats['rf_cv_accuracy']:.1%} ± {stats['rf_cv_std']:.1%}")
    print(f"         GradBoosting  CV: {stats['gb_cv_accuracy']:.1%} ± {stats['gb_cv_std']:.1%}")
    print(f"         Training time:    {stats['training_time_sec']}s")

    # Step 5: Save
    clf.save()
    print(f"\n  [5/5] Model saved to models/threat_classifier.joblib")

    # Feature importance
    print(f"\n  ┌─ TOP 15 FEATURES (by importance)")
    importance = clf.get_feature_importance()
    for i, (name, imp) in enumerate(list(importance.items())[:15], 1):
        bar = "█" * int(imp * 150)
        print(f"  │  {i:2d}. {name:<32s} {imp:.4f} {bar}")
    print(f"  └─\n")

    return clf


async def evaluate_model():
    """Evaluate existing model against database alerts."""
    from src.ml.threat_classifier import ThreatClassifier, export_training_data_from_db

    print("\n  Loading trained model...")
    clf = ThreatClassifier.load()

    print("  Exporting test data from database...")
    try:
        X, y = await export_training_data_from_db()
    except Exception as e:
        print(f"  ❌ No data: {e}")
        return

    results = clf.evaluate_detailed(X, y)

    print(f"\n  ┌─ EVALUATION RESULTS")
    print(f"  │  Test samples:      {len(X)}")
    print(f"  │  Ensemble Accuracy: {results['ensemble_accuracy']:.1%}")
    print(f"  │  RF Accuracy:       {results['rf_accuracy']:.1%}")
    print(f"  │  GB Accuracy:       {results['gb_accuracy']:.1%}")
    print(f"  │")
    print(f"  │  Classification Report:")
    for cls_name, metrics in results["classification_report"].items():
        if isinstance(metrics, dict) and "precision" in metrics:
            p = metrics["precision"]
            r = metrics["recall"]
            f1 = metrics["f1-score"]
            sup = int(metrics.get("support", 0))
            print(f"  │    {cls_name:<16s} P={p:.2f}  R={r:.2f}  F1={f1:.2f}  (n={sup})")
    print(f"  └─\n")


async def compare_ml_vs_claude():
    """Compare ML predictions against Claude's triage scores."""
    from src.ml.threat_classifier import ThreatClassifier
    from src.ml.feature_engineering import extract_features
    from src.database import get_db
    from src.models import Alert
    from sqlalchemy import select

    print("\n  Loading ML model...")
    try:
        clf = ThreatClassifier.load()
    except FileNotFoundError:
        print("  ❌ No trained model found. Run training first.")
        return

    print("  Loading alerts from database...")
    async with get_db() as db:
        result = await db.execute(
            select(Alert).where(Alert.triage_score.isnot(None))
        )
        alerts = result.scalars().all()

    if not alerts:
        print("  ❌ No alerts in database. Run load_dataset.py first.")
        return

    print(f"\n  ┌─ ML vs CLAUDE COMPARISON ({len(alerts)} alerts)")
    print(f"  │  {'Alert ID':<14s} {'Claude':>8s} {'ML':>8s} {'Δ':>7s} {'Claude Label':>14s} {'ML Label':>14s} {'Match':>6s}")
    print(f"  │  {'─'*75}")

    matches = 0
    total_delta = 0

    for alert in alerts:
        try:
            normalized = alert.normalized or {}
            raw_data = alert.raw_data or {}
            claude_score = alert.triage_score or 0.5
            claude_label = clf._score_to_label(claude_score)

            ml_score, ml_label = clf.predict(normalized, raw_data)
            delta = abs(claude_score - ml_score)
            total_delta += delta
            match = "✅" if claude_label == ml_label else "❌"
            if claude_label == ml_label:
                matches += 1

            print(f"  │  {str(alert.id)[:12]:<14s} {claude_score:>8.2f} {ml_score:>8.2f} "
                  f"{delta:>+7.2f} {claude_label:>14s} {ml_label:>14s} {match:>6s}")
        except Exception as e:
            print(f"  │  {str(alert.id)[:12]:<14s} Error: {e}")

    accuracy = matches / len(alerts) * 100 if alerts else 0
    avg_delta = total_delta / len(alerts) if alerts else 0

    print(f"  │  {'─'*75}")
    print(f"  │  Agreement Rate:    {accuracy:.1f}% ({matches}/{len(alerts)})")
    print(f"  │  Avg Score Delta:   {avg_delta:.3f}")
    print(f"  │  ")
    if accuracy >= 80:
        print(f"  │  ✅ ML and Claude are well-aligned")
    elif accuracy >= 60:
        print(f"  │  ⚠️  Moderate agreement — consider retraining with more data")
    else:
        print(f"  │  ❌ Low agreement — model needs more training data")
    print(f"  └─\n")


def _score_to_label(score: float) -> str:
    if score >= 0.90: return "critical"
    if score >= 0.70: return "high"
    if score >= 0.40: return "medium"
    if score >= 0.16: return "low"
    if score >= 0.06: return "info"
    return "false_positive"


async def main():
    args = sys.argv[1:]

    if "--evaluate" in args:
        await evaluate_model()
    elif "--compare" in args:
        await compare_ml_vs_claude()
    elif "--synthetic" in args:
        # Force synthetic-only training
        from src.ml.threat_classifier import ThreatClassifier, generate_synthetic_training_data
        clf = ThreatClassifier()
        X, y = generate_synthetic_training_data(500)
        stats = clf.train(X, y)
        clf.save()
        print(f"\n  ✅ Trained on 500 synthetic samples")
        print(f"     RF: {stats['rf_cv_accuracy']:.1%}  GB: {stats['gb_cv_accuracy']:.1%}\n")
    else:
        await train_from_database()


if __name__ == "__main__":
    asyncio.run(main())