import sys
import os
import joblib
import numpy as np
import pandas as pd

MODEL_PATH = "03-ml-detector/model.joblib"
TARGET_PATH = "04-evasion-and-hardening/evasion_targets.joblib"


def main():
    bundle = joblib.load(MODEL_PATH)
    clf = bundle["model"]
    feature_names = bundle["features"]

    targets = joblib.load(TARGET_PATH)
    X = targets["X"].reset_index(drop=True)
    print(f"loaded {len(X)} attack flows, all currently detected")

    importances = sorted(
        zip(clf.feature_importances_, feature_names), reverse=True
    )
    top_features = [name for _, name in importances[:10]]
    print(f"top 10 features by importance: {top_features}\n")

    # ---- Strategy 1: single-feature sweep ----
    print("Strategy 1: single-feature zeroing")
    best_feature = None
    best_flip = -1.0
    for f in top_features:
        X_mod = X.copy()
        X_mod[f] = 0
        preds = clf.predict(X_mod)
        flip_rate = (preds == 0).mean()
        print(f"  {f:32s} flip_rate={flip_rate:.4f}")
        if flip_rate > best_flip:
            best_flip = flip_rate
            best_feature = f
    print(f"\nbest single feature: {best_feature} (flip_rate={best_flip:.4f})\n")

    # ---- Strategy 2: greedy multi-feature ----
    print("Strategy 2: greedy top-K zeroing")
    for k in range(1, len(top_features) + 1):
        X_mod = X.copy()
        X_mod[top_features[:k]] = 0
        preds = clf.predict(X_mod)
        flip_rate = (preds == 0).mean()
        print(f"  k={k:2d}  features={top_features[:k]}  flip_rate={flip_rate:.4f}")


def realistic_evasion():
    """Strategy 3: perturb toward benign-typical values, realizable directions only."""
    import glob
    bundle = joblib.load(MODEL_PATH)
    clf = bundle["model"]
    feature_names = bundle["features"]

    targets = joblib.load(TARGET_PATH)
    X = targets["X"].reset_index(drop=True)

    # compute benign medians from the Monday (all-benign) capture
    DATA_DIR = "datasets/cic-ids-2017"
    monday = [f for f in glob.glob(f"{DATA_DIR}/*.csv") if "Monday" in f][0]
    dfb = pd.read_csv(monday, low_memory=False)
    dfb.columns = dfb.columns.str.strip()
    dfb["Label"] = dfb["Label"].str.strip()
    drop_cols = ["Label"]
    if "Fwd Header Length.1" in dfb.columns:
        drop_cols.append("Fwd Header Length.1")
    Xb = dfb.drop(columns=drop_cols).select_dtypes(include=[np.number])[feature_names]
    Xb = Xb.replace([np.inf, -np.inf], np.nan).fillna(0)
    benign_median = Xb.median()

    # realizable directions: an attacker can ADD bytes and ADD delay, i.e.
    # INCREASE packet lengths, sizes, durations, and inter-arrival times.
    # These features can realistically be pushed UP toward benign medians.
    realizable_up = [
        "Average Packet Size", "Max Packet Length", "Fwd Packet Length Max",
        "Packet Length Std", "Avg Bwd Segment Size", "Fwd Packet Length Min",
        "Bwd Packet Length Min",
    ]

    print("\nStrategy 3: realistic perturbation toward benign medians")
    print("(only features an attacker can physically increase via padding)")

    for k in range(1, len(realizable_up) + 1):
        X_mod = X.copy()
        for f in realizable_up[:k]:
            # push toward benign median only if it means INCREASING (padding)
            target = benign_median[f]
            X_mod[f] = np.maximum(X_mod[f], target)
        flip = (clf.predict(X_mod) == 0).mean()
        print(f"  pad top-{k} size features -> flip_rate={flip:.4f}  (+{realizable_up[k-1]})")


if __name__ == "__main__":
    main()
    realistic_evasion()
