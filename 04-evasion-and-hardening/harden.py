import sys
import os
import glob
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "03-ml-detector"))
import features as feat

DATA_DIR = "datasets/cic-ids-2017"
ORIG_MODEL = "03-ml-detector/model.joblib"
HARDENED_MODEL = "04-evasion-and-hardening/model_hardened.joblib"

# same realizable padding features used in the evasion
REALIZABLE_UP = [
    "Average Packet Size", "Max Packet Length", "Fwd Packet Length Max",
    "Packet Length Std", "Avg Bwd Segment Size", "Fwd Packet Length Min",
    "Bwd Packet Length Min",
]


def benign_medians(feature_names):
    monday = [f for f in glob.glob(f"{DATA_DIR}/*.csv") if "Monday" in f][0]
    dfb = pd.read_csv(monday, low_memory=False)
    dfb.columns = dfb.columns.str.strip()
    dfb["Label"] = dfb["Label"].str.strip()
    drop = ["Label"]
    if "Fwd Header Length.1" in dfb.columns:
        drop.append("Fwd Header Length.1")
    Xb = dfb.drop(columns=drop).select_dtypes(include=[np.number])[feature_names]
    Xb = Xb.replace([np.inf, -np.inf], np.nan).fillna(0)
    return Xb.median()


def pad_attacks(X_attack, medians):
    """Produce adversarially padded copies of attack flows (still attacks)."""
    X_pad = X_attack.copy()
    for f in REALIZABLE_UP:
        X_pad[f] = np.maximum(X_pad[f], medians[f])
    return X_pad


def evasion_rate(clf, X_attack, medians):
    """Fraction of attack flows that evade (predicted benign) after padding."""
    X_ev = pad_attacks(X_attack, medians)
    return (clf.predict(X_ev) == 0).mean()


def main():
    X, y, names = feat.load_dataset()
    medians = benign_medians(names)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # baseline (original) model evasion on padded attacks from the test set
    orig = joblib.load(ORIG_MODEL)["model"]
    attack_test = X_test[y_test == 1]
    before = evasion_rate(orig, attack_test, medians)
    print(f"BEFORE hardening: padded-attack evasion rate = {before:.4f}")

    # ---- adversarial training ----
    attack_train = X_train[y_train == 1]
    X_pad = pad_attacks(attack_train, medians)
    y_pad = np.ones(len(X_pad), dtype=int)

    X_aug = pd.concat([X_train, X_pad], ignore_index=True)
    y_aug = np.concatenate([y_train.values, y_pad])

    clf = RandomForestClassifier(
        n_estimators=100, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    print(f"training hardened model on {len(X_aug)} flows "
          f"({len(X_train)} original + {len(X_pad)} padded)...")
    clf.fit(X_aug, y_aug)

    joblib.dump({"model": clf, "features": names}, HARDENED_MODEL)

    # after hardening: same padded-attack evasion measurement
    hardened = joblib.load(HARDENED_MODEL)["model"]
    after = evasion_rate(hardened, attack_test, medians)
    print(f"AFTER hardening:  padded-attack evasion rate = {after:.4f}")

    # sanity: hardened model must still detect NORMAL (unpadded) attacks
    normal_recall = (hardened.predict(attack_test) == 1).mean()
    print(f"hardened model recall on NORMAL attacks = {normal_recall:.4f}")

    # sanity: hardened model must not wreck benign precision
    benign_test = X_test[y_test == 0]
    benign_correct = (hardened.predict(benign_test) == 0).mean()
    print(f"hardened model specificity on benign = {benign_correct:.4f}")


if __name__ == "__main__":
    main()
