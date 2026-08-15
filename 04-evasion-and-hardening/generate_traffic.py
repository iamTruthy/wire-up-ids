import sys
import os
import glob
import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "03-ml-detector"))

MODEL_PATH = "03-ml-detector/model.joblib"
DATA_DIR = "datasets/cic-ids-2017"
TARGET_PATH = "04-evasion-and-hardening/evasion_targets.joblib"


def load_clean(path, nrows=None):
    df = pd.read_csv(path, nrows=nrows, low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].str.strip()
    return df


def main():
    bundle = joblib.load(MODEL_PATH)
    clf = bundle["model"]
    feature_names = bundle["features"]

    # use the Friday PortScan file: a concrete, single attack type to evade
    portscan_file = [f for f in glob.glob(f"{DATA_DIR}/*.csv") if "PortScan" in f][0]
    print(f"loading attack flows from {portscan_file.split('/')[-1]}")
    df = load_clean(portscan_file)

    # keep only real PortScan attack rows
    attack = df[df["Label"] != "BENIGN"].copy()
    print(f"total attack flows available: {len(attack)}")

    drop_cols = ["Label"]
    if "Fwd Header Length.1" in attack.columns:
        drop_cols.append("Fwd Header Length.1")
    X_attack = attack.drop(columns=drop_cols).select_dtypes(include=[np.number])
    X_attack = X_attack[feature_names]  # exact training column order
    X_attack = X_attack.replace([np.inf, -np.inf], np.nan).fillna(0)

    # keep only the ones the model CORRECTLY flags as ATTACK
    preds = clf.predict(X_attack)
    correct = X_attack[preds == 1]
    print(f"of those, model correctly flags as ATTACK: {len(correct)}")
    print(f"baseline detection rate on this attack: {(preds == 1).mean():.4f}")

    # save a sample of correctly-detected attacks as evasion targets
    sample = correct.sample(n=min(1000, len(correct)), random_state=42)
    joblib.dump(
        {"X": sample, "features": feature_names},
        TARGET_PATH,
    )
    print(f"saved {len(sample)} evasion targets to {TARGET_PATH}")


if __name__ == "__main__":
    main()
