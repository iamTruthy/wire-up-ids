import glob
import joblib
import numpy as np
import pandas as pd

DATA_DIR = "datasets/cic-ids-2017"
HARDENED = "04-evasion-and-hardening/model_hardened.joblib"
TARGET_PATH = "04-evasion-and-hardening/evasion_targets.joblib"

# timing/flow features NOT used in the padding hardening
TIMING_FEATURES = [
    "Flow Duration", "Flow IAT Mean", "Flow IAT Max", "Fwd IAT Mean",
    "Fwd IAT Max", "Flow IAT Std", "Fwd IAT Total",
]


def main():
    bundle = joblib.load(HARDENED)
    clf = bundle["model"]
    names = bundle["features"]

    targets = joblib.load(TARGET_PATH)
    X = targets["X"].reset_index(drop=True)

    print(f"hardened model detects these {len(X)} port scans at baseline: "
          f"{(clf.predict(X) == 1).mean():.4f}")

    # benign medians for timing features
    monday = [f for f in glob.glob(f"{DATA_DIR}/*.csv") if "Monday" in f][0]
    dfb = pd.read_csv(monday, low_memory=False)
    dfb.columns = dfb.columns.str.strip()
    dfb["Label"] = dfb["Label"].str.strip()
    drop = ["Label"]
    if "Fwd Header Length.1" in dfb.columns:
        drop.append("Fwd Header Length.1")
    Xb = dfb.drop(columns=drop).select_dtypes(include=[np.number])[names]
    Xb = Xb.replace([np.inf, -np.inf], np.nan).fillna(0)
    med = Xb.median()

    print("\nadaptive attack: perturb TIMING features (not trained against)")
    for k in range(1, len(TIMING_FEATURES) + 1):
        X_mod = X.copy()
        for f in TIMING_FEATURES[:k]:
            X_mod[f] = np.maximum(X_mod[f], med[f])
        flip = (clf.predict(X_mod) == 0).mean()
        print(f"  perturb top-{k} timing features -> evasion={flip:.4f}")


if __name__ == "__main__":
    main()
