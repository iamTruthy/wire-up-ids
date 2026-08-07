import glob
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

DATA_DIR = "datasets/cic-ids-2017"


def load_file(path):
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].str.strip()
    y = (df["Label"] != "BENIGN").astype(int)
    drop_cols = ["Label"]
    if "Fwd Header Length.1" in df.columns:
        drop_cols.append("Fwd Header Length.1")
    X = df.drop(columns=drop_cols).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X, y, df["Label"]


def main():
    files = sorted(glob.glob(f"{DATA_DIR}/*.csv"))

    # Train on Mon-Thu, test on Friday (unseen day, PortScan/DDoS/Bot)
    train_files = [f for f in files if "Friday" not in f]
    test_files = [f for f in files if "Friday" in f]

    print("train files:")
    for f in train_files:
        print(f"  {f.split('/')[-1]}")
    print("test files (unseen day):")
    for f in test_files:
        print(f"  {f.split('/')[-1]}")

    Xtr = pd.concat([load_file(f)[0] for f in train_files], ignore_index=True)
    ytr = pd.concat([load_file(f)[1] for f in train_files], ignore_index=True)

    test_loaded = [load_file(f) for f in test_files]
    Xte = pd.concat([t[0] for t in test_loaded], ignore_index=True)
    yte = pd.concat([t[1] for t in test_loaded], ignore_index=True)
    labte = pd.concat([t[2] for t in test_loaded], ignore_index=True)

    print(f"\ntrain: {Xtr.shape[0]} flows, attack rate {ytr.mean():.3f}")
    print(f"test:  {Xte.shape[0]} flows, attack rate {yte.mean():.3f}")

    clf = RandomForestClassifier(
        n_estimators=100, n_jobs=-1, random_state=42, class_weight="balanced"
    )
    print("\ntraining on Mon-Thu...")
    clf.fit(Xtr, ytr)

    y_pred = clf.predict(Xte)

    tp = int(((y_pred == 1) & (yte == 1)).sum())
    fp = int(((y_pred == 1) & (yte == 0)).sum())
    fn = int(((y_pred == 0) & (yte == 1)).sum())
    tn = int(((y_pred == 0) & (yte == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"\n=== CROSS-DAY GENERALIZATION (test = Friday, never seen) ===")
    print(f"ATTACK precision: {precision:.4f}")
    print(f"ATTACK recall:    {recall:.4f}")
    print(f"ATTACK F1:        {f1:.4f}")
    print(f"confusion: TN={tn} FP={fp} FN={fn} TP={tp}")

    labte = labte.to_numpy()
    print(f"\nper-label recall on unseen Friday:")
    for label in sorted(pd.unique(labte)):
        mask = labte == label
        n = int(mask.sum())
        if label == "BENIGN":
            correct = int((y_pred[mask] == 0).sum())
        else:
            correct = int((y_pred[mask] == 1).sum())
        r = correct / n if n else 0.0
        print(f"  {label:28s} {n:8d} {r:8.4f}")


if __name__ == "__main__":
    main()
