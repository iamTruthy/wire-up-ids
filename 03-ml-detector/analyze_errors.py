import glob
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

MODEL_PATH = "03-ml-detector/model.joblib"
DATA_DIR = "datasets/cic-ids-2017"


def main():
    files = sorted(glob.glob(f"{DATA_DIR}/*.csv"))
    frames = [pd.read_csv(f, low_memory=False) for f in files]
    df = pd.concat(frames, ignore_index=True)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].str.strip()

    orig_labels = df["Label"]
    y = (df["Label"] != "BENIGN").astype(int)

    drop_cols = ["Label"]
    if "Fwd Header Length.1" in df.columns:
        drop_cols.append("Fwd Header Length.1")
    X = df.drop(columns=drop_cols).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    # identical split to train.py, carrying original labels to the test rows
    _, X_test, _, y_test, _, lab_test = train_test_split(
        X, y, orig_labels, test_size=0.2, stratify=y, random_state=42
    )

    bundle = joblib.load(MODEL_PATH)
    clf = bundle["model"]
    y_pred = clf.predict(X_test)

    print(f"held-out test flows: {len(y_test)}\n")
    print("per original label, HELD-OUT ONLY:")
    print(f"{'label':32s} {'test_n':>8s} {'recall':>8s} {'precision':>10s}")

    # recall: of real flows of this label, how many predicted attack (or benign for BENIGN)
    # precision here is class-conditional and only meaningful in aggregate,
    # so we report attack-precision overall plus per-label recall
    lab_test = lab_test.to_numpy()
    for label in sorted(pd.unique(lab_test)):
        mask = lab_test == label
        n = int(mask.sum())
        if label == "BENIGN":
            correct = int((y_pred[mask] == 0).sum())
        else:
            correct = int((y_pred[mask] == 1).sum())
        recall = correct / n if n else 0.0
        print(f"{label:32s} {n:8d} {recall:8.4f} {'-':>10s}")

    # overall attack-class precision on held-out (the false-alarm view)
    tp = int(((y_pred == 1) & (y_test == 1)).sum())
    fp = int(((y_pred == 1) & (y_test == 0)).sum())
    fn = int(((y_pred == 0) & (y_test == 1)).sum())
    tn = int(((y_pred == 0) & (y_test == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall_all = tp / (tp + fn) if (tp + fn) else 0.0
    print(f"\nheld-out ATTACK precision: {precision:.4f}")
    print(f"held-out ATTACK recall:    {recall_all:.4f}")
    print(f"held-out confusion: TN={tn} FP={fp} FN={fn} TP={tp}")


if __name__ == "__main__":
    main()
