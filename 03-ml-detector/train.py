import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

import features

MODEL_PATH = "03-ml-detector/model.joblib"


def main():
    print("loading dataset (full)...")
    X, y, names = features.load_dataset()   # no nrows -> full data
    print(f"loaded {X.shape[0]} flows, {X.shape[1]} features")
    print(f"attack rate: {y.mean():.3f}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    clf = RandomForestClassifier(
        n_estimators=100, n_jobs=-1, random_state=42,
        class_weight="balanced", verbose=2
    )

    print("fitting on train split...")
    clf.fit(X_train, y_train)

    joblib.dump({"model": clf, "features": names}, MODEL_PATH)
    joblib.dump(
        {"X_test": X_test, "y_test": y_test},
        "03-ml-detector/test_split.joblib",
    )

    print("done")


if __name__ == "__main__":
    main()
