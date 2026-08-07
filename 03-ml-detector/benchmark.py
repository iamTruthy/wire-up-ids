import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (
    confusion_matrix, classification_report,
    precision_score, recall_score, f1_score,
    ConfusionMatrixDisplay,
)

MODEL_PATH = "03-ml-detector/model.joblib"
TEST_PATH = "03-ml-detector/test_split.joblib"
CM_IMAGE = "03-ml-detector/confusion-matrix.png"


def main():
    bundle = joblib.load(MODEL_PATH)
    clf = bundle["model"]
    feature_names = bundle["features"]

    test = joblib.load(TEST_PATH)
    X_test, y_test = test["X_test"], test["y_test"]

    print(f"evaluating on {X_test.shape[0]} held-out flows")

    y_pred = clf.predict(X_test)

    print("\nclassification report:")
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "ATTACK"]))

    cm = confusion_matrix(y_test, y_pred)
    print("confusion matrix:")
    print(cm)
    print("layout:")
    print("  [[TN, FP],")
    print("   [FN, TP]]")

    precision = precision_score(y_test, y_pred, pos_label=1)
    recall = recall_score(y_test, y_pred, pos_label=1)
    f1 = f1_score(y_test, y_pred, pos_label=1)
    print(f"\nATTACK class: precision={precision:.4f} recall={recall:.4f} f1={f1:.4f}")

    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["BENIGN", "ATTACK"])
    disp.plot()
    plt.savefig(CM_IMAGE, dpi=150, bbox_inches="tight")
    print(f"\nconfusion matrix image saved to {CM_IMAGE}")

    top15 = sorted(zip(clf.feature_importances_, feature_names), reverse=True)[:15]
    print("\ntop 15 feature importances:")
    for importance, name in top15:
        print(f"  {importance:.4f}  {name}")


if __name__ == "__main__":
    main()
