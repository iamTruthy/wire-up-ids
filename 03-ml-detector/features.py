import glob
import numpy as np
import pandas as pd

DATA_DIR = "datasets/cic-ids-2017"


def load_dataset(data_dir=DATA_DIR, nrows_per_file=None):
    """Load all CIC-IDS2017 CSVs, clean known quirks, return (X, y, feature_names).

    y is binary: 0 = BENIGN, 1 = ATTACK.
    """
    files = sorted(glob.glob(f"{data_dir}/*.csv"))
    if not files:
        raise FileNotFoundError(f"no CSVs in {data_dir}")

    frames = []
    for f in files:
        frames.append(pd.read_csv(f, nrows=nrows_per_file, low_memory=False))
    df = pd.concat(frames, ignore_index=True)

    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].str.strip()
    y = (df["Label"] != "BENIGN").astype(int)

    drop_cols = ["Label"]
    if "Fwd Header Length.1" in df.columns:
        drop_cols.append("Fwd Header Length.1")
    X = df.drop(columns=drop_cols).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    return X, y, list(X.columns)


# ---- live reconciliation layer ----
# Features computable from the Stage 01 parser per 5-tuple flow.
# This is a documented SUBSET of CICFlowMeter's 78 features, not all of them.

class Flow:
    def __init__(self):
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.start = None
        self.last = None
        self.syn = 0
        self.ack = 0
        self.fin = 0
        self.rst = 0
        self.psh = 0

    def update(self, direction, length, flags, now):
        if self.start is None:
            self.start = now
        self.last = now
        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
        if "SYN" in flags:
            self.syn += 1
        if "ACK" in flags:
            self.ack += 1
        if "FIN" in flags:
            self.fin += 1
        if "RST" in flags:
            self.rst += 1
        if "PSH" in flags:
            self.psh += 1

    def features(self):
        duration = (self.last - self.start) if self.start else 0.0
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        return {
            "flow_duration": duration,
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "flow_bytes_per_s": total_bytes / duration if duration > 0 else 0.0,
            "flow_packets_per_s": total_packets / duration if duration > 0 else 0.0,
            "syn_count": self.syn,
            "ack_count": self.ack,
            "fin_count": self.fin,
            "rst_count": self.rst,
            "psh_count": self.psh,
        }


if __name__ == "__main__":
    X, y, names = load_dataset(nrows_per_file=50000)
    print(f"X shape: {X.shape}")
    print(f"y shape: {y.shape}")
    print(f"features: {len(names)}")
    print(f"attack rate: {y.mean():.3f}")
    print(f"first 5 feature names: {names[:5]}")
