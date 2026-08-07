# Datasets

The data files themselves are gitignored. This README records how to fetch them.

## CIC-IDS2017 (MachineLearningCSV)

Source used: Kaggle mirror `chethuhn/network-intrusion-dataset`, which carries
the CIC-IDS2017 MachineLearningCSV files (CC0-1.0).

The original Canadian Institute for Cybersecurity direct hosts
(205.174.165.80 and cicresearch.ca) no longer serve the zip directly. They
return an HTML redirect page rather than the archive. The Kaggle mirror was
used as the fallback, which matches the fetch order in the project spec.

### Fetch

    pip install kaggle
    # place a Kaggle API token at ~/.kaggle/kaggle.json, chmod 600
    mkdir -p datasets/cic-ids-2017
    cd datasets/cic-ids-2017
    kaggle datasets download -d chethuhn/network-intrusion-dataset
    unzip network-intrusion-dataset.zip

### Contents

Eight CSV files, one per capture session over five days (3-7 July 2017):

    Monday-WorkingHours                        benign baseline
    Tuesday-WorkingHours                       brute force (FTP, SSH)
    Wednesday-workingHours                     DoS, Heartbleed
    Thursday-Morning-WebAttacks                web attacks
    Thursday-Afternoon-Infilteration           infiltration
    Friday-Morning                             botnet
    Friday-Afternoon-PortScan                  port scan
    Friday-Afternoon-DDos                      DDoS

About 2.8 million labelled flows total, 78 numerical flow features plus a
categorical Label column.

### Known quirks

CIC-IDS2017 has documented issues addressed in the benchmark writeup. Label
values carry leading whitespace, some feature columns contain infinities and
NaNs from division-by-zero in the flow extractor, and a corrected
re-derivation called LYCOS-IDS2017 exists. These are handled in the pipeline
and acknowledged in 03-ml-detector/benchmark.md.
