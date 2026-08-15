# Stage 03 - Benchmark

## Setup

Random Forest, 100 trees, class_weight balanced. Two evaluations are
reported. The first is a standard same-distribution split. The second is a
cross-day generalization test, which is the more honest measure and the more
important result.

## Evaluation 1 - same-distribution split (the flattering number)

Trained on an 80/20 stratified split of the full CIC-IDS2017 set:
2,830,743 flows, 77 features, 19.7% attack rate. Held-out test: 566,149 flows.

              precision    recall  f1-score
      ATTACK     0.9967    0.9985    0.9976

    confusion  [[454256    364]     TN FP
                [   171 111358]]     FN TP

Per-label recall on the held-out split, with test counts:

  BENIGN                    454620   0.9992
  DDoS                       25741   0.9996
  DoS Hulk                   46076   0.9993
  DoS GoldenEye               2081   0.9995
  DoS Slowhttptest            1080   1.0000
  DoS slowloris               1146   0.9983
  PortScan                   31781   0.9987
  FTP-Patator                 1598   0.9994
  SSH-Patator                 1190   0.9992
  Web Attack Brute Force       308   0.9903
  Web Attack XSS               121   1.0000
  Bot                          392   0.8010
  Web Attack SQL Injection       4   0.7500   (4 flows, not assessable)
  Heartbleed                     2   1.0000   (2 flows, not assessable)
  Infiltration                   9   1.0000   (9 flows, not assessable)

Even here the cracks show. Bot recall is only 0.801, and the rare classes
have too few test flows to assess. But the headline F1 of 0.9976 looks like a
solved problem. It is not.

## Evaluation 2 - cross-day generalization (the honest number)

Trained on Monday through Thursday (brute force, DoS, web attacks,
infiltration). Tested on Friday, a day the model never saw, containing
port scan, DDoS, and botnet traffic.

  train: 2,127,498 flows, attack rate 0.126
  test:    703,245 flows (Friday), attack rate 0.411

              precision    recall  f1-score
      ATTACK     0.9960    0.0843    0.1555

    confusion  [[414224     98]     TN FP
                [264562  24361]]     FN TP

Per-label recall on unseen Friday:

  BENIGN     414322   0.9998
  DDoS       128027   0.1890
  PortScan   158930   0.0010
  Bot          1966   0.0000

Recall collapsed from 0.9985 to 0.0843. The model caught fewer than one
attack in ten. It missed essentially every port scan (159 of 158,930) and
every botnet flow, and caught under a fifth of the DDoS traffic. Precision
stayed high, so when it did raise an alert it was almost always right, but it
barely raised any.

## What this means

The near-perfect same-distribution score was substantially an artifact of
train and test being drawn from the same captures. The model learned
fingerprints specific to this dataset, not generalizable attack behavior.
The earlier warning sign, Destination Port being the single most important
feature, is borne out. The model leaned on capture-specific quirks such as
which ports these particular attacks targeted, and those did not transfer to
a different day.

This is the central lesson of the stage. A flow-feature classifier can score
0.997 F1 and still fail to generalize to the same attack types on a different
day. Same-distribution benchmarks on CIC-IDS2017 systematically overstate
real-world detection ability. CIC-IDS2017 is also a known-flawed dataset with
label and feature-extraction errors, which is why the corrected
LYCOS-IDS2017 re-derivation exists, and some of the same-distribution
separability comes from those artifacts.

## Limitations summary

This is a study benchmark. Its useful, honest finding is not the 0.997
headline but the gap between it and the 0.155 cross-day result. The model is
strong at recognizing attack patterns it has seen from the same environment
and weak at generalizing to new conditions. A production detector would need
cross-environment evaluation as standard, more diverse training data, and
features chosen to resist the port-memorization failure shown here. The
transparent Stage 02 rules and this opaque model are complementary: the rules
generalize by construction but are brittle to evasion, the model is powerful
in-distribution but fragile out of it.
