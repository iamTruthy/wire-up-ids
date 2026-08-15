# Stage 03 - The ML Detector

## What this is

A machine-learning intrusion detector trained on flow features from the
CIC-IDS2017 dataset, benchmarked honestly. This is the high rung of the
detection ramp. Where the Stage 02 rules are hand-written and transparent,
this stage learns the boundary between benign and attack traffic from labelled
data, and the real work is measuring where that learned boundary fails.

## What a flow is

A flow is one conversation between two endpoints, identified by the 5-tuple of
source IP, source port, destination IP, destination port, and protocol.
Instead of judging single packets, the detector aggregates all packets in a
flow and uses statistics about it: duration, packet and byte counts each way,
inter-arrival timing, packet-size distribution, and TCP flag counts. These
behavioural features generalise better than raw bytes, because an attack has a
characteristic shape (a port scan is many short SYN-heavy flows, a DDoS is huge
packet counts with tiny gaps) that survives changes to specific byte content.

The dataset's 78 features come from CICFlowMeter. The Stage 01 parser produces
per-packet data, not flows, so features.py includes a live-flow aggregation
layer that computes a documented subset of these features from the parser
output. That subset is honest about what can and cannot be reproduced without
CICFlowMeter's exact methodology.

## The data and its quirks

CIC-IDS2017, eight CSVs over five days, about 2.8 million labelled flows with a
19.7% attack rate. The schema was inspected before any feature code was
written. Every column name carries leading whitespace, some feature columns
contain infinities and NaNs from division-by-zero in the flow extractor, one
column is duplicated, and the label values carry whitespace too. The loader
strips names and labels, collapses all attack classes to a single ATTACK
class for a binary target, drops the duplicate column, and replaces
infinities and NaNs before training. Building against the real schema rather
than an assumed one is why the pipeline did not break.

## The model

Random Forest, 100 trees, class_weight balanced. It is the defensible baseline
for tabular flow features: it handles mixed-scale features without
normalisation, tolerates the skew and outliers throughout this data, and gives
feature importances for free. Gradient boosting would gain a little at the cost
of a dependency and tuning burden not worth it for a baseline. Train and test
were split before any fitting, stratified, with a fixed seed, and the held-out
split was saved so the benchmark evaluates the exact same rows with no leakage.

## The two benchmarks, and why the second one matters

A standard same-distribution split scored 0.9976 F1, with ATTACK recall
0.9985. Taken alone this looks like a solved problem. It is not, and the honest
core of this stage is the second evaluation.

Retrained on Monday through Thursday and tested on Friday, a day the model
never saw, recall collapsed from 0.9985 to 0.0843. The model missed almost
every port scan and every botnet flow, attack types it had trained on, only
from a different day. It had learned this dataset's specific fingerprints,
including which ports these particular attacks used, not generalisable attack
behaviour. The full numbers and per-class breakdowns are in benchmark.md.

The lesson is that a same-distribution benchmark on this dataset systematically
overstates real-world ability, and the only way to see that was to force a
harder test. The transparent rules of Stage 02 and this model are
complementary rather than a simple ladder: the rules generalise by
construction but are brittle to evasion, the model is powerful in-distribution
but fragile out of it.

## What I learnt

1. Aggregate metrics hide failures --- One F1 number said "solved." The per-class breakdown showed the model misses 1 in 5 botnet flows and can't be assessed on rare classes at all. Always break metrics down by class.

2. Real data is mostly cleaning --- The dataset arrived with whitespace in every column name, infinities and NaNs from division-by-zero, duplicate columns, and known label errors. Most of the work was distrusting and cleaning the data, not writing algorithms.

3. Leakage discipline matters --- Split before fitting, never fit on test data, save the exact held-out set so the benchmark can't accidentally cheat.

4. ML and rules are complementary --- The Stage 02 rules are transparent and generalize by construction but are brittle to evasion. The model is powerful in-distribution but fragile out of it. Neither is strictly "better."

