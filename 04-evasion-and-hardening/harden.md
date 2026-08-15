# Stage 04 - Evasion and Hardening

## What this is

An adversarial study of the Stage 03 detector, run against my own model on my
own attack samples. The question is how fragile the learned decision boundary
is, measured by how small a change flips a detected attack to benign, and then
whether the fragility can be reduced by hardening. The whole study is in the
feature space the model reads, which is the honest place to attack this
particular classifier.

## Setup

The target is 1000 Friday port-scan flows the model detects at 0.9997. Port
scan is the attack the Stage 03 model handles best in-distribution, so evading
it is a strong test. If the model's best case is fragile, that is meaningful.

## Evasion

Three strategies of increasing honesty.

Single-feature zeroing did essentially nothing, flip rate at most 0.001 across
the top ten features. A Random Forest is an ensemble of trees splitting on
different features, so removing one feature lets the others compensate. The
model is robust to naive single-feature evasion, including on Destination Port,
the feature Stage 03 flagged as suspiciously dominant.

Zeroing the top ten features together flipped 59.8 percent. But zeroing is not
a realizable perturbation. A flow with zero packet sizes is physically
impossible, so a flip there is partly an off-manifold artifact rather than an
achievable evasion.

Realistic padding was the honest attack. It only increases values, simulating
an attacker padding packets, and pushes packet-size features toward
benign-typical medians. Padding five to six size features hid about 93 percent
of the port scans. Padding beats zeroing because it lands the flow in a region
dense with real benign examples rather than in an empty corner the forest still
finds odd. The jump is sharp: adding Packet Length Std as the fourth padded
feature takes evasion from near zero to 42.8 percent.

A realizability caveat belongs here. Some padded features, such as Packet
Length Std and Avg Bwd Segment Size, are statistically derived from the actual
packet sizes and cannot be set independently. The true achievable evasion is
bounded by which features move together when real packets are padded, so 93
percent is an upper estimate. The direction of the result, that padding easily
evades, is solid.

## Hardening

The defense is adversarial training. Padded copies of the training-set attacks
were generated with the same padding, kept their ATTACK label because they are
still attacks, and added to the training data. A new forest was trained on the
augmented set.

    padded-attack evasion BEFORE hardening: 0.4345
    padded-attack evasion AFTER  hardening: 0.0000
    hardened recall on normal attacks:      0.9978
    hardened specificity on benign:         0.9993

Adversarial training closed the padding evasion completely, with no measurable
loss of normal detection or benign specificity. The model learned that a
padded port scan is still a port scan. (The 0.4345 before-number is lower than
the 93 percent above because it is measured across all attack types in the test
set, not just port scans, and padding is most effective specifically against
port scans.)

## The adaptive attacker

Closing one evasion is not closing evasion. The hardened model was trained on
padding, so of course it catches padding. The honest question is whether an
attacker who adapts to a perturbation family the model was not trained on can
still evade.

Perturbing timing features, flow duration and inter-arrival statistics, which
were not part of the padding hardening, reached only 8.7 percent evasion at
seven features. Far below the 93 percent that padding achieved against the
original model. Two likely reasons: timing carries less port-scan signal than
size, and adversarial training may have broadened the model's reliance across
more features. The curve was still rising at seven features and had not
plateaued.

## Conclusion

Adversarial training raised the cost of evasion substantially and even
generalized partly to an untrained perturbation family. It did not make the
model immune. A determined adaptive attacker still finds headroom, and a
combined size-and-timing perturbation would likely do better. Robustness here
is an arms race in which the defender raises the bar, not a problem that gets
solved. This mirrors the Stage 03 finding from the other side: the model's
power comes from patterns in a specific feature space, and both distribution
shift and deliberate perturbation of that space degrade it.
