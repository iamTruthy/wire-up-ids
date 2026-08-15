# Stage 04 - Evasion and Hardening

## What this is

The capstone. I attacked my own Stage 03 detector to measure how fragile its
decisions are, then hardened it and measured again. Everything is in the
feature space the model reads, against my own attack samples. Nothing here
touches any system I do not own.

## The idea of feature-space evasion

The model draws a boundary in 77-dimensional feature space with attacks on
one side and benign traffic on the other. Evasion means moving an attack's
feature vector across that boundary while the underlying traffic stays a
real attack. The attacker's real-world levers map to features: padding
bytes changes packet-size statistics, adding delay changes timing
statistics, splitting a flow changes packet and byte counts. The study asks
what the smallest such change is that flips the verdict, and whether an
attacker could physically make it.

## What the evasion found

Single-feature changes barely move the Random Forest, because its trees
split on many features and the rest compensate when one is removed. The
model is robust to naive evasion. But realistic packet padding, pushing
packet-size features up toward benign-typical values, hid about 93 percent
of detected port scans with only five or six changed features. The honest
number came from being careful about direction: real padding only ever
increases sizes, and pushing toward the dense benign region works far
better than pushing to an impossible empty one. Full numbers are in
evasion-results.txt and harden.md.

## What the hardening found

Adversarial training, adding padded attack samples back into the training
data with their correct ATTACK label, closed the padding evasion
completely, from 0.4345 to 0.0000, with no loss of normal detection or
benign specificity. But this only proves the model now catches the attack
it was retrained on. An adaptive attacker using a different perturbation
family, timing instead of size, still found some headroom, 8.7 percent and
rising. Hardening raised the cost of evasion and even helped a little
against an untrained attack, but it did not make the model immune.
Robustness is an arms race, not a solved state.

## What I learnt

At this point, I expected the model to be fragile, and it was, but not how
I imagined. It handled changes to any single feature, even the one Stage 03
showed it relied on most. What really broke it was padding making packet
sizes look more normal, which hid almost every port scan with just a few
changes an attacker could actually make. I didn't know that moving feature
values toward the average for normal traffic worked much better than
setting them to zero, because it put the flow where real benign traffic is,
not in an unrealistic spot. Hardening worked well: padding evasion dropped
to zero, and normal detection stayed strong. This only blocked the attack I
had already tested. When I tried changing timing instead of size, the model
let some attacks through again.
