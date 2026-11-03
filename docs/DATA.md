# Dataset Documentation

## Source
**CIC-IDS2018** (CSE-CIC-IDS2018)

## Files Used
- wednesday_dos.csv: 0 DDoS samples (deprecated)
- wednesday_dos2.csv: 686,012 total flows (548,810 DDoS, 288,666 Benign, 1,384 SSH-Patator LOIC-UDP)

## Known Issues
- CIC-IDS2018 has documented flow-construction errors (Engelen et al., 2021)
- Lab-generated attacks with fixed tools differ from production traffic
- All DDoS on port 80 (HTTP) - may not generalize to other ports

## Recommended
- Validate on second dataset (CIC-DDoS2019 or UNSW-NB15)
- Re-extract flows from PCAPs for cleaner labels

## Split Strategy
- HONEST: Time-based or session-based, not random 80/20
- CROSS-DATASET: Train on one dataset, test on another
- LEAVE-ONE-ATTACK-OUT: Train without attack X, measure recall on X
