# NovaShield — Technical Research Report

## Validation of Network-Flow Feature Engineering for Explainable Intrusion Detection

**Author:** Maria Batool

**Status:** Prepublication technical manuscript

**Year:** 2026

[Read the research report (PDF)](NovaShield_Flow_Validation_Research_Report.pdf)

### Research overview

This report investigates the consistency of NovaShield's network-flow
feature calculations against preserved CICFlowMeter reference outputs.

Using the current NovaShield implementation, five controlled synthetic
test fixtures were revalidated, producing 468 matching numerical
comparisons out of 468, under the defined comparison tolerances.

The study also documents earlier discrepancies, subsequent engineering
corrections, a the integrity verification of ten supporting PCAP and
reference CSV files.

### Research limitations

The results demonstrate agreement for the tested synthetic fixtures.
They do not establish real-world intrusion-detection accuracy,
production readiness, or independent external replication.

The complete reproducibility package is being prepared separately.

### Research identifiers

- **Research software:** [NovaShield on GitHub](https://github.com/mariabatool869-star/nova_shield)
- **Software DOI:** https://doi.org/10.5281/zenodo.24056070
- **Researcher ORCID:** https://orcid.org/0009-0001-1971-3508

*The DOI above identifies NovaShield software v0.1.0, not this manuscript.*
