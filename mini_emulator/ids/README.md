# Intrusion-Detection Pipeline (NFStream + scikit-learn)

A modular pipeline that extracts per-flow features from emulator pcaps with
**NFStream**, labels flows against the known topology, and **compares two
families of machine-learning detectors**:

* **Outlier / anomaly detection** — `IsolationForest`, `LocalOutlierFactor`,
  `OneClassSVM`, `EllipticEnvelope`, each trained on **normal flows only**.
* **Supervised classification** — `RandomForest`, `HistGradientBoosting`,
  `LogisticRegression`, `KNeighbors`, `DecisionTree`, each evaluated with
  **stratified k-fold cross-validation**.

It then produces a uniform metric comparison and a gallery of visualisations.

## Ground truth (task rule #3)

A flow is **malicious** if either endpoint (source *or* destination) is:

* the rogue `new_eth_node` — IP `10.162.0.74`, MAC `02:42:0a:a2:00:4a`, **or**
* any unicast IP not in the emulated topology whitelist.

Broadcast / multicast / link-local / DHCP `0.0.0.0` / loopback are treated as
benign control-plane noise, not intrusions. The whitelist and the rogue node
live in [`config.py`](config.py) — adjust them there if the topology changes.

## Layout-invariant features (task rule #2)

The models never see an IP, MAC, port, container id or absolute timestamp.
Those columns (`IDENTITY_COLUMNS` in `config.py`) are used **only** to build the
label, then dropped. What the models see are flow statistics that stay valid in
a later time window or a re-addressed network: packet/byte counts, packet-size
distributions, **relative** durations and inter-arrival times, TCP-flag tallies,
the L4 protocol number, and engineered ratios/rates (`bytes_per_packet`,
`src2dst_bytes_ratio`, `syn_ratio`, …). A guard in `preprocessing.build_matrix`
raises if any identity column ever leaks into the feature matrix.

## Modules

| File | Stage |
|------|-------|
| `config.py`             | topology whitelist, rogue node, feature lists |
| `feature_extraction.py` | NFStream → raw flow table (cached to CSV) |
| `labeling.py`           | ground-truth labels by IP/MAC, both directions |
| `preprocessing.py`      | feature engineering, selection, cleaning |
| `outlier_models.py`     | anomaly detectors (fit on normal only) |
| `classification.py`     | classifiers + stratified cross-validation |
| `evaluation.py`         | uniform metric table for both families |
| `visualization.py`      | the figure gallery |
| `pipeline.py`           | CLI orchestrator |

## Usage

```bash
# inside the SEED Ubuntu VM
sudo apt-get install -y libpcap-dev
python3 -m pip install -r ids/requirements.txt

# from the mini_emulator/ directory
python3 -m ids.pipeline \
    --pcap captures_full/capture_20260527_085807/merged.pcap \
    --outdir ids_out
```

The first run caches the NFStream output to `ids_out/flows_raw.csv`; later runs
reuse it (so you can iterate on models/plots without re-parsing the pcap). To
force re-extraction add `--force-extract`; to run the ML/plots from an existing
cache on any machine, pass `--features-csv path/to/flows_raw.csv`.

### Key options

| flag | default | meaning |
|------|---------|---------|
| `--test-size`     | 0.3  | held-out fraction for outlier-detector evaluation |
| `--cv-splits`     | 5    | StratifiedKFold splits for classification |
| `--contamination` | 0.05 | expected outlier fraction for the detectors |
| `--no-plots`      | off  | skip the figure gallery |

## Outputs (`--outdir`)

```
flows_raw.csv        # NFStream cache (features + identity columns)
flows_labeled.csv    # + ground-truth label and reason
features.csv         # final model matrix + label
cv_scores.csv        # per-classifier CV mean/std
model_comparison.csv # unified metric table (both families)
figures/             # 01..10 PNG gallery (see visualization.py)
```

## Notes

* Outlier detectors are trained on **normal-only** training flows; the malicious
  flows appear solely at evaluation time.
* Classifiers are cross-validated with the scaler inside the CV pipeline, so no
  leakage from validation folds; the confusion matrix / ROC use out-of-fold
  (`cross_val_predict`) predictions.
* For imbalanced intrusion data, prefer **recall**, **F1** and **PR-AUC** over
  raw accuracy.
