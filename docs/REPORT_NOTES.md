# Project Report Notes

This is a living record for the final beginner-friendly project report and PDF.
Only completed and tested work is recorded here.

## Milestones 1 and 2 — Environment and project skeleton

### Goal

Prepare a clean, repeatable Python workspace for the Automated Network
Intrusion Detection System before working with any network data.

### Verified environment

- Operating system: Arch Linux
- Python: 3.14.6
- Git: 2.55.0
- Python virtual-environment support: available

### Setup completed

1. Created a local Git repository on the `main` branch.
2. Added `.gitignore` so generated local files are not committed.
3. Created `.venv`, an isolated Python environment for this project.
4. Created the folders `data`, `models`, `src`, `logs`, and `tests`.
5. Installed and imported the baseline packages successfully:
   NumPy 2.5.2, pandas 3.0.5, scikit-learn 1.9.0, and joblib 1.5.3.
6. Created the initial Git commit:
   `c101499 chore: initialize IDS project structure`.

### Why this matters

The virtual environment prevents this project’s packages from interfering with
other Python projects. Git provides a history of changes. The folder structure
keeps datasets, program code, trained models, logs, and tests separate.

### Tests performed

- Confirmed the virtual environment runs Python 3.14.6.
- Imported every baseline package successfully.
- Ran `pip check`; it reported no broken requirements.
- Compiled the starter `src` package without a syntax error.

## Milestone 3 — Dataset

### Source used

The official CIC/UNB dataset form was unavailable during setup. The project
therefore uses the public Kaggle mirror `dhoogla/cicids2017`, which documents
that it provides a cleaned CICIDS2017 release and credits the original CIC/UNB
authors. Downloaded data remains ignored by Git.

### Files obtained and verified

The mirror provides eight Parquet files rather than CSV files. Parquet stores
tabular data compactly while preserving column types. A ZIP transfer issue was
detected and repaired before extraction; the repaired ZIP passed a full
integrity check.

The eight files contain 2,313,810 traffic-flow rows in total. Each row has 77
numeric network-flow features plus one `Label` column.

### Inspection results

- Missing values: 0
- Infinite numeric values: 0
- Labels: 15 total (one benign label and 14 attack labels)
- Benign rows: 1,977,318

The data is strongly imbalanced. For example, DDoS has 128,014 rows, whereas
Heartbleed has 11 and Web Attack - SQL Injection has 21. This must be explained
when interpreting future model metrics.

### Next step

Created `src/preprocess_dataset.py`. It processes one file at a time, checks
that every feature is numeric, removes rows containing missing or infinite
values, preserves the original label as `attack_type`, and adds an
`is_malicious` target (0 for Benign, 1 for every attack).

### Preprocessing tests

- A real benign source file was processed: all 458,831 rows were retained,
  with 0 missing and 0 infinite rows.
- A small controlled test with one Benign row, one DDoS row, one infinite row,
  and one missing-label row produced exactly two rows. The invalid rows were
  removed and the binary target was correctly set to 0 and 1.

### Full processing result

The full processing job completed successfully.

- Files processed: 8
- Rows before processing: 2,313,810
- Rows after processing: 2,313,810
- Rows removed for missing values: 0
- Rows removed for infinite values: 0
- Benign rows (`is_malicious = 0`): 1,977,318
- Malicious rows (`is_malicious = 1`): 336,492

The resulting files have 79 columns: 77 numeric features, `attack_type`, and
`is_malicious`. They are stored in `data/processed/cicids2017_binary/` and are
ignored by Git because they are generated data. Milestone 3 is complete. No
model result has been claimed or measured.

## Milestone 4 — Baseline Random Forest Model

### Goal

Train a Random Forest classifier on the processed CICIDS2017 data,
evaluate it on a held-out test set, and save the model and metrics.

### Data used

- All 8 processed Parquet files combined: 2,313,810 rows, 77 numeric features.
- `attack_type` and `is_malicious` excluded from features.
  `is_malicious` (0 = benign, 1 = malicious) is the target label.
- Class balance: 85.5 % benign (1,977,318 rows), 14.5 % malicious (336,492 rows).

### Train / test split

Stratified 80 / 20 split with `random_state=42`:

| Set      | Rows      | Malicious % |
|----------|-----------|-------------|
| Training | 1,851,048 | 14.54 %     |
| Test     | 462,762   | 14.54 %     |

Stratification ensures both halves have the same class ratio.

### Model configuration

| Parameter       | Value      | Reason                                         |
|-----------------|------------|------------------------------------------------|
| n_estimators    | 100        | Standard baseline; good balance of speed/accuracy |
| class_weight    | balanced   | Prevents the model ignoring the minority class |
| random_state    | 42         | Reproducible results                           |
| n_jobs          | -1         | Use all CPU cores for faster training          |

### Actual measured results (test set, 462,762 rows)

Training time: **105 seconds** on the local machine.

| Metric    | Value  |
|-----------|--------|
| Accuracy  | 99.88 % |
| Precision | 0.9951 |
| Recall    | 0.9965 |
| F1-score  | 0.9958 |

Full per-class breakdown:

|               | Precision | Recall | F1-score | Support |
|---------------|-----------|--------|----------|---------|
| Benign (0)    | 1.00      | 1.00   | 1.00     | 395,464 |
| Malicious (1) | 1.00      | 1.00   | 1.00     | 67,298  |

### Interpretation

All four metrics are above 99.5 %. This is high but expected for
the CICIDS2017 benchmark: it contains many repeated attack patterns that
Random Forest distinguishes easily from benign flows using basic flow
statistics (packet counts, durations, byte rates).

The results are trustworthy because:
- The model never saw the test set during training (strict 80/20 split).
- Stratification ensures the test set contains the same class distribution
  as the full dataset.
- `class_weight="balanced"` was used so the model was not rewarded for
  simply predicting "benign" on everything.

In a real deployment the model would face novel, unseen attack patterns.
This benchmark score reflects performance on known attack categories.
The Recall of 0.9965 means the model misses only 0.35 % of malicious flows
in this test set — important because missed attacks are more dangerous
than false alarms.

### Saved outputs

| File                                  | Purpose                              |
|---------------------------------------|--------------------------------------|
| `models/random_forest_baseline.joblib`| Trained model (12.4 MB, compressed)  |
| `models/baseline_metrics.json`        | All metrics in machine-readable form |
| `models/feature_names.json`           | Ordered list of the 77 feature names |

All three files are excluded from Git (generated artefacts).
Source code committed: `src/train_model.py`.
