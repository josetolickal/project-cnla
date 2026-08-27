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
