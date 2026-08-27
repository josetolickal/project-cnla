# Project Report Notes

This is a living record for the final beginner-friendly project report and PDF.
Only completed and tested work is recorded here.

---

## Milestones 1 and 2 — Environment and Project Skeleton

### Goal

Prepare a clean, repeatable Python workspace for the Automated Network
Intrusion Detection System before working with any network data.

### What a virtual environment is

A virtual environment is an isolated copy of Python that belongs only to this
project. When you install a package inside the virtual environment, it does not
affect any other Python project on the same machine. This prevents version
conflicts — for example, if another project needs scikit-learn version 1.0 and
this project needs version 1.9, both can coexist without breaking each other.
The environment is activated with `source .venv/bin/activate` and deactivated
with `deactivate`.

### What Git and `.gitignore` do

Git is a version-control tool. Every time a meaningful change is made,
it is recorded as a "commit" with a short message describing what changed.
This creates a full history so that any earlier working version can be
recovered at any time.

`.gitignore` is a text file that tells Git which files to ignore completely.
Large data files, trained model files, and temporary cache folders are listed
there so they are never accidentally uploaded to GitHub. Only source code,
configuration, and documentation are tracked.

### What each project folder is for

| Folder   | Purpose |
|----------|---------|
| `data/`  | Raw and processed dataset files (ignored by Git — too large) |
| `models/`| Saved trained model files (ignored by Git — generated output) |
| `src/`   | All Python source code for the project |
| `logs/`  | Log files written at runtime (ignored by Git) |
| `tests/` | Test scripts that verify individual components work correctly |
| `docs/`  | Documentation and this report |

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

### Tests performed

- Confirmed the virtual environment runs Python 3.14.6.
- Imported every baseline package successfully.
- Ran `pip check`; it reported no broken requirements.
- Compiled the starter `src` package without a syntax error.

---

## Milestone 3 — Dataset

### Goal

Obtain the CICIDS2017 network traffic dataset, understand its structure,
clean it, and save it in a format ready for machine learning.

### What CICIDS2017 is

CICIDS2017 (Canadian Institute for Cybersecurity Intrusion Detection
Evaluation Dataset 2017) is a publicly available benchmark dataset for
intrusion detection research. It was created by the University of New
Brunswick. It contains one week of realistic network traffic recorded in
a lab environment, including both normal (benign) traffic and several
types of attack traffic such as DDoS, brute-force, port scans, and
web attacks. Researchers use it to train and compare intrusion detection
models because the ground truth labels (which flows are attacks) are
already known.

### What the 77 features represent

Each row in the dataset represents one *network flow* — a conversation
between two computers identified by the same source IP, destination IP,
source port, destination port, and protocol. CICFlowMeter software was
used to extract statistical summaries of each flow. The 77 numeric
features capture things such as:

- **Packet counts** — how many packets were sent forward and backward.
- **Byte counts** — total data transferred in each direction.
- **Packet lengths** — minimum, maximum, mean, and standard deviation of
  packet sizes.
- **Inter-arrival times (IAT)** — how long the gaps between packets were.
- **Flag counts** — how many TCP control flags (SYN, FIN, RST, ACK, PSH)
  appeared in the flow.
- **Flow duration** — how long the entire flow lasted.
- **Bytes per second / packets per second** — the rate of data transfer.

Attack traffic often looks statistically different from benign traffic —
for example, a DDoS flood sends an abnormally high number of packets per
second, and a port scan creates many short flows with SYN flags and no
completing handshake.

### What Parquet is and why it is used

Parquet is a compressed, column-oriented file format for storing tabular
data (like a table or spreadsheet). Compared with CSV files:

- **Smaller on disk** — compression reduces file size significantly.
- **Faster to load** — only the columns you request are read, not the
  whole file.
- **Preserves data types** — integer and float columns keep their exact
  types, whereas CSV stores everything as text that must be re-parsed.

The processed dataset is stored in Parquet format for these reasons.

### Source used

The official CIC/UNB dataset form was unavailable during setup. The project
therefore uses the public Kaggle mirror `dhoogla/cicids2017`, which documents
that it provides a cleaned CICIDS2017 release and credits the original CIC/UNB
authors. Downloaded data remains ignored by Git.

### Files obtained and verified

The mirror provides eight Parquet files rather than CSV files.
A ZIP transfer issue was detected and repaired before extraction;
the repaired ZIP passed a full integrity check.

The eight files contain 2,313,810 traffic-flow rows in total. Each row has 77
numeric network-flow features plus one `Label` column.

### Inspection results

- Missing values: 0
- Infinite numeric values: 0
- Labels: 15 total (one benign label and 14 attack labels)
- Benign rows: 1,977,318

The data is strongly imbalanced. For example, DDoS has 128,014 rows, whereas
Heartbleed has 11 and Web Attack — SQL Injection has 21. This must be explained
when interpreting model metrics: a model that simply predicted "benign" for
every row would still be correct 85.5 % of the time, which is why accuracy
alone is not sufficient — Precision, Recall, and F1-score are also required.

### What the preprocessing script does and why

Created `src/preprocess_dataset.py`. It performs the following steps:

1. **Reads each raw Parquet file** one at a time to avoid loading all data
   into memory at once.
2. **Checks that every feature column is numeric.** Non-numeric columns
   cannot be used directly by scikit-learn models, so their presence would
   cause an error.
3. **Removes rows with missing values.** A missing value (NaN) in a feature
   means the measurement was not recorded. Leaving NaN values in would
   either crash the model or force it to guess.
4. **Removes rows with infinite values.** Some flow-rate calculations
   (bytes per second) produce infinity when the flow duration is zero.
   Infinite values cannot be represented as floating-point model inputs.
5. **Preserves the original attack label as `attack_type`.** This column
   records the specific attack name (e.g., "DDoS", "PortScan"). It is kept
   for analysis but is **never used as a model feature** because it
   directly reveals the answer — using it would make the model cheat.
6. **Creates the binary target column `is_malicious`:**
   - `0` means the flow is benign (normal traffic).
   - `1` means the flow is an attack of any type.
   This converts the 15-class problem into a simpler binary (two-class)
   detection task: benign versus malicious.
7. **Saves the result as a new Parquet file** in
   `data/processed/cicids2017_binary/`.

### Preprocessing tests

- A real benign source file was processed: all 458,831 rows were retained,
  with 0 missing and 0 infinite rows removed.
- A small controlled test with one Benign row, one DDoS row, one infinite
  row, and one missing-label row produced exactly two rows. The invalid rows
  were removed and the binary target was correctly set to 0 and 1.

### Full processing result

The full processing job completed successfully.

| Item                              | Count     |
|-----------------------------------|-----------|
| Files processed                   | 8         |
| Rows before processing            | 2,313,810 |
| Rows after processing             | 2,313,810 |
| Rows removed for missing values   | 0         |
| Rows removed for infinite values  | 0         |
| Benign rows (`is_malicious = 0`)  | 1,977,318 |
| Malicious rows (`is_malicious = 1`)| 336,492  |

The resulting files have 79 columns: 77 numeric features, `attack_type`, and
`is_malicious`. They are stored in `data/processed/cicids2017_binary/` and are
ignored by Git because they are generated data. Milestone 3 is complete.

---

## Milestone 4 — Baseline Random Forest Model

### Goal

Train a Random Forest classifier on the processed CICIDS2017 data,
evaluate it on a held-out test set, and save the model and metrics.

### What a Random Forest is (plain English)

A **Decision Tree** is a model that makes predictions by asking a series
of yes/no questions about the input features — for example: "Is the
packet rate above 1000 per second?" → Yes → "Is the flow duration under
0.1 seconds?" → Yes → "Predict: Malicious." A single decision tree can
become very specific to its training data and fail on new data.

A **Random Forest** fixes this by building many decision trees (100 in
this project) instead of just one. Each tree is trained on a random
subset of the training rows and uses a random subset of features for each
split. When a new flow needs to be classified, all 100 trees vote, and
the majority vote wins. This makes the overall prediction much more
reliable and resistant to noise than any single tree.

Random Forest is a good first choice for this project because:
- It handles a mix of feature scales without needing normalisation.
- It gives feature importances, which will be useful for explainability.
- It is fast enough to train on millions of rows on a standard laptop.

### What a stratified train/test split is

Before training, the full dataset is divided into two non-overlapping parts:

- **Training set (80 %)** — used to teach the model.
- **Test set (20 %)** — held back completely and only used to measure
  performance after training is finished.

The key word is *stratified*: the split is done in a way that keeps the
same class ratio in both halves. Because the data is 85.5 % benign and
14.5 % malicious, both the training set and the test set are also
approximately 85.5 % benign and 14.5 % malicious. Without stratification,
one set could end up with very few malicious examples by chance, making
the evaluation unreliable.

The model never sees the test set during training, so the test results
represent genuine performance on unseen data.

### What `class_weight="balanced"` means

Without this setting, the model is trained to minimise its total number of
mistakes. Since 85.5 % of the data is benign, it could achieve 85.5 %
accuracy by simply predicting "benign" every single time — without ever
learning what an attack looks like.

`class_weight="balanced"` tells the Random Forest to treat each class as
equally important regardless of how many rows it has. It does this by
giving each malicious training example roughly 5.9× more weight than each
benign example (because there are 5.9× fewer malicious rows). This forces
the model to actually learn to distinguish attacks.

### What Precision, Recall, and F1-score mean

These three metrics measure performance on the malicious class specifically
(positive class = malicious flow):

**Precision** — "Of all the flows the model *labelled as malicious*,
what fraction were actually malicious?"
A low Precision means many false alarms (innocent traffic flagged as
attacks). In an IDS, false alarms waste analyst time.

**Recall** — "Of all the flows that *actually were malicious*, what
fraction did the model *catch*?"
A low Recall means attacks are being missed. In an IDS, a missed attack
is more dangerous than a false alarm.

**F1-score** — The harmonic mean of Precision and Recall. It gives a
single number that balances both concerns. A perfect F1 is 1.0.

For example: Recall = 0.9965 means the model caught 99.65 % of all
malicious flows in the test set, missing only 0.35 %.

**Accuracy** — "What fraction of *all* predictions (benign and malicious)
were correct?" Useful as a summary but can be misleading on imbalanced
data (see the class weight explanation above).

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

| Parameter    | Value    | Reason                                            |
|--------------|----------|---------------------------------------------------|
| n_estimators | 100      | Standard baseline; good balance of speed/accuracy |
| class_weight | balanced | Prevents the model ignoring the minority class    |
| random_state | 42       | Fixed seed makes results reproducible             |
| n_jobs       | -1       | Use all CPU cores for faster parallel training    |

### Actual measured results (test set, 462,762 rows)

Training time: **105 seconds** on the local machine.

| Metric    | Value   |
|-----------|---------|
| Accuracy  | 99.88 % |
| Precision | 0.9951  |
| Recall    | 0.9965  |
| F1-score  | 0.9958  |

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

| File                                   | Purpose                              |
|----------------------------------------|--------------------------------------|
| `models/random_forest_baseline.joblib` | Trained model (12.4 MB, compressed)  |
| `models/baseline_metrics.json`         | All metrics in machine-readable form |
| `models/feature_names.json`            | Ordered list of the 77 feature names |

All three files are excluded from Git (generated artefacts).
Source code committed: `src/train_model.py`.
