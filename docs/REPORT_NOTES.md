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

---

## Milestone 5 — Prediction Pipeline

### Goal

Build a reusable module that loads the saved model and predicts whether a
single network flow is benign or malicious, returning a label and a
confidence probability. This module is the shared entry point for all
future components — SHAP explainability, risk scoring, and the dashboard
will all call it instead of duplicating the prediction logic.

### What the prediction pipeline is and why it is needed

After training, the model is saved to disk as a `.joblib` file. To use it
again the project needs code that:

1. Loads the model from disk (only done once, then reused).
2. Accepts one row of feature values as input.
3. Arranges the features in exactly the same order the model was trained on.
4. Asks the model for a prediction and a probability.
5. Returns a clean, readable result.

Without this module, every part of the project (dashboard, risk engine,
SHAP) would have to repeat all of these steps. Putting it in one place
means a bug only needs to be fixed once.

### What `load_pipeline()` does

Loads two files from the `models/` folder:
- `random_forest_baseline.joblib` — the trained Random Forest object.
- `feature_names.json` — the ordered list of 77 feature names.

Both are returned together in a dict called the *pipeline*. The feature
names are loaded alongside the model because the model internally maps
column index 0 to the first feature it was trained on, index 1 to the
second, and so on. If a caller passes features in a different order, the
prediction will be silently wrong. Keeping the feature list guarantees
the order is always correct.

### What `predict_flow()` does

Accepts one traffic flow as a Python dict or pandas Series (both formats
are supported). Steps performed:

1. Checks that all 77 required feature names are present. Raises a clear
   error message if any are missing.
2. Builds a single-row numpy array with features in the correct order.
3. Calls `model.predict()` → returns 0 (benign) or 1 (malicious).
4. Calls `model.predict_proba()` → returns a probability for each class;
   takes the probability of the malicious class (index 1).
5. Returns a dict: `label`, `is_malicious`, and `probability`.

Extra columns like `attack_type` and `is_malicious` in the input are
silently ignored, so raw dataset rows can be passed directly without
any pre-filtering.

### What the probability value means

`probability` is how confident the model is that the flow is malicious,
on a scale from 0.0 to 1.0. It comes from `predict_proba()`, which
counts what fraction of the 100 trees voted "malicious".

- `1.0` — all 100 trees voted malicious (maximum confidence).
- `0.0` — all 100 trees voted benign.
- `0.6` — 60 trees voted malicious, 40 voted benign (borderline).

This probability is important for the risk engine (Milestone 7), which
will use it to decide whether a detection is LOW, MEDIUM, HIGH, or
CRITICAL risk.

### Files created

| File | Purpose |
|---|---|
| `src/predict.py` | `load_pipeline()` and `predict_flow()` functions; also contains `predict_batch()` for batch use by the dashboard |
| `src/run_prediction_demo.py` | Demo script that runs 4 real rows through the pipeline and prints results |

### Actual demo results (4 real rows from the dataset)

| Test | Ground truth | Predicted | Probability | Result |
|------|-------------|-----------|-------------|--------|
| Benign flow (Monday traffic) | Benign | benign | 0.0000 | PASS ✓ |
| DDoS attack flow | DDoS | malicious | 1.0000 | PASS ✓ |
| DoS slowloris flow | DoS slowloris | malicious | 1.0000 | PASS ✓ |
| Benign flow (from DDoS file) | Benign | benign | 0.0000 | PASS ✓ |

All 4 tests passed. The pipeline correctly:
- Loads and reuses the saved model.
- Ignores non-feature columns (`attack_type`, `is_malicious`) automatically.
- Returns the correct label and probability for every test case.
- Handles rows from different Parquet files without any special setup.

### Extension — Attack Type Identification (Two-Stage Pipeline)

The binary model answers "is this malicious?" A second model was added to
answer "what kind of attack is it?" — making the system more useful for a
real analyst who needs to know whether they are facing a DDoS, a brute-force
login attempt, or a port scan.

#### Why a two-stage design?

A single model could try to predict all 15 classes at once (Benign + 14
attack types). However, a two-stage pipeline has clearer responsibilities:

- **Stage 1 (binary model)** — optimised purely for catching attacks vs.
  missing them. High Recall on the malicious class is the priority.
- **Stage 2 (multi-class model)** — only runs after Stage 1 confirms the
  flow is malicious. It is trained only on malicious rows, so it focuses on
  distinguishing *between* attack types and cannot return Benign as an attack
  name.

If Stage 2 makes a wrong classification (e.g., calls a PortScan a DDoS),
the important thing — that it was flagged as malicious — is still correct.

#### What a LabelEncoder is

Machine learning models work with numbers, not text strings. A
`LabelEncoder` converts each attack name to a unique integer:
`"Bot" → 0`, `"DDoS" → 1`, `"DoS GoldenEye" → 2`, and so on. The encoder is
saved alongside the model so the numbers can be converted back to
human-readable names when displaying results.

#### Multi-class model results (attack-only test set, 67,299 rows)

Training time: **4.2 seconds**. Overall accuracy: **99.71 %**.

Per-class results (selected):

| Attack type | Precision | Recall | F1-score | Test rows |
|---|---|---|---|---|
| DDoS | 1.00 | 1.00 | 1.00 | 25,603 |
| DoS Hulk | 1.00 | 1.00 | 1.00 | 34,570 |
| DoS GoldenEye | 0.99 | 1.00 | 1.00 | 2,057 |
| DoS slowloris | 1.00 | 1.00 | 1.00 | 1,077 |
| DoS Slowhttptest | 1.00 | 1.00 | 1.00 | 1,046 |
| FTP-Patator | 1.00 | 1.00 | 1.00 | 1,186 |
| SSH-Patator | 0.99 | 1.00 | 1.00 | 644 |
| PortScan | 0.96 | 0.99 | 0.97 | 391 |
| Bot | 1.00 | 1.00 | 1.00 | 288 |
| Web Attack - Brute Force | 0.74 | 0.78 | 0.76 | 294 |
| Web Attack - XSS | 0.42 | 0.35 | 0.38 | 130 |
| Infiltration | 1.00 | 1.00 | 1.00 | 7 |
| Web Attack - Sql Injection | 1.00 | 0.50 | 0.67 | 4 |
| Heartbleed | 1.00 | 1.00 | 1.00 | 2 |

#### Interpretation of per-class results

Common, high-volume attacks (DDoS, DoS Hulk, FTP-Patator) are identified
almost perfectly because the model has thousands of representative training
examples. Less common attack types are identified less reliably:

- **Web Attack - XSS (F1 = 0.38)** — only 652 rows total; the model does
  not have enough examples to learn consistent patterns.
- **Web Attack - Sql Injection (F1 = 0.67)** — only 21 rows total. The
  model catches very few because it has barely seen any examples.
- **Heartbleed (F1 = 1.00 in this split)** — only 11 rows total; performance is
  statistically unreliable with so little data.

These limitations are honest and expected. They would be disclosed in a
real system: "Attack type identification is highly accurate for common
attacks. Rare attack types may be misclassified at the type level, but
Stage 1 still catches them as malicious."

#### Two-stage pipeline live demo (9 real rows)

| Ground truth | Stage 1 | Stage 2 (attack type) | Confidence |
|---|---|---|---|
| Benign | benign | — | — |
| DDoS | malicious | DDoS | 1.00 |
| DoS Hulk | malicious | DoS Hulk | 1.00 |
| DoS slowloris | malicious | DoS slowloris | 1.00 |
| FTP-Patator | malicious | *Web Attack - XSS (type mismatch)* | 0.83 |
| SSH-Patator | malicious | SSH-Patator | 1.00 |
| PortScan | malicious | PortScan | 1.00 |
| Bot | malicious | Bot | 1.00 |
| Web Attack - XSS | malicious | Web Attack - XSS | 1.00 |

The demo now confirms the intended architecture: Stage 2 no longer returns
Benign because it was trained only on malicious rows. One selected
FTP-Patator row is still classified as Web Attack - XSS. This is a model
type-level error, not a pipeline failure: the binary alarm still fires and
the second model returns an attack-only label.

#### Additional files saved

| File | Purpose |
|---|---|
| `models/attack_type_classifier.joblib` | Trained multi-class model (gitignored) |
| `models/attack_type_label_encoder.joblib` | LabelEncoder for attack names (gitignored) |
| `models/attack_type_metrics.json` | Per-class metrics in machine-readable form |
| `src/train_attack_classifier.py` | Training script |
| `src/predict.py` (updated) | Now includes `identify_attack_type()` and updated `load_pipeline()` |
| `src/run_two_stage_demo.py` | Demo for Stage 1 plus attack-only Stage 2 |

---

## Milestone 6 — Explainability (SHAP)

### Goal

Provide human-understandable explanations for individual model predictions.
Security analysts and presentation examiners must be able to ask:
*"Why did the system flag this network flow as an attack?"*
and receive a clear, verifiable list of contributing features rather than
treating the classifier as an unexplained black box.

### What SHAP is (plain English)

SHAP (SHapley Additive exPlanations) is based on cooperative game theory.
Imagine a football team wins a match; Shapley values calculate how much credit
each individual player deserves for that victory.

In intrusion detection, each network feature (like packet rate, byte count,
or flag count) is a "player", and the prediction ("malicious" vs "benign")
is the match outcome. SHAP calculates the exact contribution of each feature:
- **Positive SHAP value (+)**: Pushed the prediction toward **malicious**.
  (e.g., abnormally high `Flow Packets/s` or large `Init Fwd Win Bytes`).
- **Negative SHAP value (-)**: Pushed the prediction toward **benign**.
  (e.g., normal flow duration or standard packet lengths).

### Implementation

Created `src/explain.py`:
- `get_tree_explainer(model)`: Builds and caches a `shap.TreeExplainer` for the
  Random Forest model so that inference remains fast.
- `explain_flow(flow, pipeline, top_k=5)`: Evaluates a traffic flow, generates
  local SHAP values for the malicious class, and ranks features into:
  - `top_attack_drivers`: Features that strongly increased attack probability.
  - `top_benign_drivers`: Features that exhibited normal characteristics.
  - Plain-English natural language summary for quick understanding.
- `format_explanation_table()`: Formats results into a clean CLI table or log.

---

## Milestone 7 — Threat Risk Engine

### Goal

Convert raw machine learning probabilities and attack classifications into
an actionable, transparent security risk level:
**LOW**, **MEDIUM**, **HIGH**, or **CRITICAL**.

### Transparent Scoring Logic

Rather than fabricating an obscure score, the system applies a documented,
reproducible composite formula:

$$\text{Risk Score} = (P_{\text{malicious}} \times 0.60) + (\text{Attack Severity Weight} \times 0.40) + \text{Log Boost}$$

- **Probability Weight (60 %)**: Model statistical confidence.
- **Attack Severity Weight (40 %)**: Inherent real-world danger of the attack:
  - `Benign`: 0.00
  - `PortScan`: 0.30 (Reconnaissance / probing)
  - `FTP-Patator` / `SSH-Patator` / `Web Attack`: 0.50 - 0.60 (Brute force / injection)
  - `DoS Hulk` / `DoS GoldenEye` / `Bot`: 0.75 - 0.80 (Active denial of service)
  - `DDoS` / `Heartbleed` / `SQL Injection`: 0.95 (Severe volumetric / exfiltration)
- **Log Correlation Boost**: Allows Milestone 9 host log evidence to dynamically
  escalate risk.

### Risk Level Mapping

| Range | Threat Level | Operational Meaning |
|---|---|---|
| `0.00 – 0.35` | **LOW** | Normal traffic or low-impact exploratory scans |
| `0.35 – 0.65` | **MEDIUM** | Password guessing / brute-force authentication attempts |
| `0.65 – 0.85` | **HIGH** | Active denial of service or botnet command-and-control |
| `0.85 – 1.00` | **CRITICAL** | Volumetric DDoS outage or remote database exploitation |

### Verified Test Results

- All 6 unit tests in `tests/test_xai_and_risk.py` passed in 0.04s.
- End-to-end demo `src/run_xai_and_risk_demo.py` confirms that:
  - Benign flows register as **LOW** risk with negative SHAP drivers.
  - DDoS flows register as **CRITICAL** risk (0.9200) with positive SHAP drivers
    (`Init Fwd Win Bytes`, `Flow Bytes/s`, `Flow Packets/s`).

---

## Milestone 10 — Automated Threat Response (Controlled Mitigation)

### Goal

Provide controlled defensive actions (such as dropping network packets or
blocking malicious source IPs) when a HIGH or CRITICAL attack is confirmed,
while maintaining strict safeguards against self-lockout or unintended damage.

### Safety Design

1. **Dry-Run Mode Enabled by Default**:
   In dry-run mode, the responder calculates and formats the exact Linux
   firewall command (`iptables -A INPUT -s <IP> -j DROP`) and writes the audit
   record to `logs/response.log`, without altering kernel firewall tables.
2. **Strict IP Whitelist**:
   `127.0.0.1`, `localhost`, `192.168.1.1`, and loopback subnets are permanently
   protected and can never be blocked.
3. **Audit Logging & Manual Override**:
   All mitigation actions are logged with timestamps and rationale, and
   administrators can manually unblock or block IPs through the API and dashboard.

---

## Milestone 11 — Real-Time Flask Web Dashboard

### Goal

Provide a live, visual monitoring dashboard connecting all components of the
detection pipeline — flow classification, attack identification, SHAP
explanations, risk levels, and automated threat mitigation.

### Architecture & Implementation

Created `src/app.py` and `src/templates/index.html`:
- **Backend API**:
  - `GET /api/status`: System operational state, total flows analyzed, attack counts.
  - `GET /api/events`: Real-time circular buffer stream of recently analyzed network flows.
  - `GET /api/event/<id>`: Full forensic details and SHAP explanation for a specific flow.
  - `POST /api/simulate`: Injects simulated traffic flows (Benign, DDoS, PortScan, SSH-Patator)
    and executes them through the full ML + XAI + Risk + Mitigation stack.
  - `POST /api/mitigation/toggle_dry_run`: Dynamic toggle between safe dry-run and live enforcement.
  - `POST /api/mitigation/unblock` / `block`: Manual IP management.
- **Frontend UI (`src/templates/index.html`)**:
  - Dark-mode responsive interface built with Tailwind CSS and FontAwesome.
  - Top KPI cards: Total Flows, Attacks Detected, Malicious Ratio, Highest Threat Tier, Mitigated IPs.
  - Real-time Traffic Event Table with color-coded risk tags (**LOW**, **MEDIUM**, **HIGH**, **CRITICAL**).
  - Interactive SHAP Inspector: Visual horizontal bar chart of top positive/negative feature
    contributions rendered dynamically via Chart.js.
  - Live Simulation Toolbar: Buttons to inject realistic test attacks and auto-stream mode.
  - Firewall Management Panel: View blocked IPs, toggle dry-run, and manual IP block controls.

### Verified Test Results

- All 6 dashboard test cases in `tests/test_dashboard_app.py` passed in 0.10s.
- Total test suite (`tests/`): 15 automated unit and integration tests passing.

---

## Milestone 9 — Linux System Log Correlation

### Goal

Enhance intrusion confidence by cross-referencing network-level anomalies
with host-level Linux authentication activity. If a remote attacker attempts
to brute-force SSH logins, evidence appears both in network packet flow
characteristics and in the host server's authentication syslog.

### Implementation (`src/log_correlator.py`)

- **Multi-Environment Log Detection**:
  - Automatically inspects Linux standard logs (`/var/log/auth.log`, `/var/log/secure`,
    or systemd journal) when running on Linux.
  - Automatically falls back to `logs/auth.log` on development/testing setups.
- **Log Parsing**:
  - Uses regular expressions to extract failed login attempts, targeted usernames
    (e.g., `root`, `admin`), source IP addresses, and timestamps.
- **Dynamic Risk Score Escalation**:
  - When network detection flags an attack and host authentication logs confirm
    simultaneous failed login attempts from the same source IP:
    - 1–2 failed attempts: adds `+0.08` risk boost.
    - 3–9 failed attempts: adds `+0.15` risk boost.
    - 10+ failed attempts: adds `+0.20` risk boost.
  - This escalates borderline probes into confirmed **HIGH** or **CRITICAL** incidents.

### Verified Test Results

- All 3 correlation unit tests in `tests/test_log_correlator.py` passed.
- Integrated seamlessly into `src/app.py` event processing.

---

## Milestone 8 — Network Packet Capture & Feature Mapping

### Goal

Bridge raw network packets into the 77 statistical flow features expected
by the trained Random Forest models.

### Implementation (`src/capture.py`)

- **Bidirectional Flow Assembly**:
  - Groups packets into flows using the 5-tuple: `(src_ip, dst_ip, src_port, dst_port, protocol)`.
  - Distinguishes forward packets (client-to-server) and backward packets (server-to-client).
- **Feature Extraction Pipeline**:
  - Calculates inter-arrival times (IAT), duration in microseconds, byte and packet rates,
    TCP flag tallies (SYN, FIN, RST, ACK, PSH, URG), and window sizes.
  - Outputs a complete 77-feature dictionary strictly conforming to `models/feature_names.json`.
- **Live Sniffing & Safe Simulation**:
  - Supports live interface sniffing with Scapy.
  - Provides simulated packet generation for safe, cross-platform demonstration without root access.

### Verified Test Results

- All 3 capture unit tests in `tests/test_capture.py` passed.

---

## Milestone 12 — End-to-End System Integration

### Goal

Unify all submodules into an automated pipeline executable via a single command.

### Pipeline Flow

$$\text{Packet Capture (M8)} \longrightarrow \text{77-Feature Mapping} \longrightarrow \text{Stage 1 \& 2 ML (M4, M5)} \longrightarrow \text{Log Correlation (M9)} \longrightarrow \text{Risk Engine (M7)} \longrightarrow \text{SHAP XAI (M6)} \longrightarrow \text{Threat Mitigation (M10)} \longrightarrow \text{Dashboard (M11)}$$

### Orchestration Script (`main.py`)

- `python main.py`: Runs the complete end-to-end integration scenario across Benign,
  SSH Brute-Force, and DDoS traffic.
- `python main.py --web`: Launches the Flask real-time monitoring web dashboard.

---

## Milestone 13 — System Evaluation & Presentation Deliverables

### Summary of Completed Milestones

All 13 milestones outlined in `PROJECT_CONTEXT.md` are fully implemented and verified:
- **18 automated unit and integration tests** passing in `tests/`.
- Working **Explainable AI (SHAP)** engine delivering human-readable rationale.
- Deterministic **Risk Engine** mapping attacks to LOW/MED/HIGH/CRITICAL tiers.
- Safe **Firewall Response** module running with dry-run protection.
- Live **Flask Web Dashboard** with real-time SOC-style monitoring.
- **Dual-Mode User Interface (HCI Accessibility)**:
  - **Simple Mode (Non-Technical Users)**: Translates IP addresses into human device origins
    (e.g., `🏠 Local Home/Office Device`, `⚠️ Suspicious External Machine`), translates
    attack categories into plain English (`💥 Traffic Flood Attack`, `🔑 Password Guessing Attack`),
    provides actionable advice ("What Should I Do?"), and translates SHAP math into simple stories.
  - **Expert Mode (SOC Analysts & Evaluators)**: Displays raw network 5-tuples, exact mathematical
    features, iptables syntax, and interactive SHAP TreeExplainer contribution charts.

---

## Milestone 14 — Native Wireshark Integration & 3-Pane Packet Inspection

### Goal

Integrate Wireshark network packet capture (`.pcap` / `.pcapng`), deep packet inspection (DPI), and live Linux interface sniffing directly into the web dashboard.

### Implemented Features

1. **Browser `.pcap` Upload Engine**:
   - Web endpoint `/api/upload_pcap` accepts `.pcap` or `.pcapng` files exported directly from Wireshark or `tcpdump`.
   - The backend aggregates packets into bidirectional 5-tuple flows, computes 77 CICFlowMeter features, evaluates them with the ML models, computes risk scores, and pushes results into the dashboard in real time.

2. **Wireshark 3-Pane Packet Dissector Modal**:
   - Clicking any traffic incident opens an interactive modal mimicking Wireshark's classic 3-pane interface:
     - **Top Pane:** Packet Frame Stream (`No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Flags/Info`).
     - **Middle Pane:** Decoded OSI Protocol Tree (`Frame` -> `Ethernet II` -> `IPv4` -> `TCP/UDP`).
     - **Bottom Pane:** Raw Wire Hex Dump with byte offsets.

3. **Linux Live Sniffer Background Controller**:
   - Managed background daemon via `/api/capture/start`, `/api/capture/stop`, and `/api/capture/status`.
   - Directly sniffs live Linux interfaces (`eth0`, `wlan0`, `lo`) via Scapy/libpcap.
   - Includes graceful synthetic fallback for restricted test environments.

4. **Bundled Demo Attack PCAPs**:
   - `data/sample_pcaps/syn_flood_ddos.pcap` (DDoS SYN-flood attack stream).
   - `data/sample_pcaps/ssh_bruteforce.pcap` (SSH password-guessing brute-force session).
   - `data/sample_pcaps/benign_web_browsing.pcap` (Normal HTTP/HTTPS request/response exchange).

