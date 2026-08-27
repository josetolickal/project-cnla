"""Validate CICIDS2017 flow files and create a binary IDS training dataset.

The original ``Label`` column is retained as ``attack_type``.  The added
``is_malicious`` column is the first model target: 0 means Benign traffic and
1 means any attack.  Files are processed one at a time so the full dataset
does not need to fit in memory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


LABEL_COLUMN = "Label"
BENIGN_LABEL = "Benign"


def preprocess_file(input_path: Path, output_path: Path) -> dict[str, int | str]:
    """Validate one Parquet file and write its processed version."""
    frame = pd.read_parquet(input_path)
    frame.columns = frame.columns.str.strip()

    if LABEL_COLUMN not in frame.columns:
        raise ValueError(f"{input_path.name} does not contain a '{LABEL_COLUMN}' column.")

    feature_columns = [column for column in frame.columns if column != LABEL_COLUMN]
    non_numeric = [
        column for column in feature_columns if not pd.api.types.is_numeric_dtype(frame[column])
    ]
    if non_numeric:
        raise ValueError(f"{input_path.name} has non-numeric features: {non_numeric}")

    rows_before = len(frame)
    missing_rows = frame.isna().any(axis=1)
    finite_rows = np.isfinite(frame[feature_columns].to_numpy()).all(axis=1)
    valid_rows = ~missing_rows & finite_rows
    cleaned = frame.loc[valid_rows].copy()

    labels = cleaned.pop(LABEL_COLUMN).astype("string").str.strip()
    cleaned["attack_type"] = labels
    cleaned["is_malicious"] = (labels != BENIGN_LABEL).astype("int8")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    cleaned.to_parquet(output_path, index=False)

    return {
        "input_file": input_path.name,
        "output_file": output_path.name,
        "rows_before": rows_before,
        "rows_after": len(cleaned),
        "rows_removed_missing": int(missing_rows.sum()),
        "rows_removed_infinite": int((~finite_rows).sum()),
        "benign_rows": int((cleaned["is_malicious"] == 0).sum()),
        "malicious_rows": int((cleaned["is_malicious"] == 1).sum()),
        "feature_count": len(feature_columns),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        type=Path,
        default=Path("data/cicids2017_kaggle/raw"),
        help="Folder containing source Parquet files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/processed/cicids2017_binary"),
        help="Folder for processed Parquet files and the processing summary.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Optional limit for a quick test run.",
    )
    args = parser.parse_args()

    input_paths = sorted(args.input_dir.glob("*.parquet"))
    if args.max_files is not None:
        input_paths = input_paths[: args.max_files]
    if not input_paths:
        raise FileNotFoundError(f"No Parquet files found in {args.input_dir}")

    summaries = [
        preprocess_file(path, args.output_dir / path.name) for path in input_paths
    ]
    totals = {
        "files_processed": len(summaries),
        "rows_before": sum(item["rows_before"] for item in summaries),
        "rows_after": sum(item["rows_after"] for item in summaries),
        "benign_rows": sum(item["benign_rows"] for item in summaries),
        "malicious_rows": sum(item["malicious_rows"] for item in summaries),
        "rows_removed_missing": sum(item["rows_removed_missing"] for item in summaries),
        "rows_removed_infinite": sum(item["rows_removed_infinite"] for item in summaries),
    }
    summary = {"files": summaries, "totals": totals}
    summary_path = args.output_dir / "processing_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(totals, indent=2))
    print(f"Saved summary to {summary_path}")


if __name__ == "__main__":
    main()
