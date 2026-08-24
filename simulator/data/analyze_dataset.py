import sys
from pathlib import Path
import pandas as pd


def analyze_dataset():
    data_dir = Path(__file__).resolve().parent
    dataset_path = data_dir / "consolidated_dataset_raw.csv"
    report_path = data_dir / "dataset_analysis_report.txt"

    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}")
        sys.exit(1)

    print(f"Loading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path)

    report_lines = []

    def log(line=""):
        print(line)
        report_lines.append(line)

    log("=" * 80)
    log("          ORBITAL_SHIELD - DATASET ANALYSIS REPORT")
    log("=" * 80)
    log(f"Source file: {dataset_path.name}")
    log()

    # 1 & 2. Row and column count
    num_rows, num_cols = df.shape
    log("1. DATASET DIMENSIONS")
    log("-" * 80)
    log(f"Total Rows   : {num_rows:,}")
    log(f"Total Columns: {num_cols}")
    log()

    # 3. Columns and datatypes
    log("2. COLUMNS AND DATA TYPES")
    log("-" * 80)
    col_info = []
    for col in df.columns:
        col_info.append(f" - {col:<32} : {str(df[col].dtype):<10}")
    log("\n".join(col_info))
    log()

    # 4. Missing values
    log("3. MISSING VALUES PER COLUMN")
    log("-" * 80)
    missing_series = df.isnull().sum()
    total_missing = missing_series.sum()
    log(f"Total Missing Values in Dataset: {total_missing}")
    if total_missing == 0:
        log("No missing values found across any columns.")
    else:
        for col, count in missing_series.items():
            if count > 0:
                pct = (count / num_rows) * 100
                log(f" - {col:<32} : {count} ({pct:.2f}%)")
    log()

    # 5. Categorical & discrete unique value counts
    log("4. UNIQUE VALUES COUNT (CATEGORICAL / DISCRETE COLUMNS)")
    log("-" * 80)
    discrete_cols = [
        col for col in df.columns if df[col].dtype == "object" or df[col].nunique() <= 20
    ]
    for col in discrete_cols:
        unique_cnt = df[col].nunique()
        log(f" - {col:<32} : {unique_cnt} unique value(s)")
        if unique_cnt <= 10:
            val_counts = df[col].value_counts().to_dict()
            log(f"    Values: {val_counts}")
    log()

    # 6. Label distribution
    log("5. LABEL VALUE DISTRIBUTION")
    log("-" * 80)
    if "Label" in df.columns:
        label_counts = df["Label"].value_counts(dropna=False).sort_index()
        label_pcts = df["Label"].value_counts(normalize=True, dropna=False).sort_index() * 100
        log(f"{'Label':<10} {'Count':<15} {'Percentage':<15}")
        log("-" * 40)
        for label_val, count in label_counts.items():
            pct = label_pcts[label_val]
            log(f"{str(label_val):<10} {count:<15,d} {pct:>6.2f}%")
    else:
        log("Column 'Label' not found in dataset.")
    log()

    # 7. Basic descriptive statistics for numeric columns
    log("6. DESCRIPTIVE STATISTICS (NUMERIC COLUMNS)")
    log("-" * 80)
    desc = df.describe().T
    desc_formatted = desc[["mean", "std", "min", "25%", "50%", "75%", "max"]]
    log(desc_formatted.to_string())
    log()

    # 8. Duplicate rows
    log("7. DUPLICATE ROWS")
    log("-" * 80)
    dup_count = df.duplicated().sum()
    log(f"Duplicate Rows Count: {dup_count:,} ({(dup_count / num_rows) * 100:.2f}%)")
    log()

    # 9. Constant columns
    log("8. CONSTANT COLUMNS DETECTION")
    log("-" * 80)
    constant_cols = [col for col in df.columns if df[col].nunique() <= 1]
    if constant_cols:
        log(f"Constant columns found ({len(constant_cols)}):")
        for col in constant_cols:
            val = df[col].iloc[0] if num_rows > 0 else None
            log(f" - {col:<32} (Constant Value: {val})")
    else:
        log("No constant columns detected.")
    log()

    log("=" * 80)
    log("                    END OF REPORT")
    log("=" * 80)

    # 10. Save to dataset_analysis_report.txt
    report_content = "\n".join(report_lines) + "\n"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"\nAnalysis report successfully saved to: {report_path}")


if __name__ == "__main__":
    analyze_dataset()
