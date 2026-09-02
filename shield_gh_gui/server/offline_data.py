"""Reads the real SHIELD-GH evidence CSVs as-is. No synthetic fallback rows."""
import csv
import os

SCRATCH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

DATASETS = {
    "e1": {
        "label": "E1 — MCC/GHSR/AVCR/FIR/ESRL raw results",
        "path": os.path.join(SCRATCH_ROOT, "E1_results", "e1_raw_results.csv"),
    },
    "multiseed": {
        "label": "Task 9 — multi-seed MCC comparison",
        "path": os.path.join(SCRATCH_ROOT, "Task9_Evidence", "multiseed_results.csv"),
    },
    "ablation": {
        "label": "Task 9.5 — ablation study",
        "path": os.path.join(SCRATCH_ROOT, "Task9_5_Evidence", "ablation_results.csv"),
    },
}


def _coerce(value):
    if value == "" or value is None:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def list_datasets():
    out = []
    for key, meta in DATASETS.items():
        exists = os.path.isfile(meta["path"])
        columns = []
        if exists:
            with open(meta["path"], newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                columns = next(reader, [])
        out.append({
            "key": key,
            "label": meta["label"],
            "path": os.path.relpath(meta["path"], SCRATCH_ROOT),
            "available": exists,
            "columns": columns,
        })
    return out


def read_dataset(key):
    """Reads the file's first CSV table only. Some of these files (e.g.
    Task9_Evidence/multiseed_results.csv) concatenate a second summary table
    after a blank line with a different column set — that second table is
    real data too, just not this endpoint's shape, so we stop at the blank
    line rather than crash or silently merge two schemas into one row list."""
    meta = DATASETS.get(key)
    if meta is None:
        return None
    if not os.path.isfile(meta["path"]):
        return None
    with open(meta["path"], newline="", encoding="utf-8") as f:
        lines = []
        for raw_line in f:
            if raw_line.strip() == "":
                break
            lines.append(raw_line)
    reader = csv.DictReader(lines)
    columns = reader.fieldnames or []
    rows = []
    for row in reader:
        row.pop(None, None)  # drop any ragged overflow field, shouldn't occur post-truncation
        rows.append({k: _coerce(v) for k, v in row.items()})
    return {"columns": columns, "rows": rows, "path": os.path.relpath(meta["path"], SCRATCH_ROOT)}
