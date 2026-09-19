#!/usr/bin/env python3
"""Klarion comparative benchmark harness.

Runs klarion, gitleaks, trufflehog, detect-secrets, and ripsecrets over:
  1. leaky-repo (Plazmaz/leaky-repo) -- real-format secret corpus with an
     official per-file ground truth (.leaky-meta/secrets.csv). Scored with
     the dataset's official methodology (file coverage, capped find
     coverage, FP overage) plus file-level precision/recall/F1 against
     risk files.
  2. flask + rails checkouts -- clean real-world corpora; every finding is
     counted as noise (a small number may be intentional dummy fixtures;
     they are reported for manual review, not silently dropped).

All tools run in offline mode (no network verification) for parity.
Raw tool outputs are preserved under results/raw/.
"""

import csv
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent
REPO = BENCH.parent
TARGETS = BENCH / "datasets" / "scan-targets"
RAW = BENCH / "results" / "raw"
RESULTS = BENCH / "results"
GT_CSV = BENCH / "datasets" / "leaky-repo" / ".leaky-meta" / "secrets.csv"

DATASETS = ["leaky", "flask", "rails"]


def sh(cmd, cwd, ok_codes=(0, 1), stream_stderr=False):
    # stream_stderr passes the tool's stderr straight to the terminal. Klarion
    # writes its adjudication progress there; captured, a multi-minute AI run
    # printed nothing and looked like a hang. The report is on stdout either way.
    t0 = time.monotonic()
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=None if stream_stderr else subprocess.PIPE, text=True)
    dt = time.monotonic() - t0
    if p.returncode not in ok_codes:
        detail = "(printed above)" if stream_stderr else p.stderr[-2000:]
        raise RuntimeError(f"{cmd} exited {p.returncode}\nstderr: {detail}")
    return p.stdout, dt


def norm(path, dataset):
    """Strip dataset dir prefix and leading ./ from a reported path."""
    while path.startswith("./"):
        path = path[2:]
    prefix = dataset + "/"
    if path.startswith(prefix):
        path = path[len(prefix):]
    abs_prefix = str(TARGETS / dataset) + "/"
    if path.startswith(abs_prefix):
        path = path[len(abs_prefix):]
    return path


# ---------------------------------------------------------------- runners
# Each runner returns (findings, seconds, raw_text) where findings is a
# list of {"file": relpath, "line": int|None, "rule": str}.

def _run_klarion_cmd(dataset, extra):
    # Explicit config always: without it klarion auto-discovers the repo's own
    # dogfood .klarion.toml, whose allowlists (docs/** etc.) would contaminate
    # the comparison.
    cmd = [str(REPO / "klarion"), "scan", "-f", "json"] + extra + [dataset]
    out, dt = sh(cmd, cwd=TARGETS, stream_stderr=True)
    data = json.loads(out)
    finds = [
        {"file": norm(f["file"], dataset), "line": f.get("line"), "rule": f["rule_id"]}
        for f in data.get("findings") or []
    ]
    return finds, dt, out


def run_klarion(dataset):
    return _run_klarion_cmd(
        dataset, ["--no-ai", "--config", str(HERE / "klarion-neutral.toml")]
    )


def run_klarion_ai(dataset):
    return _run_klarion_cmd(
        dataset, ["--config", str(HERE / "klarion-ai.toml")]
    )


def run_klarion_cs(dataset):
    # Keyless: CredSweeper's ML model as the judge. KLARION_CS_NOMATCH picks
    # the policy for candidates CredSweeper never extracted (see the script).
    # Klarion reports paths relative to the scan root; the judge needs it.
    os.environ["KLARION_CS_ROOT"] = str(TARGETS / dataset)
    return _run_klarion_cmd(
        dataset, ["--config", str(HERE / "klarion-cs.toml")]
    )


def run_gitleaks(dataset):
    report = RAW / f"gitleaks-{dataset}.json"
    _, dt = sh(
        ["gitleaks", "dir", dataset, "--report-format", "json",
         "--report-path", str(report), "--exit-code", "0", "--no-banner"],
        cwd=TARGETS, ok_codes=(0,),
    )
    raw = report.read_text()
    data = json.loads(raw) if raw.strip() else []
    finds = [
        {"file": norm(f["File"], dataset), "line": f.get("StartLine"), "rule": f["RuleID"]}
        for f in data
    ]
    return finds, dt, raw


def run_trufflehog(dataset):
    out, dt = sh(
        ["trufflehog", "filesystem", dataset, "--json",
         "--no-verification", "--no-update"],
        cwd=TARGETS, ok_codes=(0, 1, 183),
    )
    finds = []
    for line in out.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        meta = obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        if not meta.get("file"):
            continue
        finds.append({
            "file": norm(meta["file"], dataset),
            "line": meta.get("line"),
            "rule": obj.get("DetectorName", "?"),
        })
    return finds, dt, out


def run_detect_secrets(dataset):
    out, dt = sh(
        ["detect-secrets", "scan", "--all-files"],
        cwd=TARGETS / dataset,
    )
    data = json.loads(out)
    finds = []
    for fname, entries in (data.get("results") or {}).items():
        for e in entries:
            finds.append({
                "file": norm(fname, dataset),
                "line": e.get("line_number"),
                "rule": e.get("type", "?"),
            })
    return finds, dt, out


def run_ripsecrets(dataset):
    out, dt = sh(["ripsecrets", dataset + "/"], cwd=TARGETS)
    finds = []
    for line in out.splitlines():
        m = re.match(r"^(.+?):(\d+):", line)
        if m:
            finds.append({
                "file": norm(m.group(1), dataset),
                "line": int(m.group(2)),
                "rule": "ripsecrets",
            })
    return finds, dt, out


RUNNERS = {
    "klarion": run_klarion,
    "klarion-ai": run_klarion_ai,
    "klarion-cs": run_klarion_cs,
    "klarion-cs-unc": lambda d: (os.environ.__setitem__("KLARION_CS_NOMATCH", "uncertain"), run_klarion_cs(d))[1],
    "gitleaks": run_gitleaks,
    "trufflehog": run_trufflehog,
    "detect-secrets": run_detect_secrets,
    "ripsecrets": run_ripsecrets,
}


# ---------------------------------------------------------------- scoring

def load_ground_truth():
    rows = []
    with open(GT_CSV) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, risk, info = next(csv.reader([line]))
            rows.append({"file": name, "risk": int(risk), "info": int(info)})
    return rows


def score_leaky(findings, gt):
    """Official leaky-repo methodology + file-level P/R/F1 on risk files."""
    per_file = defaultdict(int)
    for f in findings:
        per_file[f["file"]] += 1

    gt_files = {r["file"] for r in gt}
    risk_files = {r["file"] for r in gt if r["risk"] > 0}

    total_expected = sum(r["risk"] + r["info"] for r in gt)
    capped_finds = 0
    overage_fp = 0
    files_covered = 0
    per_file_rows = []
    for r in gt:
        found = per_file.get(r["file"], 0)
        expected = r["risk"] + r["info"]
        capped = min(found, expected)
        capped_finds += capped
        overage_fp += max(found - expected, 0)
        if found:
            files_covered += 1
        per_file_rows.append({
            "file": r["file"], "expected": expected, "risk": r["risk"],
            "found": found,
        })

    flagged = set(per_file)
    out_of_gt = sorted(flagged - gt_files)
    out_of_gt_findings = sum(per_file[f] for f in out_of_gt)

    tp_files = len(flagged & risk_files)
    prec = tp_files / len(flagged) if flagged else 0.0
    rec = tp_files / len(risk_files)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    return {
        "total_findings": len(findings),
        "files_covered": files_covered,
        "gt_files": len(gt_files),
        "file_coverage_pct": round(100 * files_covered / len(gt_files), 2),
        "capped_finds": capped_finds,
        "total_expected": total_expected,
        "find_coverage_pct": round(100 * capped_finds / total_expected, 2),
        "overage_fp_in_gt_files": overage_fp,
        "out_of_gt_files_flagged": out_of_gt,
        "out_of_gt_findings": out_of_gt_findings,
        "risk_files_total": len(risk_files),
        "risk_files_detected": tp_files,
        "risk_files_missed": sorted(risk_files - flagged),
        "file_precision": round(prec, 4),
        "risk_file_recall": round(rec, 4),
        "file_f1": round(f1, 4),
        "per_file": per_file_rows,
    }


def score_clean(findings):
    per_file = defaultdict(int)
    for f in findings:
        per_file[f["file"]] += 1
    by_rule = defaultdict(int)
    for f in findings:
        by_rule[f["rule"]] += 1
    return {
        "total_findings": len(findings),
        "files_flagged": len(per_file),
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "findings": [
            {"file": f["file"], "line": f["line"], "rule": f["rule"]}
            for f in sorted(findings, key=lambda x: (x["file"], x["line"] or 0))
        ],
    }


def main():
    only_tools = sys.argv[1].split(",") if len(sys.argv) > 1 else list(RUNNERS)
    only_datasets = sys.argv[2].split(",") if len(sys.argv) > 2 else DATASETS
    RAW.mkdir(parents=True, exist_ok=True)
    gt = load_ground_truth()
    out = RESULTS / "accuracy.json"
    existing = json.loads(out.read_text()) if out.exists() else {}
    results = {}
    for tool in only_tools:
        runner = RUNNERS[tool]
        results[tool] = existing.get(tool, {})
        for dataset in only_datasets:
            print(f"[{tool}] scanning {dataset} ...", flush=True)
            try:
                finds, dt, raw = runner(dataset)
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                results[tool][dataset] = {"error": str(e)}
                continue
            (RAW / f"{tool}-{dataset}.out").write_text(raw)
            score = score_leaky(finds, gt) if dataset == "leaky" else score_clean(finds)
            score["wall_seconds"] = round(dt, 3)
            results[tool][dataset] = score
            print(f"  {len(finds)} findings in {dt:.2f}s", flush=True)

    existing.update(results)
    out.write_text(json.dumps(existing, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
