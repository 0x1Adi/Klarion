#!/usr/bin/env python3
"""Render the benchmark result tables (markdown) from results/*.json."""

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"

ORDER = ["klarion-ai", "klarion", "gitleaks", "trufflehog", "detect-secrets", "ripsecrets"]
LABEL = {
    "klarion-ai": "**Klarion (AI, claude-cli/haiku)**",
    "klarion": "Klarion (candidates, no AI)",
    "gitleaks": "gitleaks 8.30.0",
    "trufflehog": "trufflehog 3.93.5",
    "detect-secrets": "detect-secrets 1.5.0",
    "ripsecrets": "ripsecrets 0.1.11",
}


def acc():
    d = json.loads((RESULTS / "accuracy.json").read_text())
    print("### leaky-repo accuracy (44 ground-truth files, 42 with risk secrets)\n")
    print("| Tool | Findings | Files covered | File coverage | Find coverage | Risk-file recall | File precision | F1 |")
    print("|---|---|---|---|---|---|---|---|")
    for t in ORDER:
        L = d.get(t, {}).get("leaky")
        if not L or "error" in L:
            continue
        print(f"| {LABEL[t]} | {L['total_findings']} | {L['files_covered']}/44 | "
              f"{L['file_coverage_pct']}% | {L['find_coverage_pct']}% | "
              f"{L['risk_file_recall']:.2f} | {L['file_precision']:.2f} | {L['file_f1']:.2f} |")
    print("\n### Clean-corpus noise (flask 3.2MB + rails 51MB working trees)\n")
    print("| Tool | flask findings | rails findings | rails files flagged |")
    print("|---|---|---|---|")
    for t in ORDER:
        r = d.get(t, {})
        if "flask" not in r or "error" in r.get("flask", {}):
            continue
        print(f"| {LABEL[t]} | {r['flask']['total_findings']} | {r['rails']['total_findings']} | {r['rails']['files_flagged']} |")


def timing():
    print("\n### Scan speed (hyperfine, ≥5 runs, offline modes)\n")
    print("| Tool | leaky-repo (704KB) | rails (51MB) |")
    print("|---|---|---|")
    rows = {}
    for ds in ("leaky", "rails"):
        f = RESULTS / f"timing-{ds}.json"
        for r in json.loads(f.read_text())["results"]:
            rows.setdefault(r["command"] if False else r.get("parameters", {}).get("name") or r["command"], {})
    # hyperfine stores names under 'command' when -n used? It stores in 'command' the actual command; names live in 'command' only without -n. Use zip with known order.
    names = ["klarion", "gitleaks", "trufflehog", "detect-secrets", "ripsecrets"]
    data = {}
    for ds in ("leaky", "rails"):
        res = json.loads((RESULTS / f"timing-{ds}.json").read_text())["results"]
        for name, r in zip(names, res):
            data.setdefault(name, {})[ds] = (r["mean"], r["stddev"])
    for name in names:
        l, rr = data[name]["leaky"], data[name]["rails"]
        def fmt(t):
            m, s = t
            return f"{m*1000:.1f} ms ± {s*1000:.1f}" if m < 1 else f"{m:.2f} s ± {s:.2f}"
        label = LABEL["klarion"] if name == "klarion" else LABEL.get(name, name)
        if name == "klarion":
            label = "Klarion (scan stage, no AI)"
        print(f"| {label} | {fmt(l)} | {fmt(rr)} |")


def history():
    h = json.loads((RESULTS / "history.json").read_text())
    print("\n### Git-history scanning (leaky-repo, 25 commits)\n")
    print("| Tool | Findings | Files |")
    print("|---|---|---|")
    for t in ("klarion", "gitleaks", "trufflehog"):
        print(f"| {t} | {h[t]['findings']} | {h[t]['files']} |")
    print("\n(detect-secrets and ripsecrets do not scan git history.)")


def audits():
    d = json.loads((RESULTS / "study.json").read_text())
    print("\n### Human-audited composition of clean-corpus findings (rails+flask)\n")
    print("| Tool | Reviewed | Dummy test fixture | Placeholder/example | Pure noise | Possibly real |")
    print("|---|---|---|---|---|---|")
    for fp in d["fp"]:
        s = fp["audit"]["summary"]
        print(f"| {fp['tool']} | {s['total_reviewed']} | {s['dummy_fixture']} | "
              f"{s['placeholder_example']} | {s['noise']} | {s['possibly_real']} |")


if __name__ == "__main__":
    acc()
    timing()
    history()
    audits()
