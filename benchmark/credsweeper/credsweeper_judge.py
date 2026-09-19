#!/usr/bin/env python3
"""Klarion `ai.provider = "command"` judge backed by CredSweeper's ML model.

stdin: JSON array of Klarion candidates. stdout: {"results": [...]}.
Runs `python -m credsweeper` once per batch over the batch's files, then
joins CredSweeper's per-line ml_probability onto each candidate by
(path, line span). No key, no network. `pip install credsweeper` first.

Env: KLARION_CS_HI (secret at/above, default CredSweeper "medium"),
     KLARION_CS_LO (false_positive below, default "lowest"),
     KLARION_CS_NOMATCH = false_positive | uncertain (candidate at a line
     CredSweeper extracted nothing from; default false_positive),
     KLARION_CS_ROOT: Klarion reports paths relative to the scan root; set
     this to that root when it is not the cwd.
"""
import json
import os
import subprocess
import sys
import tempfile

HI = float(os.environ.get("KLARION_CS_HI", "0.62204"))
LO = float(os.environ.get("KLARION_CS_LO", "0.22917"))
NOMATCH = os.environ.get("KLARION_CS_NOMATCH", "false_positive")
ROOT = os.environ.get("KLARION_CS_ROOT", "")


def resolve(path):
    return os.path.abspath(os.path.join(ROOT, path) if ROOT and not os.path.isabs(path) else path)


def credsweeper(files):
    """{abspath: {line_num: (probability, rule)}} for every candidate CredSweeper extracts."""
    present = [f for f in files if os.path.isfile(f)]
    if not present:
        sys.exit(f"credsweeper_judge: none of {len(files)} candidate files exist from {os.getcwd()}; "
                 "set KLARION_CS_ROOT to the scan root")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    cmd = [sys.executable, "-m", "credsweeper", "--path", *present, "--ml_threshold", "0.0001",
           "--ml_batch_size", "64", "--log", "error", "--save-json", out]
    p = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        sys.exit(f"credsweeper exited {p.returncode}: {p.stderr[-500:]}")
    raw = open(out).read()
    data = json.loads(raw) if raw.strip() else []  # CredSweeper writes nothing when it scanned nothing
    os.unlink(out)
    idx = {}
    for c in data:
        # Rules with use_ml=false carry no probability: a pattern-specific hit, treat as strong.
        prob = 1.0 if c.get("ml_probability") is None else float(c["ml_probability"])
        for ld in c.get("line_data_list") or []:
            lines = idx.setdefault(os.path.abspath(ld["path"]), {})
            cur = lines.get(ld["line_num"])
            if cur is None or prob > cur[0]:
                lines[ld["line_num"]] = (prob, c.get("rule", "?"))
    return idx


def judge(reqs, idx):
    results, tally = [], {"match": 0, "nomatch": 0}
    for r in reqs:
        lines = idx.get(resolve(r["file"]), {})
        span = range(r["line"], r["line"] + max(1, min(r.get("occurrences") or 1, 64)))
        hit = max((lines[n] for n in span if n in lines), default=None)
        if hit is None:
            tally["nomatch"] += 1
            v = {"status": NOMATCH, "confidence": 0.7, "reason": "credsweeper: nothing extracted at this line"}
        else:
            tally["match"] += 1
            p, rule = hit
            if p >= HI:
                v = {"status": "secret", "confidence": p}
            elif p < LO:
                v = {"status": "false_positive", "confidence": 1 - p}
            else:
                v = {"status": "uncertain", "confidence": 0.5}
            v["reason"] = f"credsweeper {rule} p={p:.3f}"
        results.append({"index": r["index"], **v})
        if os.environ.get("KLARION_CS_DUMP"):  # per-candidate rows for miss analysis
            with open(os.environ["KLARION_CS_DUMP"], "a") as d:
                d.write(json.dumps({"file": r["file"], "line": r["line"], "rule": r.get("rule_id"), **v}) + "\n")
        tally[v["status"]] = tally.get(v["status"], 0) + 1
    line = f"credsweeper_judge: {len(reqs)} candidates {tally}\n"
    sys.stderr.write(line)
    if os.environ.get("KLARION_CS_LOG"):  # Klarion only shows a judge's stderr on failure
        with open(os.environ["KLARION_CS_LOG"], "a") as log:
            log.write(line)
    return results


def selftest():
    """Sanity: a real-format key scores above a placeholder; a bare identifier is not extracted."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write('aws_secret_access_key = "' + "Q3x9kLm2Zp8vTn4Rw7Yb" + '1Hc5Jd0Fg6Ns3Vt2Xa9Ue"\n')
        f.write('password = "your_password_here"\n')
        f.write("SseCustomerKeySHA256AttrName = SseCustomerKeySHA256AttrName\n")
    reqs = [{"index": i, "file": f.name, "line": i + 1, "occurrences": 1} for i in range(3)]
    res = judge(reqs, credsweeper([f.name]))
    os.unlink(f.name)
    print(json.dumps(res, indent=1))
    assert res[0]["status"] == "secret", "FN: real-format key not judged secret"
    assert res[1]["status"] != "secret", "FP: placeholder judged secret"
    assert "nothing extracted" in res[2]["reason"], "identifier line should be nomatch"
    print("OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    reqs = json.load(sys.stdin)
    files = sorted({resolve(r["file"]) for r in reqs})
    print(json.dumps({"results": judge(reqs, credsweeper(files)) if files else []}))
