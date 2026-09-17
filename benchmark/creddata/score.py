"""Score scanner output against CredData labels.

A labeled line is (FilePath, LineStart, LineEnd): T if any label on it is T,
X if all its labels are X, else F. A finding covers a line span (a collapsed key
block or a multi-line gitleaks match covers several) and hits the labeled lines
whose range intersects it (only the T ones when any is T). Findings on unlabeled lines
are counted but excluded from precision, as CredData's own benchmark does.

Views:
  line      every labeled line; X counts as negative (CredData: non-T is false)
  line-noX  X lines ignored
  line-prod lines outside test-purpose scope dirs (test, mock, example,
            sample, fixture); CredData labels all test credentials T (rule 1)
  line-prod-noUUID  line-prod without T lines whose only category is UUID
            (sampled: COM GUIDs, badge ids, ARNs -- identifiers, not secrets)
  file      a file is positive if it has a T line; a tool hits it if it hits a
            T line; a negative file is hit if the tool hits any of its lines

usage: score.py <creddata-root> <tool> <output> [<tool> <output> ...]
       score.py <creddata-root> --selftest
tools: klarion (findings+suppressed = all candidates), klarion-kept (findings
       only), gitleaks (JSON report), detect-secrets (JSON)
"""
import csv, glob, json, re, sys
from collections import defaultdict

TEST_SCOPE = re.compile(r"^data/[0-9a-f]{8}/(?:[^/]+/)*(?:test|mock|example|sample|fixture)/")

UUID_ONLY = set()                        # (path, start, end) whose T labels are all UUID

def load_labels(root):
    gt, tcat = defaultdict(set), defaultdict(set)
    for f in glob.glob(f"{root}/meta/*.csv"):
        for r in csv.DictReader(open(f, newline="")):
            key = (r["FilePath"], int(r["LineStart"]), int(r["LineEnd"]))
            gt[key].add(r["GroundTruth"])
            if r["GroundTruth"] == "T":
                tcat[key].update(r["Category"].split(":"))
    UUID_ONLY.update(k for k, c in tcat.items() if c == {"UUID"})
    by_file = defaultdict(list)          # path -> [(start, end, label)]
    for (path, s, e), g in gt.items():
        by_file[path].append((s, e, "T" if "T" in g else "F" if "F" in g else "X"))
    return by_file

def norm(path):
    # anchor on data/<8-hex repo id>/: a bare find("data/") matches "creddata/"
    path = path.replace("\\", "/")
    m = re.search(r"(?:^|/)(data/[0-9a-f]{8}/.*)$", path)
    return m.group(1) if m else "data/" + path.lstrip("./")

def findings(tool, out):
    if tool.startswith("klarion"):
        d = json.load(open(out))
        rows = (d.get("findings") or []) + ([] if tool == "klarion-kept" else (d.get("suppressed") or []))
        # a collapsed key block spans `occurrences` lines from `line`
        return [(norm(r["file"]), r["line"], r["line"] + max(r.get("occurrences") or 1, 1) - 1) for r in rows]
    if tool == "gitleaks":
        return [(norm(r["File"]), r["StartLine"], max(r["EndLine"], r["StartLine"])) for r in json.load(open(out)) or []]
    if tool == "detect-secrets":
        d = json.load(open(out))
        return [(norm(p), r["line_number"], r["line_number"]) for p, rs in d["results"].items() for r in rs]
    raise SystemExit(f"unknown tool {tool}")

def prf(tp, fp, P):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / P if P else 0.0
    return dict(TP=tp, FP=fp, FN=P - tp, precision=round(p, 4), recall=round(r, 4),
                f1=round(2 * p * r / (p + r), 4) if p + r else 0.0)

def score(labels, finds):
    hit, unlabeled = set(), 0
    for path, lo, hi in finds:
        matched = [(path, s, e, g) for s, e, g in labels.get(path, ()) if s <= hi and lo <= e]
        unlabeled += not matched
        if any(m[3] == "T" for m in matched):
            # a T range overlapping a non-T range: flagging the credential is correct
            matched = [m for m in matched if m[3] == "T"]
        hit.update(matched)
    allrows = [(p, s, e, g) for p, rows in labels.items() for s, e, g in rows]
    def view(keep, neg=("F", "X")):
        rows = [r for r in allrows if keep(r)]
        P = sum(r[3] == "T" for r in rows)
        tp = sum(1 for r in hit if keep(r) and r[3] == "T")
        fp = sum(1 for r in hit if keep(r) and r[3] in neg)
        return prf(tp, fp, P)
    out = dict(findings=len(finds), unlabeled_hits=unlabeled,
               line=view(lambda r: True), **{"line-noX": view(lambda r: True, ("F",))},
               **{"line-prod": view(lambda r: not TEST_SCOPE.match(r[0]))},
               **{"line-prod-noUUID": view(lambda r: not TEST_SCOPE.match(r[0]) and r[:3] not in UUID_ONLY)})
    pos_files = {p for p, rows in labels.items() if any(g == "T" for *_, g in rows)}
    hit_pos = {r[0] for r in hit if r[3] == "T"}
    hit_neg = {r[0] for r in hit if r[0] not in pos_files}
    out["file"] = prf(len(hit_pos), len(hit_neg), len(pos_files))
    return out

def selftest(labels):
    oracle = [(p, s, s) for p, rows in labels.items() for s, e, g in rows if g == "T"]
    everything = [(p, s, s) for p, rows in labels.items() for s, e, g in rows]
    o, a, n = score(labels, oracle), score(labels, everything), score(labels, [])
    assert o["line"]["recall"] == 1 and o["line"]["precision"] == 1 and o["file"]["precision"] == 1, o
    P = sum(g == "T" for rows in labels.values() for *_, g in rows)
    # every negative is a FP, except one whose start line sits inside a T range
    shadowed = sum(1 for p, rows in labels.items() for s, e, g in rows if g != "T"
                   and any(s2 <= s <= e2 for s2, e2, g2 in rows if g2 == "T"))
    assert a["line"]["FP"] == len(everything) - P - shadowed and a["line"]["recall"] == 1, a
    assert n["line"]["TP"] == 0 and n["line"]["FN"] == P, n                          # nothing found: all FN
    assert score(labels, [("data/00000000/_/none.txt", 1, 1)])["unlabeled_hits"] == 1
    # a span hits every range it intersects: one finding over a whole file = all its lines
    p, rows = next((p, rows) for p, rows in labels.items() if len(rows) > 3)
    span = score({p: rows}, [(p, 1, 10**9)])
    assert span["line"]["TP"] + span["line"]["FP"] == len(rows) - sum(
        1 for s, e, g in rows if g != "T" and any(g2 == "T" for *_, g2 in rows)), span
    print("selftest ok")

if __name__ == "__main__":
    root, args = sys.argv[1], sys.argv[2:]
    labels = load_labels(root)
    if args == ["--selftest"]:
        selftest(labels); sys.exit()
    c = defaultdict(int)
    for rows in labels.values():
        for *_, g in rows: c[g] += 1
    print(f"labeled lines: T {c['T']}, F {c['F']}, X {c['X']}; files {len(labels)}")
    for tool, out in zip(args[::2], args[1::2]):
        print(json.dumps({tool: score(labels, findings(tool, out))}))
