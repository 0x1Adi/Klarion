"""Check and score the CredData sample run. Python 3.8+, stdlib only.

  python3 score_ai.py check noai.json   # before the AI run: model sees only the sample?
  python3 score_ai.py score ai.json     # after: keep rates, recall, precision
"""
import json, math, random, sys
from collections import Counter, defaultdict

S = json.load(open("sample.json"))

def rows(path):
    d = json.load(open(path))
    return d.get("findings") or [], d.get("suppressed") or []

def judged(rs):
    return [r for r in rs if (r.get("verdict") or {}).get("status")]

def check(path):
    kept, supp = rows(path)
    chosen = {f for u in S["sample"] for f in u["fingerprints"]}
    got = {r["fingerprint"] for r in judged(kept + supp)}
    extra, missing = got - chosen, chosen - got
    print(f"candidates {len(kept) + len(supp)}, to model {len(got)}, expected {len(chosen)}")
    if extra or missing:
        sys.exit(f"MISMATCH: {len(extra)} extra, {len(missing)} missing -- wrong binary, config or baseline path; do not run AI")
    print("OK: the AI run will adjudicate exactly the sample")

def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))

def score(path):
    kept, supp = rows(path)
    chosen = {f for u in S["sample"] for f in u["fingerprints"]}
    verdicts = {r["fingerprint"] for r in judged(kept + supp)}
    if verdicts != chosen:
        sys.exit(f"MISMATCH: {len(verdicts - chosen)} extra, {len(chosen - verdicts)} unjudged -- run failed or wrong baseline")
    spans = defaultdict(list)                   # fingerprint -> [(lo, hi, status, reason, rule)]
    for r, active in [(r, True) for r in kept] + [(r, False) for r in supp]:
        if r["fingerprint"] in chosen:
            lo = r["line"]; hi = lo + max(r.get("occurrences") or 1, 1) - 1
            v = r.get("verdict") or {}
            spans[r["fingerprint"]].append((lo, hi, active, v.get("status"), v.get("reason", ""), r["rule_id"]))
    out = defaultdict(list); status = defaultdict(Counter); missed = []
    for u in S["sample"]:
        hit = [s for f in u["fingerprints"] for s in spans[f]
               if u["start"] is None or (s[0] <= u["end"] and u["start"] <= s[1])]
        assert hit, u                             # every sampled unit has a judged candidate
        k = any(s[2] for s in hit)
        out[u["stratum"]].append(int(k))
        if u["stratum"] == "T-prod" and not u.get("uuid_only"):
            out["T-prod-nonuuid"].append(int(k))
        status[u["stratum"]][max((s[3] for s in hit), key=["false_positive", "uncertain", "secret"].index)] += 1
        if u["stratum"] == "T-prod" and not k:
            missed.append((u["file"], u["start"], hit[0][5], hit[0][4]))
    pop = S["population"]
    print("keep rate per stratum (95% Wilson CI); verdicts: best per unit")
    for st in S["sizes"]:   # T-prod-nonuuid is a subset of T-prod, not printed
        n, k = len(out[st]), sum(out[st]); lo, hi = wilson(k, n)   # n > 0: every stratum is sampled
        print(f"  {st:7s} n={n:3d} kept={k:3d} rate={k / n:.2f} [{lo:.2f}, {hi:.2f}]  pop={pop[st]}  {dict(status[st])}")
    def est(o):
        r = {st: sum(o[st]) / len(o[st]) for st in o}
        tp_all = pop["T-prod"] * r["T-prod"] + pop["T-test"] * r["T-test"]
        fp_all = pop["N-prod"] * r["N-prod"] + pop["N-test"] * r["N-test"]
        tp_prod, fp_prod = pop["T-prod"] * r["T-prod"], pop["N-prod"] * r["N-prod"]
        # CredData labels UUIDs T by category; the ones in prod are GUIDs, badge ids, ARNs
        tp_nu = (pop["T-prod"] - S["population_T_prod_uuid_only"]) * r.get("T-prod-nonuuid", r["T-prod"])
        ratio = lambda a, b: a / b if b else 0.0
        return dict(recall_all=tp_all / S["labeled_T_lines"], recall_prod=tp_prod / S["labeled_T_prod_lines"],
                    recall_prod_nouuid=tp_nu / S["labeled_T_prod_nonuuid_lines"],
                    precision_all=ratio(tp_all, tp_all + fp_all), precision_prod=ratio(tp_prod, tp_prod + fp_prod),
                    precision_prod_nouuid=ratio(tp_nu, tp_nu + fp_prod),
                    unlabeled_kept=pop["U"] * r["U"])
    point = est(out)
    rng = random.Random(1); boots = defaultdict(list)
    for _ in range(4000):
        b = est({st: [rng.choice(v) for _ in v] for st, v in out.items()})
        for m, x in b.items():
            boots[m].append(x)
    print("estimates for Klarion + AI over all CredData lines Klarion flags (95% stratified bootstrap)")
    for m, x in point.items():
        v = sorted(boots[m]); lo, hi = v[int(0.025 * len(v))], v[int(0.975 * len(v)) - 1]
        print(f"  {m:22s} {x:.3f} [{lo:.3f}, {hi:.3f}]" if m != "unlabeled_kept" else f"  {m:22s} {x:.0f} [{lo:.0f}, {hi:.0f}] extra findings on lines CredData never labeled")
    print(f"T-prod units the model suppressed: {len(missed)} (first 15: file, line, rule, reason)")
    for m in missed[:15]:
        print("  ", *m)

if __name__ == "__main__":
    {"check": check, "score": score}[sys.argv[1]](sys.argv[2])
