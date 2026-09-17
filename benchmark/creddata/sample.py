"""Build a stratified CredData sample for one AI-mode Klarion run.

Unit: a labeled line hit by at least one Klarion candidate (score.py matching),
plus candidates on unlabeled lines. Strata: T-prod, T-test, N-prod, N-test
(N = F or X; test = CredData test-purpose scope dir), U (unlabeled candidate).
Every candidate hitting a sampled line goes to the model; every other candidate
in the shipped files is baselined, so the model sees only the sample.

usage: sample.py <creddata-root> <klarion-no-ai.json> <outdir> [seed]
writes outdir/data/... (files with a sampled candidate, same relative paths),
       outdir/baseline.json, outdir/sample.json
"""
import json, os, random, shutil, sys
from collections import defaultdict
import score

N = {"T-prod": 150, "T-test": 100, "N-prod": 150, "N-test": 75, "U": 100}
MAX_FILE = 8 << 20          # keep the shipped archive small; files above are not sampled

def main(root, klarion_json, outdir, seed=7):
    labels = score.load_labels(root)
    d = json.load(open(klarion_json))
    cands = (d.get("findings") or []) + (d.get("suppressed") or [])
    assert cands and all(c.get("fingerprint") for c in cands)
    hits = defaultdict(set)                     # stratum key -> fingerprints hitting it
    unit_stratum, unlabeled = {}, defaultdict(set)
    for c in cands:
        path = score.norm(c["file"])
        lo = c["line"]; hi = lo + max(c.get("occurrences") or 1, 1) - 1
        m = [(path, s, e, g) for s, e, g in labels.get(path, ()) if s <= hi and lo <= e]
        if any(x[3] == "T" for x in m):
            m = [x for x in m if x[3] == "T"]
        if not m:
            unlabeled[(path, None, None, c["fingerprint"])].add(c["fingerprint"]); continue
        for key in m:
            hits[key].add(c["fingerprint"])
            unit_stratum[key] = ("T" if key[3] == "T" else "N") + ("-test" if score.TEST_SCOPE.match(path) else "-prod")
    size = lambda p: os.path.getsize(os.path.join(root, p))   # unit key: (path, start, end, label|fp)
    pop = defaultdict(list)
    for key, st in unit_stratum.items():
        pop[st].append(key)
    for key in unlabeled:
        pop["U"].append(key)
    rng = random.Random(seed)
    sample, chosen = [], set()
    for st in N:
        eligible = sorted((k for k in pop[st] if size(k[0]) <= MAX_FILE), key=str)
        for k in rng.sample(eligible, min(N[st], len(eligible))):
            fps = sorted(unlabeled[k] if st == "U" else hits[k])
            sample.append(dict(stratum=st, file=k[0], start=k[1], end=k[2], fingerprints=fps,
                               uuid_only=k[:3] in score.UUID_ONLY))
            chosen.update(fps)
    files = sorted({s["file"] for s in sample})
    # every candidate in the shipped files that is not chosen goes in the baseline
    shipped = set(files)
    base = {c["fingerprint"]: dict(rule_id=c["rule_id"], file=c["file"], secret_redacted=c["secret_redacted"],
                                   accepted_at="2026-09-16T00:00:00Z")
            for c in cands if score.norm(c["file"]) in shipped and c["fingerprint"] not in chosen}
    to_model = [c for c in cands if c["fingerprint"] in chosen]
    if os.path.exists(outdir):
        shutil.rmtree(outdir)
    for f in files:
        dst = os.path.join(outdir, f); os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(os.path.join(root, f), dst)
    json.dump(dict(fingerprints=base), open(f"{outdir}/baseline.json", "w"), indent=1)
    meta = dict(seed=seed, sizes=N, max_file_bytes=MAX_FILE,
                population={st: len(pop[st]) for st in N},
                population_eligible={st: sum(size(k[0]) <= MAX_FILE for k in pop[st]) for st in N},
                population_T_prod_uuid_only=sum(k[:3] in score.UUID_ONLY for k in pop["T-prod"]),
                labeled_T_prod_nonuuid_lines=sum(g == "T" and not score.TEST_SCOPE.match(p) and (p, s, e) not in score.UUID_ONLY
                                                 for p, rows in labels.items() for s, e, g in rows),
                labeled_T_lines=sum(g == "T" for rows in labels.values() for *_, g in rows),
                labeled_T_prod_lines=sum(g == "T" and not score.TEST_SCOPE.match(p) for p, rows in labels.items() for *_, g in rows),
                expected_model_candidates=len(to_model), expected_fingerprints=len(chosen),
                files=len(files), sample=sample)
    json.dump(meta, open(f"{outdir}/sample.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in meta.items() if k != "sample"}, indent=1))

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]) if len(sys.argv) > 4 else 7)
