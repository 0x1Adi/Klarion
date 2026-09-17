"""Break down CredData true lines a scanner misses, by category and extension.
usage: misses.py <creddata-root> <tool> <output> [sample-category]"""
import csv, glob, os, sys, random, collections
import score
root, tool, out = sys.argv[1:4]
labels = collections.defaultdict(list)   # key -> rows
for f in glob.glob(f"{root}/meta/*.csv"):
    for r in csv.DictReader(open(f, newline="")):
        labels[(r["FilePath"], int(r["LineStart"]), int(r["LineEnd"]))].append(r)
hits = collections.defaultdict(set)
for path, lo, hi in score.findings(tool, out):
    hits[path].add((lo, hi))
cat_all, cat_hit, ext_all, ext_hit = (collections.Counter() for _ in range(4))
missed = collections.defaultdict(list)
for (path, s, e), rows in labels.items():
    t = [r for r in rows if r["GroundTruth"] == "T"]
    if not t or (os.environ.get("PROD") and score.TEST_SCOPE.match(path)): continue
    cat = t[0]["Category"].split(":")[0]; ext = os.path.splitext(path)[1].lower() or "(none)"
    h = any(s <= hi and lo <= e for lo, hi in hits.get(path, ()))
    cat_all[cat] += 1; ext_all[ext] += 1
    if h: cat_hit[cat] += 1; ext_hit[ext] += 1
    else: missed[cat].append((path, s, e, t[0]))
def table(all_, hit, n=22):
    for k, v in all_.most_common(n):
        print(f"  {k:28s} {hit[k]:6d}/{v:<6d} recall {hit[k]/v:.2f}  missed {v-hit[k]}")
print("by category"); table(cat_all, cat_hit)
print("by extension"); table(ext_all, ext_hit)
if len(sys.argv) > 4:
    random.seed(1)
    for path, s, e, r in random.sample(missed[sys.argv[4]], min(25, len(missed[sys.argv[4]]))):
        lines = open(f"{root}/{path}", errors="replace").read().split("\n")[s-1:e]
        print(f"--- {path}:{s} [{r['Category']}]", " | ".join(x.strip()[:160] for x in lines)[:220])
if os.environ.get("CONC"):
    per = collections.Counter(p for c in missed.values() for p, *_ in c)
    tot = sum(per.values()); run = 0
    print("missed lines", tot, "in", len(per), "files")
    for i, (p, n) in enumerate(per.most_common(15), 1):
        run += n; cats = collections.Counter(r["Category"] for c in missed.values() for pp, s, e, r in c if pp == p)
        print(f"  {n:5d} cum {run/tot:.2f} {p} {dict(cats.most_common(2))}")
