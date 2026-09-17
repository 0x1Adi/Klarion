"""Rebuild CredData's data/ without full repo downloads.

Per repo: shallow, blobless fetch of the pinned commit; list the tree; check out
only files whose sha256(path)[:8] is a FileID in meta. Then CredData's own
move_files and obfuscate_creds produce the same data/ as download_data.py.
"""
import hashlib, json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
import download_data as dd
from meta_row import read_meta

def git(d, *args, timeout=600):
    return subprocess.run(["git", *args], cwd=d, check=True, capture_output=True, text=True, timeout=timeout)

def fetch(item):
    repo_id, url = item
    sha = repo_id[:40]
    meta_path = f"meta/{dd.get_new_repo_id(repo_id)}.csv"
    if not os.path.exists(meta_path):
        return repo_id, "no-meta", 0, 0
    rows = read_meta(meta_path)
    if not rows:
        return repo_id, "empty-meta", 0, 0
    want = {r.FileID for r in rows}
    d = os.path.realpath(f"{dd.TMP_DIR}/{repo_id}")
    os.makedirs(d, exist_ok=True)
    if not os.path.exists(f"{d}/.git"):
        git(d, "init", "-q")
        for kv in (("core.repositoryformatversion", "1"), ("extensions.partialClone", "origin"),
                   ("remote.origin.url", url), ("remote.origin.promisor", "true"),
                   ("remote.origin.partialclonefilter", "blob:none")):
            git(d, "config", *kv)
    git(d, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", sha)
    names = git(d, "ls-tree", "-r", "--name-only", "-z", sha).stdout.split("\0")
    paths = [p for p in names if p and not p.endswith(".xml")
             and hashlib.sha256(p.encode()).hexdigest()[:8] in want]
    for i in range(0, len(paths), 200):
        git(d, "checkout", "-q", sha, "--", *paths[i:i + 200])
    return repo_id, "ok", len(paths), len(want)

if __name__ == "__main__":
    snapshot = json.load(open("snapshot.json"))
    os.makedirs(dd.TMP_DIR, exist_ok=True)
    ok, t0 = {}, time.time()
    with ThreadPoolExecutor(max_workers=int(sys.argv[1]) if len(sys.argv) > 1 else 8) as ex:
        futs = {ex.submit(fetch, it): it for it in snapshot.items()}
        for n, f in enumerate(as_completed(futs), 1):
            repo_id, url = futs[f]
            try:
                rid, status, got, want = f.result()
                if status == "ok":
                    ok[repo_id] = url
                print(f"[{n}/{len(snapshot)} {time.time()-t0:.0f}s] {status} {got}/{want} {url}", flush=True)
            except Exception as e:
                err = getattr(e, "stderr", "") or str(e)
                print(f"[{n}/{len(snapshot)}] FAIL {url}: {str(err)[-200:]}", flush=True)
    json.dump(ok, open("fetched.json", "w"))
    print(f"FETCHED {len(ok)} repos in {time.time()-t0:.0f}s", flush=True)
