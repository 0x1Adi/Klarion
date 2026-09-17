import json, sys, time
import fetch_partial as fp
snap = json.load(open("snapshot.json")); ok = json.load(open("fetched.json"))
todo = [(k, v) for k, v in snap.items() if k not in ok]
print("retrying", len(todo), flush=True)
for item in todo:
    for attempt in range(3):
        try:
            rid, status, got, want = fp.fetch(item)
            print(status, got, want, item[1], flush=True)
            if status == "ok": ok[rid] = item[1]
            break
        except Exception as e:
            print("attempt", attempt, "failed", item[1], str(getattr(e, "stderr", "") or e)[-150:], flush=True)
            time.sleep(5)
json.dump(ok, open("fetched.json", "w")); print("FETCHED", len(ok), flush=True)
