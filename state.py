#!/usr/bin/env python3
"""
Shared memory for the scheduled CyberPulse watcher runs (state/state.json).

  python3 state.py filter  < candidates.json   # prints only articles not seen before
  python3 state.py add     < items.json        # marks articles seen (keeps priority/advisory info)
  python3 state.py next-id DDMMYYYY            # reserves and prints the next advisory ID for that date
  python3 state.py set-id  TA13112026.03       # records an ID issued by hand, so numbering continues after it
  python3 state.py since   HOURS               # prints items logged in the last HOURS hours (for the summary)

Article items are JSON objects: {"url": ..., "title": ..., "source": ..., "priority": ..., "type": ...,
"advisory_id": ... (optional), "note": ...}. Matching is by URL and by normalised title, so the same story
from a second site is still seen as new only if its title differs.
After any change: git add state && git commit && git push (see STYLE_GUIDE / task prompt).
"""
import datetime as dt, json, os, re, sys

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state", "state.json")
IST = dt.timezone(dt.timedelta(hours=5, minutes=30))


def load():
    if os.path.exists(PATH):
        return json.load(open(PATH))
    return {"seen": [], "ids": {}}


def save(s):
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    cutoff = (dt.datetime.now(IST) - dt.timedelta(days=21)).isoformat()
    s["seen"] = [x for x in s["seen"] if x.get("logged_at", "") >= cutoff]
    json.dump(s, open(PATH, "w"), indent=1, ensure_ascii=False)


def norm(t):
    return re.sub(r"[^a-z0-9]+", " ", (t or "").lower()).strip()


def main():
    cmd = sys.argv[1]
    s = load()
    urls = {x.get("url") for x in s["seen"]}
    titles = {norm(x.get("title")) for x in s["seen"]}
    if cmd == "filter":
        items = json.load(sys.stdin)
        new = [i for i in items if i.get("url") not in urls and norm(i.get("title")) not in titles]
        print(json.dumps(new, indent=1, ensure_ascii=False))
    elif cmd == "add":
        now = dt.datetime.now(IST).isoformat(timespec="minutes")
        for i in json.load(sys.stdin):
            i.setdefault("logged_at", now)
            if i.get("url") in urls:
                for x in s["seen"]:
                    if x.get("url") == i.get("url"):
                        x.update({k: v for k, v in i.items() if k != "logged_at"})
            else:
                s["seen"].append(i)
        save(s)
        print("ok")
    elif cmd == "next-id":
        d = sys.argv[2]
        n = s["ids"].get(d, 0) + 1
        s["ids"][d] = n
        save(s)
        print(f"TA{d}.{n:02d}")
    elif cmd == "set-id":
        m = re.fullmatch(r"TA(\d{8})\.(\d{2})", sys.argv[2])
        d, n = m.group(1), int(m.group(2))
        s["ids"][d] = max(s["ids"].get(d, 0), n)
        save(s)
        print(f"next for {d}: TA{d}.{s['ids'][d] + 1:02d}")
    elif cmd == "since":
        cutoff = (dt.datetime.now(IST) - dt.timedelta(hours=float(sys.argv[2]))).isoformat()
        print(json.dumps([x for x in s["seen"] if x.get("logged_at", "") >= cutoff], indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
