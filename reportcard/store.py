"""Where results live: one JSON snapshot per day, a small state file, and an event log."""
import glob
import json
import os
import tempfile
import time


class Store:
    def __init__(self, data_dir):
        self.dir = data_dir
        self.snap_dir = os.path.join(data_dir, "snapshots")

    def ensure(self):
        os.makedirs(self.snap_dir, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:
            pass

    # ---------- generic JSON files ----------
    def _path(self, name):
        return os.path.join(self.dir, name)

    def load(self, name, default=None):
        try:
            with open(self._path(name), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {} if default is None else default

    def save(self, name, data):
        self.ensure()
        self._atomic(self._path(name), data)

    def _atomic(self, path, data):
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, sort_keys=True)
        os.replace(tmp, path)

    # ---------- daily snapshots ----------
    def save_snapshot(self, snap):
        self.ensure()
        day = time.strftime("%Y-%m-%d", time.localtime(snap["time"]))
        self._atomic(os.path.join(self.snap_dir, day + ".json"), snap)
        self.prune()
        return day

    def snapshots(self, since):
        out = []
        for p in sorted(glob.glob(os.path.join(self.snap_dir, "*.json"))):
            try:
                with open(p, encoding="utf-8") as fh:
                    s = json.load(fh)
            except (OSError, ValueError):
                continue
            if s.get("time", 0) >= since:
                out.append(s)
        return out

    def prune(self, keep_days=90):
        limit = time.time() - keep_days * 86400
        for p in glob.glob(os.path.join(self.snap_dir, "*.json")):
            try:
                if os.path.getmtime(p) < limit:
                    os.remove(p)
            except OSError:
                pass

    # ---------- events (alerts sent, outages) ----------
    def add_event(self, event):
        self.ensure()
        event.setdefault("time", time.time())
        with open(self._path("events.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, sort_keys=True) + "\n")

    def events(self, since):
        out = []
        try:
            with open(self._path("events.jsonl"), encoding="utf-8") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if e.get("time", 0) >= since:
                        out.append(e)
        except OSError:
            pass
        return out
