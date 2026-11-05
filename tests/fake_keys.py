"""Stand-in for the Keysrs `keys` CLI, for offline tests.

Behaviour comes from $HOME/.fake_keys/scenario.json:
    {"token": {"exit": 0, "stdout": "...", "stderr": "", "sleep": 0},
     "issue": {...}}
Every call is appended to $HOME/.fake_keys/calls.jsonl with argv and env.
It never touches the Keychain, the network or the real Keysrs app.
"""

import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    state = Path(os.environ.get("HOME", "/nonexistent")) / ".fake_keys"
    state.mkdir(parents=True, exist_ok=True)
    argv = sys.argv[1:]
    with open(state / "calls.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"argv": argv, "env": dict(os.environ)}) + "\n")

    if argv[:2] == ["client", "token"]:
        cmd = "token"
    elif argv[:2] == ["client", "issue"]:
        cmd = "issue"
    else:
        print("fake keys: unsupported command", file=sys.stderr)
        return 64

    try:
        scenario = json.loads((state / "scenario.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        scenario = {}
    step = scenario.get(cmd)
    if not isinstance(step, dict):
        print(f"fake keys: no scenario for {cmd}", file=sys.stderr)
        return 1
    if step.get("sleep"):
        time.sleep(float(step["sleep"]))
    if step.get("stderr"):
        sys.stderr.write(step["stderr"])
    if step.get("stdout"):
        sys.stdout.write(step["stdout"])
    return int(step.get("exit", 0))


if __name__ == "__main__":
    sys.exit(main())
