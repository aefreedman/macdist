#!/usr/bin/env python3
"""Internal op-run worker: scrub resolved credentials before any Butler output escapes."""

import argparse
import os
from pathlib import Path
import sys

# The isolated op environment intentionally excludes inherited Python settings.
# Do not leave compiled utility artifacts in the source tree.
sys.dont_write_bytecode = True

from . import publish


def run(argv, source=None, timeout=3600):
    source = os.environ if source is None else source
    key = source.get("BUTLER_API_KEY", "")
    token = source.get("OP_SERVICE_ACCOUNT_TOKEN", "")
    if (not key or key.startswith("op://") or any(c.isspace() for c in key)
            or not token or any(c.isspace() for c in token)
            or not 1 <= timeout <= 14400 or len(argv) < 2 or not Path(argv[0]).is_absolute()
            or argv[1] not in ("push", "status")):
        print("Worker rejected missing resolved credentials or unsupported operation.", flush=True)
        return 1
    env = publish.base_environment(source)
    # Butler receives neither the service-account token nor other tools' secrets.
    env["BUTLER_API_KEY"] = key
    # Disable access to Butler's normal saved personal login, even if authentication fails.
    command = [argv[0], "--identity", "/dev/null", *argv[1:]]
    try:
        return publish.stream_process(command, env, lambda line: print(line, flush=True),
                                      secrets=(key, token), timeout=timeout, own_group=False,
                                      terminal=argv[1] == "push")
    except (OSError, publish.PublishingError, KeyboardInterrupt):
        print("Butler worker failed or was interrupted; no login or retry attempted.", flush=True)
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("butler")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    sys.exit(run([args.butler, *args.arguments], timeout=args.timeout))
