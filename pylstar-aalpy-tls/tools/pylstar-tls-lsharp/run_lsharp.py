#!/usr/bin/env python
"""Run pylstar-tls's unmodified infer_server / infer_client with AALpy's L#.

Usage: run_lsharp.py {server|client} [infer_server.py / infer_client.py arguments...]

The original main() is called as is; only the module's LSTAR name is replaced
by LSharpLearner, which has the same interface.
"""

import importlib
import importlib.metadata
import os
import sys

from lsharp_learner import LSharpLearner

PYLSTAR_TLS_SRC = os.environ.get("PYLSTAR_TLS_SRC", "/root/pylstar-tls/src")


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("server", "client"):
        sys.exit("usage: run_lsharp.py {server|client} [arguments...]")
    role = sys.argv[1]

    sys.path.insert(0, PYLSTAR_TLS_SRC)
    module = importlib.import_module(f"infer_{role}")
    module.LSTAR = LSharpLearner

    # main() looks for scenarios/ next to sys.argv[0], so make the command line
    # look like a direct call of the original script.
    sys.argv = [os.path.join(PYLSTAR_TLS_SRC, f"infer_{role}.py")] + sys.argv[2:]

    print(f"learner: L# (AALpy {importlib.metadata.version('aalpy')})")
    sys.stdout.flush()
    module.main()

    info = LSharpLearner.last_info
    if info:
        print(
            f"L# learning rounds: {info['learning_rounds']}, "
            f"learning time: {info['learning_time']}s, "
            f"equivalence query time: {info['eq_oracle_time']}s"
        )


if __name__ == "__main__":
    main()
