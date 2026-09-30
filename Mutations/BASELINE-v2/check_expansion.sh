#!/bin/zsh
# R1 check: the instrumented BASELINE-v1 must macro-expand to exactly the same
# protocols and goals as the plain fixed model in reference_uninstrumented/.
# Only the herald and the "All input read from" comment may differ.
set -e
export PATH=$HOME/.local/bin:$PATH
here=${0:A:h}
tmp=$(mktemp -d)
(cd $here && cpsa4 -e -o $tmp/instrumented.txt tls13_baseline.scm)
(cd $here/reference_uninstrumented && cpsa4 -e -o $tmp/plain.txt tls13_fixed_plain.scm)
strip() { grep -v -e '^(comment "All input read from' $1 | python3 -c '
import sys; t = sys.stdin.read(); i = t.index("(herald"); j = t.index("\n\n", i); print(t[:i] + t[j:])'; }
if diff <(strip $tmp/instrumented.txt) <(strip $tmp/plain.txt); then
  echo "R1 CHECK PASSED: expansions identical ($(grep -c '^(defprotocol' $tmp/plain.txt) protocols, $(grep -c '^(defgoal' $tmp/plain.txt) goals)"
else
  echo "R1 CHECK FAILED"; exit 1
fi
