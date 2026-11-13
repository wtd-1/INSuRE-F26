#!/bin/sh
# Usage: /render.sh <scenario> <file.automaton>
#   scenario: e.g. server.tls13, server.tls12, client.tls13 (see automaton2dot.py)
# Writes <file>.dot and <file>.svg next to the automaton file.

set -e

SCENARIO="$1"
AUTOMATON="$2"
BASE="${AUTOMATON%.automaton}"

cd /opt/pylstar-tls-v0.5/src
# scapy/cryptography deprecation warnings are noise here.
export PYTHONWARNINGS=ignore

if python -c 'import sys, automaton2dot; sys.exit(sys.argv[1] not in automaton2dot.mappings)' "$SCENARIO"; then
    python automaton2dot.py "$SCENARIO" "$AUTOMATON" "$BASE.dot"
else
    # automaton2dot.py has no message abbreviations (and so no colours or
    # security checks) for this scenario, e.g. client.freak: draw it as is.
    echo "No automaton2dot.py rules for $SCENARIO: drawing the plain state machine."
    python -c 'import sys; from automata.automata import load_automaton_from_file as load
open(sys.argv[2], "w").write(load(sys.argv[1]).dot())' "$AUTOMATON" "$BASE.dot"
fi
dot -Tsvg "$BASE.dot" -o "$BASE.svg"
