#!/bin/bash
#
# Summarize inference results into CSV tables (see tools/analysis/summarize.py
# and docs/reproducing-the-paper.md).
#
# Usage: ./summarize-results.sh [results-dir] [--no-bdist]
#
#   results-dir defaults to results/. Every inference folder below it is read,
#   and the tables are written to <results-dir>/analysis/. --no-bdist skips the
#   (slower) distinguishing bound computation.
#
# Needs the tls-test-bed/automaton2dot image (make containers/tools/automaton2dot.docker).

set -e

TARGET="${1:-results}"
case "$TARGET" in --*) TARGET=results ;; *) shift || true ;; esac
[ -d "$TARGET" ] || { echo "Error: $TARGET is not a directory" >&2; exit 1; }
TARGET="$(cd "$TARGET" && pwd)"

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"

docker run --rm \
           --user "$(id -u):$(id -g)" \
           -e PYTHONWARNINGS=ignore \
           -v "$TARGET":/data \
           -v "$SCRIPTDIR/tools/analysis":/analysis:ro \
           tls-test-bed/automaton2dot python /analysis/summarize.py /data "$@"
