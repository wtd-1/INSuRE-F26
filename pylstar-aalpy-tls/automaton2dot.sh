#!/bin/bash
#
# Render an inferred state machine as a graph, with pylstar-tls's automaton2dot.py.
#
# Usage: ./automaton2dot.sh <results-dir | file.automaton> [scenario]
#
#   With a results directory, final.automaton is rendered to final.dot and final.svg
#   in that directory. With a .automaton file, <file>.dot and <file>.svg are written
#   next to it.
#
#   scenario is e.g. server.tls13, server.tls13-auth (mutual authentication) or
#   client.tls13. It can be left out for directories created by infer-*.sh or
#   run-experiments.sh (<kind>--<stack>--<scenario>--...).

set -e

[ -n "$1" ] || { echo "Usage: $0 <results-dir | file.automaton> [scenario]" >&2; exit 1; }

# Resolve the target before changing directory.
TARGET="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ -d "$TARGET" ]; then
    DIR="$TARGET"
    FILE=final.automaton
else
    DIR="$(dirname "$TARGET")"
    FILE="$(basename "$TARGET")"
fi
[ -f "$DIR/$FILE" ] || { echo "Error: $DIR/$FILE not found" >&2; exit 1; }

SCENARIO="$2"
if [ -z "$SCENARIO" ]; then
    # results/<kind>--<stack>--<scenario>--<inferer>--<timestamp>
    IFS='|' read -r KIND _ VOCABULARY _ <<< "$(basename "$DIR" | sed 's/--/|/g')"
    case "$KIND" in
        server)   SCENARIO="server.$VOCABULARY" ;;
        srv-auth) case "$VOCABULARY" in
                      tls1[0-3]) SCENARIO="server.$VOCABULARY-auth" ;;  # enables the client-auth bypass check
                      *)         SCENARIO="server.$VOCABULARY" ;;
                  esac ;;
        client)   SCENARIO="client.$VOCABULARY" ;;
        *) echo "Error: cannot guess the scenario from \"$(basename "$DIR")\"; pass it as a second argument (e.g. server.tls13)" >&2
           exit 1 ;;
    esac
fi

SCRIPTDIR="$(dirname "$0")"
cd "$SCRIPTDIR"

docker run --rm \
           -v "$DIR":/results \
           tls-test-bed/automaton2dot /render.sh "$SCENARIO" "/results/$FILE"

echo "Graph written to $DIR/${FILE%.automaton}.svg"
