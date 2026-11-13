#!/bin/bash
#
# Batch runner for state machine inference experiments.
# See docs/reproducing-the-paper.md for the full guide.
#
# Usage: ./run-experiments.sh [options] <experiments.tsv>...
#
# Each non-comment line of an experiments file is:
#     kind  image  tls_version  scenario  [extra pylstar-tls arguments...]
# kind is server, srv-auth or client (-> infer-server.sh, infer-srv-auth.sh,
# infer-client.sh); image is e.g. wolfssl:v4.4.0-stable (the tls-test-bed/
# prefix is optional). Fields are separated by tabs or spaces.
#
# Options:
#   --campaign NAME     results go to results/NAME/ (default: campaign-<date>)
#   --inferers LIST     comma-separated inferer images, without tls-test-bed/
#                       (default: pylstar-tls,pylstar-tls-lsharp, i.e. L* and L#)
#   --repeat R          run every experiment R times (default: 1)
#   --jobs N            run N inferences in parallel (default: 1)
#   --eq METHOD         equivalence method passed as -E unless a line has its
#                       own -E, e.g. RW:10000:0.1 or BDist:3 (default: RW:10000:0.1)
#   --max-time T        stop a run after T (sleep syntax: 3600, 90m, 4h; default: 4h)
#   --build             build missing stack images with make before running them
#   --prune             remove each stack image once all its runs are done
#   --skip-done         skip runs whose result folder already has final.automaton
#   --dry-run           print the runs and commands without executing them
#
# Per run, results/NAME/<run>/ holds pylstar-tls's usual files plus:
#   console.log   everything the inference printed (live progress, L# timing)
#   run.tsv       metadata: command, start/end time, wall time, exit status, load
# results/NAME/runner.log has one START/END line per run.

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPTDIR"

# ---------------------------------------------------------------------------
# Single run (internal: called through xargs for parallelism)
# ---------------------------------------------------------------------------

log_line() {
    echo "$(date '+%Y-%m-%dT%H:%M:%S') $*" >> "$CAMPAIGN_DIR/runner.log"
}

image_target() {  # tls-test-bed/<family>:<tag> -> containers/<family>/<tag>.docker
    local rest="${1#tls-test-bed/}"
    echo "containers/${rest%%:*}/${rest#*:}.docker"
}

ensure_image() {
    local image="$1" safe="$2"
    docker image inspect "$image" >/dev/null 2>&1 && return 0
    if [ "$BUILD" != 1 ]; then
        echo "image $image is missing (use --build)" >&2
        return 1
    fi
    local target
    target="$(image_target "$image")"
    # One build per image, even with several parallel runs needing it.
    (
        flock 9
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            rm -f "$target"   # stale marker from a pruned image
            log_line "BUILD $image"
            make "$target" > "$CAMPAIGN_DIR/.runner/build-$safe.log" 2>&1
        fi
    ) 9> "$CAMPAIGN_DIR/.runner/build-$safe.lock"
}

release_image() {  # decrement the image's pending run count; prune at zero
    local image="$1" safe="$2"
    (
        flock 9
        local count
        count=$(( $(cat "$CAMPAIGN_DIR/.runner/pending-$safe") - 1 ))
        echo "$count" > "$CAMPAIGN_DIR/.runner/pending-$safe"
        if [ "$count" -le 0 ] && [ "$PRUNE" = 1 ]; then
            docker image rm "$image" >/dev/null 2>&1 && log_line "PRUNE $image" || true
            rm -f "$(image_target "$image")"
        fi
    ) 9> "$CAMPAIGN_DIR/.runner/pending-$safe.lock"
}

run_one() {
    local kind image version scenario extra inferer repeat name safe
    IFS=$'\x1f' read -r kind image version scenario extra inferer repeat name safe <<< "$1"
    local outdir="$CAMPAIGN_DIR/$name"

    if [ "$SKIP_DONE" = 1 ] && [ -f "$outdir/final.automaton" ]; then
        log_line "SKIP  $name (already done)"
        release_image "$image" "$safe"
        return 0
    fi

    local script
    case "$kind" in
        server)   script=./infer-server.sh ;;
        srv-auth) script=./infer-srv-auth.sh ;;
        client)   script=./infer-client.sh ;;
    esac

    # shellcheck disable=SC2206
    local args=($extra)
    case " $extra " in
        *" -E "*|*" --eq-method "*) ;;
        *) args+=(-E "$EQ") ;;
    esac

    rm -rf "$outdir"
    mkdir -p "$outdir"

    if ! ensure_image "$image" "$safe"; then
        log_line "END   $name status=build-failed"
        printf 'status\tbuild-failed\n' > "$outdir/run.tsv"
        release_image "$image" "$safe"
        return 0
    fi

    local start end rc status load_start load_end
    load_start="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo -)"
    start="$(date +%s.%N)"
    log_line "START $name"

    INFERER_IMAGE="tls-test-bed/$inferer" RESULTS_DIR="$SCRIPTDIR/$outdir" \
        "$script" "$image" "$version" "$scenario" "${args[@]}" > "$outdir/console.log" 2>&1 &
    local pid=$!
    ( sleep "$MAX_TIME" && kill -TERM "$pid" ) 2>/dev/null &
    local watchdog=$!
    rc=0
    wait "$pid" || rc=$?
    pkill -P "$watchdog" 2>/dev/null || true   # its sleep
    kill "$watchdog" 2>/dev/null || true
    wait "$watchdog" 2>/dev/null || true

    # infer-*.sh name their containers tls-{server,client,inferer}-<pid>;
    # make sure none survives a timeout or a crash.
    docker ps --format '{{.Names}}' | grep -E "^tls-(server|client|inferer)-$pid\$" \
        | xargs -r docker kill >/dev/null 2>&1 || true

    end="$(date +%s.%N)"
    load_end="$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo -)"
    if [ "$rc" = 0 ] && [ -f "$outdir/final.automaton" ]; then
        status=ok
    elif [ "$rc" = 143 ]; then
        status=timeout
    else
        status=failed
    fi

    {
        printf 'campaign\t%s\n' "$CAMPAIGN"
        printf 'kind\t%s\n' "$kind"
        printf 'image\t%s\n' "$image"
        printf 'tls_version\t%s\n' "$version"
        printf 'scenario\t%s\n' "$scenario"
        printf 'extra_args\t%s\n' "$extra"
        printf 'eq_method\t%s\n' "$EQ"
        printf 'inferer\t%s\n' "$inferer"
        printf 'repeat\t%s\n' "$repeat"
        printf 'jobs\t%s\n' "$JOBS"
        printf 'start_epoch\t%s\n' "$start"
        printf 'end_epoch\t%s\n' "$end"
        printf 'wall_seconds\t%s\n' "$(awk "BEGIN {printf \"%.1f\", $end - $start}")"
        printf 'exit_code\t%s\n' "$rc"
        printf 'status\t%s\n' "$status"
        printf 'loadavg_start\t%s\n' "$load_start"
        printf 'loadavg_end\t%s\n' "$load_end"
        printf 'host\t%s\n' "$(hostname)"
        printf 'command\tINFERER_IMAGE=tls-test-bed/%s %s %s %s %s %s\n' "$inferer" "$script" "$image" "$version" "$scenario" "${args[*]}"
    } > "$outdir/run.tsv"

    log_line "END   $name status=$status wall=$(awk "BEGIN {printf \"%.0f\", $end - $start}")s"
    release_image "$image" "$safe"
}

if [ "$1" = "--internal-run" ]; then
    run_one "$2"
    exit 0
fi

# ---------------------------------------------------------------------------
# Main: parse options, expand experiments into runs, execute them
# ---------------------------------------------------------------------------

usage() {
    sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

CAMPAIGN="campaign-$(date +%Y%m%d-%H%M%S)"
INFERERS="pylstar-tls,pylstar-tls-lsharp"
REPEAT=1
JOBS=1
EQ="RW:10000:0.1"
MAX_TIME=4h
BUILD=0
PRUNE=0
SKIP_DONE=0
DRY_RUN=0
FILES=()

while [ $# -gt 0 ]; do
    case "$1" in
        --campaign)  CAMPAIGN="$2"; shift 2 ;;
        --inferers)  INFERERS="$2"; shift 2 ;;
        --repeat)    REPEAT="$2"; shift 2 ;;
        --jobs)      JOBS="$2"; shift 2 ;;
        --eq)        EQ="$2"; shift 2 ;;
        --max-time)  MAX_TIME="$2"; shift 2 ;;
        --build)     BUILD=1; shift ;;
        --prune)     PRUNE=1; shift ;;
        --skip-done) SKIP_DONE=1; shift ;;
        --dry-run)   DRY_RUN=1; shift ;;
        -h|--help)   usage 0 ;;
        -*)          echo "Unknown option: $1" >&2; usage ;;
        *)           FILES+=("$1"); shift ;;
    esac
done
[ ${#FILES[@]} -gt 0 ] || usage

CAMPAIGN_DIR="results/$CAMPAIGN"
export CAMPAIGN CAMPAIGN_DIR EQ MAX_TIME BUILD PRUNE SKIP_DONE JOBS SCRIPTDIR

slug() {  # make a string safe for a folder name
    # printf, not echo: echo would swallow arguments such as -E
    printf '%s\n' "$*" | sed -e 's/^-*//' -e 's/[[:space:]]\{1,\}/_/g' -e 's/[^A-Za-z0-9._=-]//g' -e 's/--*/-/g'
}

# Expand experiments x repeats x inferers into run lines (fields separated by \x1f, which unlike tabs never collapse),
# grouped by stack image (so --prune can free disk space early).
RUNS="$(mktemp)"
trap 'rm -f "$RUNS" "$RUNS.sorted"' EXIT
IFS=',' read -r -a INFERER_LIST <<< "$INFERERS"
for file in "${FILES[@]}"; do
    [ -f "$file" ] || { echo "No such file: $file" >&2; exit 1; }
    while read -r kind image version scenario extra; do
        case "$kind" in ''|'#'*) continue ;; esac
        case "$kind" in
            server|srv-auth|client) ;;
            *) echo "Invalid kind \"$kind\" in $file" >&2; exit 1 ;;
        esac
        [ -n "$scenario" ] || { echo "Incomplete line in $file: $kind $image $version" >&2; exit 1; }
        extra="${extra%%#*}"                       # allow trailing comments
        extra="${extra#"${extra%%[![:space:]]*}"}"  # trim (in bash: echo/xargs would eat -E)
        extra="${extra%"${extra##*[![:space:]]}"}"
        image="tls-test-bed/${image#tls-test-bed/}"
        stack="${image#tls-test-bed/}"
        stack="${stack//:/_}"
        safe="$(slug "$stack")"
        extra_slug="$(slug "$extra")"
        for r in $(seq 1 "$REPEAT"); do
            for inferer in "${INFERER_LIST[@]}"; do
                name="$kind--$stack--$scenario--v$version${extra_slug:+--$extra_slug}--$inferer--r$r"
                printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\n' \
                    "$kind" "$image" "$version" "$scenario" "$extra" "$inferer" "$r" "$name" "$safe"
            done
        done
    done < "$file"
done > "$RUNS"
# Drop duplicates (the same experiment listed twice would share a folder).
N_DUPLICATES=$(cut -d$'\x1f' -f8 "$RUNS" | sort | uniq -d | wc -l)
[ "$N_DUPLICATES" = 0 ] || echo "Note: $N_DUPLICATES duplicate run(s) listed more than once; each is run once."
awk -F'\037' '!seen[$8]++' "$RUNS" | sort -s -t $'\x1f' -k2,2 > "$RUNS.sorted"

N_RUNS=$(wc -l < "$RUNS.sorted")
N_IMAGES=$(cut -d$'\x1f' -f2 "$RUNS.sorted" | sort -u | wc -l)
echo "Campaign $CAMPAIGN: $N_RUNS runs on $N_IMAGES stack images, $JOBS in parallel, -E $EQ"

if [ "$DRY_RUN" = 1 ]; then
    while IFS=$'\x1f' read -r kind image version scenario extra inferer repeat name safe; do
        case "$kind" in server) s=infer-server.sh ;; srv-auth) s=infer-srv-auth.sh ;; client) s=infer-client.sh ;; esac
        case " $extra " in *" -E "*) e="" ;; *) e="-E $EQ" ;; esac
        echo "[$name] INFERER_IMAGE=tls-test-bed/$inferer RESULTS_DIR=$CAMPAIGN_DIR/$name ./$s $image $version $scenario $extra $e"
    done < "$RUNS.sorted"
    exit 0
fi

command -v flock >/dev/null || { echo "flock is required (util-linux)" >&2; exit 1; }
mkdir -p "$CAMPAIGN_DIR/.runner"
# Pending run count per image, for --prune.
cut -d$'\x1f' -f9 "$RUNS.sorted" | sort | uniq -c | while read -r count safe; do
    echo "$count" > "$CAMPAIGN_DIR/.runner/pending-$safe"
done
log_line "CAMPAIGN $CAMPAIGN runs=$N_RUNS images=$N_IMAGES jobs=$JOBS eq=$EQ inferers=$INFERERS repeat=$REPEAT"
echo "Progress: tail -f $CAMPAIGN_DIR/runner.log"

xargs -d '\n' -P "$JOBS" -n 1 "$SCRIPTDIR/$(basename "$0")" --internal-run < "$RUNS.sorted"

log_line "CAMPAIGN $CAMPAIGN finished"
echo "Done. Summarize with: ./summarize-results.sh $CAMPAIGN_DIR"
