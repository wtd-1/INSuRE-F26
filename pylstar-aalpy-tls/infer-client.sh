#!/bin/bash

set -e

SCRIPTDIR="$(dirname "$0")"
cd "$SCRIPTDIR"

CLIENT_IMAGE=$1
# Inference tool image; e.g. INFERER_IMAGE=tls-test-bed/pylstar-tls-lsharp to learn with L#.
INFERER_IMAGE="${INFERER_IMAGE:-tls-test-bed/pylstar-tls}"
VERSION=$2
VOCABULARY=$3

shift 3

PID=$$

if [ -z "$( docker network ls -f name=tls-test-bed -q )" ]; then
    docker network create tls-test-bed
fi

docker run -d --rm \
           --name "tls-client-$PID" \
           --network tls-test-bed \
           -v "$PWD"/crypto/material/trusted-ca/ca.pem:/tmp/ca.pem \
           "$CLIENT_IMAGE" /run_client.sh \
                           -p 4444 \
                           -V "$VERSION" \
                           $CIPHERS \
                           -A /tmp/ca.pem

# Stop the client on exit, even when the inference fails (set -e).
trap 'docker kill "tls-client-$PID" >/dev/null 2>&1 || true' EXIT

if [ -z "$RESULTS_DIR" ]; then
    # Default: a fresh directory under results/ (git-ignored) in this repo.
    RUN_NAME="${CLIENT_IMAGE##*/}"
    INFERER_NAME="${INFERER_IMAGE##*/}"
    mkdir -p results
    RESULTS_DIR="$(mktemp -d "$PWD/results/client--${RUN_NAME//:/_}--$VOCABULARY--${INFERER_NAME//:/_}--$(date +%Y%m%d-%H%M%S)-XXXXXX")"
fi
mkdir -p "$RESULTS_DIR"

# Signing updates the CA's serial and index files: serialize it, so that
# client inferences can run in parallel (run-experiments.sh --jobs).
if command -v flock >/dev/null; then
    flock crypto/.ca.lock make -C crypto certs/"tls-inferer-$PID".crt
else
    make -C crypto certs/"tls-inferer-$PID".crt
fi

docker run -i --rm \
           --name tls-inferer-$PID \
           -v "$RESULTS_DIR":/results \
           -v "$PWD"/crypto/material:/tmp/material \
           -v "$PWD"/crypto/certs:/tmp/certs \
           --network tls-test-bed \
           "$INFERER_IMAGE" /probe_client.sh \
                            -T "tls-client-$PID":4444 \
                            -S "$VOCABULARY" \
                            -L "tls-inferer-$PID":4433 \
                            -C valid:/tmp/certs/"tls-inferer-$PID".crt:/tmp/certs/"tls-inferer-$PID".key:DEFAULT \
                            -C invalid:/tmp/material/servers/invalid/cert.pem:/tmp/material/servers/invalid/key.pem \
                            -C untrusted:/tmp/material/servers/untrusted/cert.pem:/tmp/material/servers/untrusted/key.pem \
                            -o /results \
                            "$@"

echo Results are in "$RESULTS_DIR"
