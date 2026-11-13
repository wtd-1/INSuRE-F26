#!/bin/bash

set -e

SCRIPTDIR="$(dirname "$0")"
cd "$SCRIPTDIR"

SERVER_IMAGE=$1
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
           --name "tls-server-$PID" \
           --network tls-test-bed \
           -v "$PWD/crypto/material/servers/valid/key.pem":/tmp/key.pem \
           -v "$PWD/crypto/material/servers/valid/cert.pem":/tmp/cert.pem \
           -v "$PWD/crypto/material/trusted-ca/ca.pem":/tmp/ca.pem \
           "$SERVER_IMAGE" /run_server.sh \
                           -C /tmp/cert.pem -K /tmp/key.pem \
                           -A /tmp/ca.pem \
                           -p 4433 \
                           -V "$VERSION"

# Stop the server on exit, even when the inference fails (set -e).
trap 'docker kill "tls-server-$PID" >/dev/null 2>&1 || true' EXIT

if [ -z "$RESULTS_DIR" ]; then
    # Default: a fresh directory under results/ (git-ignored) in this repo.
    RUN_NAME="${SERVER_IMAGE##*/}"
    INFERER_NAME="${INFERER_IMAGE##*/}"
    mkdir -p results
    RESULTS_DIR="$(mktemp -d "$PWD/results/srv-auth--${RUN_NAME//:/_}--$VOCABULARY--${INFERER_NAME//:/_}--$(date +%Y%m%d-%H%M%S)-XXXXXX")"
fi
mkdir -p "$RESULTS_DIR"

docker run -i --rm \
           --name tls-inferer-$PID \
           -v "$RESULTS_DIR":/results \
           -v "$PWD"/crypto/material:/tmp/material \
           --network tls-test-bed \
           "$INFERER_IMAGE" /probe_server.sh \
                            -R "tls-server-$PID":4433 \
                            -S "$VOCABULARY" \
                            -C valid:/tmp/material/clients/valid/cert.pem:/tmp/material/clients/valid/key.pem:DEFAULT \
                            -C untrusted:/tmp/material/clients/untrusted/cert.pem:/tmp/material/clients/untrusted/key.pem \
                            -o /results \
                            "$@"

echo Results are in "$RESULTS_DIR"
