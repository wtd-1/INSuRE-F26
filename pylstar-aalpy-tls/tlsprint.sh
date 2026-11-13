#!/bin/bash

set -e

SCRIPTDIR="$(dirname "$0")"
cd "$SCRIPTDIR"

SERVER_IMAGE=$1
TLSPRINT_IMAGE=tls-test-bed/tlsprint
VERSION=$2

shift 2

PID=$$

if [ -z "$( docker network ls -f name=tls-test-bed -q )" ]; then
    docker network create tls-test-bed
fi

docker run -d --rm \
           --name "tls-server-$PID" \
           --network tls-test-bed \
           -v "$PWD/crypto/material/servers/valid/key.pem":/tmp/key.pem \
           -v "$PWD/crypto/material/servers/valid/cert.pem":/tmp/cert.pem \
           "$SERVER_IMAGE" /run_server.sh \
                           -C /tmp/cert.pem -K /tmp/key.pem \
                           -p 4433 \
                           -V "$VERSION"

# Stop the server on exit, even when tlsprint fails (set -e).
trap 'docker kill "tls-server-$PID" >/dev/null 2>&1 || true' EXIT

docker run -i --rm \
           --name tls-inferer-$PID \
           --network tls-test-bed \
           "$TLSPRINT_IMAGE" tlsprint identify "tls-server-$PID" -p 4433
