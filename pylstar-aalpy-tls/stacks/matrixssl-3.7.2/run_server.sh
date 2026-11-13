#!/bin/bash

set -e

PORT=4433
KEYFILE=/tmp/key.pem
CERTFILE=/tmp/cert.pem
VERBOSE=

usage () {
    echo "Error: $1"
    echo "$0 [-C cert_file|-K key_file|-p port|-V version|-v|-A ca_file]" >&2
    exit 1
}

while getopts "C:K:p:vV:A:" option; do
    case "$option" in
        C)
            CERTFILE="$OPTARG"
            ;;
        K)
            KEYFILE="$OPTARG"
            ;;
        p)
            PORT="$OPTARG"
            ;;
        v)
            VERBOSE=1
            ;;
        V)
            case "$OPTARG" in
                "1.0"|"TLS 1.0"|"TLS_1.0")
                    ;;
                *)
                    usage "invalid version \"$OPTARG\" (expected: 1.0 only)"
                    ;;
            esac
            ;;
        A)
            echo Ignoring -A for now...
            ;;
        *)
            usage "invalid option \"$OPTION\""
            ;;
    esac
done

[ -f "$CERTFILE" ] || usage "$CERTFILE is not a certificate file"
[ -f "$KEYFILE" ] || usage "$KEYFILE is not a key file"
[ "$PORT" -ge 1 -a "$PORT" -le 65535 ] || usage "$PORT is not a valid port value"

if [ -f /matrixssl/apps/ssl/server ]; then
    /matrixssl/apps/ssl/server -c "$CERTFILE" -k "$KEYFILE" -P "$PORT"
else
    cp "$CERTFILE" /matrixssl/sampleCerts/RSA/1024_RSA.pem
    cp "$KEYFILE" /matrixssl/sampleCerts/RSA/1024_RSA_KEY.pem
    /matrixssl/apps/server
fi
