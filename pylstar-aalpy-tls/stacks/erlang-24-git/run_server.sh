#!/bin/bash

set -e

PORT=4433
KEYFILE=/tmp/key.pem
CERTFILE=/tmp/cert.pem
VERSION=tlsv1.2
BEHAVIOUR=http
VERBOSE=

usage () {
    echo "Error: $1"
    echo "$0 [-C cert_file|-K key_file|-p port|-V version|-v|-A ca_file]" >&2
    exit 1
}

while getopts "C:K:p:vV:B:" option; do
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
                    VERSION=tlsv1
                    ;;
                "1.1"|"TLS 1.1"|"TLS_1.1")
                    VERSION=tlsv1.1
                    ;;
                "1.2"|"TLS 1.2"|"TLS_1.2")
                    VERSION=tlsv1.2
                    ;;
                "1.3"|"TLS 1.3"|"TLS_1.3")
                    VERSION=tlsv1.3
                    ;;
                *)
                    usage "invalid version \"$OPTARG\" (expected: 1.0 to 1.3)"
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

escript /server.erl "$VERSION" "$PORT" "$CERTFILE" "$KEYFILE"
