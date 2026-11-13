#!/bin/bash

set -e

PORT=4433
KEYFILE=
CERTFILE=
CAFILE=
VERSION=-tls12
BEHAVIOUR=http
VERBOSE=
CIPHERS=

usage () {
    echo "Error: $1"
    echo "$0 [-C cert_file|-K key_file|-A ca_file|-p port|-V version|-v|-B behaviour]" >&2
    exit 1
}

while getopts "C:KA::p:vV:B:c:" option; do
    case "$option" in
        c)
            CIPHERS="-cipher $OPTARG"
            ;;
        C)
            CERTFILE="$OPTARG"
            usage "unsupported option for now (-C)"
            ;;
        K)
            KEYFILE="$OPTARG"
            usage "unsupported option for now (-K)"
            ;;
        A)
            CAFILE="-V $OPTARG"
            ;;

        p)
            PORT="$OPTARG"
            ;;
        v)
            VERBOSE=1
            ;;
        V)
            VERSION=tls1.3
            ;;
        B)
            case "$OPTARG" in
                "http")
                    BEHAVIOUR="$OPTARG"
                    usage "unsupported behaviour \"$OPTARG\""
                    ;;
                "echo")
                    usage "unsupported behaviour \"$OPTARG\""
                    ;;
                *)
                    usage "invalid behaviour \"$OPTARG\" (expected: http or echo)"
                    ;;
            esac
            ;;
        *)
            usage "invalid option \"$OPTION\""
            ;;
    esac
done

#[ -f "$CERTFILE" ] || usage "$CERTFILE is not a certificate file"
#[ -f "$KEYFILE" ] || usage "$KEYFILE is not a key file"
[ "$PORT" -ge 1 -a "$PORT" -le 65535 ] || usage "$PORT is not a valid port value"

ncat -c "while read server port; do ./cli \$server \$port $CAFILE < /dev/null > /dev/null 2> /dev/null; done" -l -p "$PORT" -k
