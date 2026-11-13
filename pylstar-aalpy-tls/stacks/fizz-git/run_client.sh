#!/bin/bash

set -e

PORT=4433
KEYFILE=
CERTFILE=
CAFILE=
VERSION=-tls1_2
BEHAVIOUR=http
VERBOSE=

usage () {
    echo "Error: $1"
    echo "$0 [-C cert_file|-K key_file|-A ca_file|-p port|-V version|-v|-B behaviour]" >&2
    exit 1
}

while getopts "C:KA::p:vV:B:c:" option; do
    case "$option" in
        c)
            CIPHERS="-ciphers TLS_AES_128_GCM_SHA256"
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
            CAFILE="-verify -cafile $OPTARG"
            ;;

        p)
            PORT="$OPTARG"
            ;;
        v)
            VERBOSE=1
            ;;
        V)
            VERSION="tls13"
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

echo $CAFILE
ncat -c "while read server port; do ./build_/bin/fizz s_client -connect \$server:\$port < /dev/null; done" -l -p "$PORT" -k
