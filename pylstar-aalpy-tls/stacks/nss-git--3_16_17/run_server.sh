#!/bin/bash

set -e

PORT=4433
KEYFILE=/tmp/key.pem
CERTFILE=/tmp/cert.pem
CAFILE=
CAOPTION=

usage () {
    echo "Error: $1"
    echo "$0 [-C cert_file|-K key_file|-p port|-V version|-v|-A ca_file]" >&2
    exit 1
}

while getopts "C:K:p:A:V:v" option; do
    case "$option" in
        A)
            CAFILE="$OPTARG"
            ;;
        v)
            echo "Ignoring $option for now..."
            ;;
        C)
            CERTFILE="$OPTARG"
            ;;
        K)
            KEYFILE="$OPTARG"
            ;;
        p)
            PORT="$OPTARG"
            ;;
        V)
            case "$OPTARG" in
                "1.0"|"TLS 1.0"|"TLS_1.0")
                    VERSION="tls1.0:tls1.0"
                    ;;
                "1.1"|"TLS 1.1"|"TLS_1.1")
                    VERSION="tls1.1:tls1.1"
                    ;;
                "1.2"|"TLS 1.2"|"TLS_1.2")
                    VERSION="tls1.2:tls1.2"
                    ;;
                "1.3"|"TLS 1.3"|"TLS_1.3")
                    VERSION="tls1.3:tls1.3"
                    ;;
                *)
                    usage "invalid version \"$OPTARG\" (expected: 1.0 to 1.3)"
                    ;;
            esac
            ;;
        *)
            usage "invalid option \"$OPTION\""
            ;;
    esac
done

[ -f "$CERTFILE" ] || usage "$CERTFILE is not a certificate file"
[ -f "$KEYFILE" ] || usage "$KEYFILE is not a key file"
[ "$PORT" -ge 1 -a "$PORT" -le 65535 ] || usage "$PORT is not a valid port value"

openssl pkcs12 -export -passout pass: -out wwww.tls-inferer.gasp.ebfe.fr.p12 -inkey $KEYFILE -in $CERTFILE -name wwww.tls-inferer.gasp.ebfe.fr
pk12util -i wwww.tls-inferer.gasp.ebfe.fr.p12 -d sql:nssdb -W ''

if [ -f "$CAFILE" ]; then
    certutil -A -n ca-root -t "T,," -i "$CAFILE" -d sql:./nssdb
    CAOPTION="-A ca-root -rr"
fi

selfserv -d sql:./nssdb -p "$PORT" -V "$VERSION" -n wwww.tls-inferer.gasp.ebfe.fr $CAOPTION
