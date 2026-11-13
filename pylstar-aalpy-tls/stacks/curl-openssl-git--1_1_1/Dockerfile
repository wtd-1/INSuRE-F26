FROM debian:buster AS builder
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends git perl gcc make libc6-dev ca-certificates && apt-get clean

WORKDIR /openssl
ARG COMMIT
RUN git clone --branch ${COMMIT} --depth 1 https://github.com/openssl/openssl.git .

RUN ./config
RUN make -j
RUN make install_sw DESTDIR=/tmp/destdir

RUN apt install -y --no-install-recommends autoconf automake libtool m4

RUN git clone https://github.com/curl/curl
# Pinned like the curl-gnutls and curl-wolfssl stacks: current curl requires OpenSSL >= 3.
RUN cd curl && git checkout -b current curl-7_75_0
RUN cd curl && autoreconf -fi
# curl 7.75.0 names this option --with-ssl (--with-openssl came later and would be ignored).
RUN cd curl && ./configure --with-ssl=/tmp/destdir/usr/local
RUN cd curl && make -j
RUN cd curl && make install

RUN apt-get update && apt-get install -y --no-install-recommends ncat && apt-get clean
RUN ldconfig
RUN ldconfig /tmp/destdir/usr/local/lib
COPY run_client.sh /run_client.sh
