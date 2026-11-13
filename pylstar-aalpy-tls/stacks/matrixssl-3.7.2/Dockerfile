FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends git perl gcc make libc6-dev ca-certificates ncat && apt-get clean
COPY matrixssl-3-7-2-open.tgz matrixssl-3-7-2-open.tgz
RUN tar xvzf matrixssl-3-7-2-open.tgz && mv matrixssl-3-7-2-open matrixssl

RUN sed -i 's/TLS_1_0/TLS_1_2/' matrixssl/apps/server.c
RUN sed -i 's+^#define REQUIRE_SECURE_REHANDSHAKES$+// #define REQUIRE_SECURE_REHANDSHAKES+' matrixssl/matrixssl/matrixsslConfig.h
RUN cd matrixssl && CFLAGS="-DUSE_SSL_HANDSHAKE_MSG_TRACE=1 -DUSE_SSL_INFORMATIONAL_TRACE=1" make && CFLAGS="-DUSE_SSL_HANDSHAKE_MSG_TRACE=1 -DUSE_SSL_INFORMATIONAL_TRACE=1" make -C apps

COPY run_server.sh /run_server.sh
