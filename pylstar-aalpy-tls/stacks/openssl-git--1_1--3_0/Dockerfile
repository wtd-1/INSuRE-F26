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


FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends ncat && apt-get clean

COPY --from=builder /tmp/destdir /
RUN ldconfig
RUN ldconfig /usr/local/lib64/

COPY run_server.sh /run_server.sh
COPY run_client.sh /run_client.sh
