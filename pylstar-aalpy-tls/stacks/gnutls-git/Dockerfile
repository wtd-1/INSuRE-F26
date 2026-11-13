FROM debian:bullseye
# Debian bullseye is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security bullseye-security main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends git perl gcc make libc6-dev ca-certificates ncat && apt-get clean
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf libtool gettext autopoint libev-dev \
    automake autogen nettle-dev libp11-kit-dev libtspi-dev libunistring-dev \
    guile-2.2-dev libtasn1-6-dev libidn2-0-dev gawk gperf \
    libunbound-dev dns-root-data bison wget patch && apt-get clean


RUN git clone https://github.com/gnutls/gnutls.git

ARG COMMIT=3.7.0

RUN cd gnutls && git checkout -b current ${COMMIT}
RUN cd gnutls && ./bootstrap
RUN cd gnutls && ./configure --prefix=/usr/local --disable-doc --disable-manpages
RUN cd gnutls && make
RUN cd gnutls && make install
RUN ldconfig


COPY run_server.sh /run_server.sh
COPY run_client.sh /run_client.sh
