FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends git perl gcc make libc6-dev ca-certificates ncat && apt-get clean
RUN apt-get update && apt-get install -y --no-install-recommends python2 python3 && apt-get clean
RUN git clone https://github.com/ARMmbed/mbedtls.git
ARG COMMIT=mbedtls-2.16.2
RUN cd mbedtls && git checkout -b current ${COMMIT} && git submodule init && git submodule update
COPY explicit.patch /tmp/oracle.patch
RUN git config --global user.email "you@example.com" && git config --global user.name "Your name"
RUN cd mbedtls && git checkout -b FFT && git am /tmp/oracle.patch
RUN cd mbedtls && make -j

COPY run_server.sh /run_server.sh
