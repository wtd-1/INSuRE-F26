FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update -y && apt install -y git cmake make build-essential pkg-config libunwind-dev
RUN apt install -y golang ncat

ARG REPO=boringssl
RUN git clone https://boringssl.googlesource.com/${REPO}

ARG COMMIT=fips-android-20191020
WORKDIR boringssl/

RUN git checkout -b current ${COMMIT}
RUN mkdir build && cd build && cmake .. 
RUN cd build && make

COPY run_client.sh /run_client.sh
COPY run_server.sh /run_server.sh
