FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update -y && apt install -y git cmake make pkg-config g++ libssl-dev libbrotli-dev openssl ncat

RUN git clone https://github.com/h2o/picotls.git
ARG COMMIT=master

WORKDIR picotls/
RUN git checkout -b current ${COMMIT}
RUN git submodule init && git submodule update
RUN cmake . && make

COPY run_client.sh /run_client.sh
