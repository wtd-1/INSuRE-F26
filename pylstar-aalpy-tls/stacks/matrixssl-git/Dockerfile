FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends git perl gcc make libc6-dev ca-certificates ncat && apt-get clean
RUN git clone https://github.com/matrixssl/matrixssl.git
ARG COMMIT=4-3-0-open
RUN cd matrixssl && git checkout -b current ${COMMIT}
RUN sed -i 's/USE_TLS_1_._AND_ABOVE/USE_TLS_1_0_AND_ABOVE/' /matrixssl/configs/default/matrixsslConfig.h || true
RUN cd matrixssl && make -j

WORKDIR /matrixssl

COPY run_server.sh /run_server.sh
