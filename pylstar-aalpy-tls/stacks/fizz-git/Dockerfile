from debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt update && apt install -y git make gcc python3

RUN apt install -y g++ cmake libboost-all-dev libevent-dev libdouble-conversion-dev \
    libgoogle-glog-dev libgflags-dev libiberty-dev liblz4-dev liblzma-dev \
    libsnappy-dev make zlib1g-dev binutils-dev libjemalloc-dev libssl-dev \
    pkg-config libsodium-dev libgtest-dev libgmock-dev libunwind8-dev libelf-dev libdwarf-dev \
    libzstd-dev ncat libzstd-dev

RUN git clone https://github.com/fmtlib/fmt.git
RUN cd fmt && git checkout 7.1.3
RUN cd fmt && mkdir _build && cd _build && cmake .. && make -j$(nproc) && make install

RUN git clone https://github.com/facebook/zstd.git
RUN cd zstd && git checkout v1.5.0
RUN cd zstd && make install

ARG COMMIT=v2021.02.15.00
RUN git clone https://github.com/facebook/folly.git
RUN cd folly && git checkout ${COMMIT}
RUN cd folly && mkdir _build && cd _build && cmake .. && make -j $(nproc) && make install

#ARG REPO=facebookincubator
RUN git clone https://github.com/facebookincubator/fizz

WORKDIR fizz/
RUN git checkout -b current ${COMMIT}
RUN mkdir build_ && cd build_ && cmake ../fizz && make

COPY run_client.sh /run_client.sh

