FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends git perl gcc make libc6-dev ca-certificates ncat && apt-get clean

RUN apt-get update && apt-get install -y --no-install-recommends \
    libncurses-dev libwxgtk3.0-dev libssl-dev autoconf && apt-get clean

RUN git clone https://github.com/erlang/otp.git

ARG COMMIT=OTP-24.0.3
RUN cd otp && git checkout -b current ${COMMIT}

RUN cd otp && ./otp_build autoconf
RUN cd otp && ./configure
RUN cd otp && make -j
RUN cd otp && make -j install

COPY server.erl run_server.sh /
