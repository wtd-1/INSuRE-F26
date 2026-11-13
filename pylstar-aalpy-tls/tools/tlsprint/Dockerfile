# Pinned to stretch: "oldoldstable" used to mean stretch, the last release with openjdk-8.
FROM debian:stretch
# Debian stretch is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian stretch main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list

RUN apt-get update && apt install -y openjdk-8-jdk python3 python3-pip
RUN pip3 install tlsprint

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
