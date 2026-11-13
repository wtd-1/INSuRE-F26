FROM debian:buster
# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list

RUN apt-get update -y && apt install -y git gcc mercurial make libz-dev g++ ncat && apt clean
RUN hg clone https://hg.mozilla.org/projects/nspr
RUN cd nspr && hg update NSPR_4_33_RTM

RUN git clone https://github.com/nss-dev/nss.git
ARG COMMIT=NSS_3_75_RTM

WORKDIR /nss/
RUN git checkout -b current ${COMMIT}
RUN sed -i 's/strncpy/memcpy/' /nss/coreconf/nsinstall/pathsub.c
RUN echo "DEFINES += -Wno-error=deprecated-declarations" >> /nss/coreconf/config.mk
RUN echo "DEFINES += -Wno-error=misleading-indentation" >> /nss/coreconf/config.mk
RUN echo "DEFINES += -Wno-error=int-in-bool-context" >> /nss/coreconf/config.mk
RUN echo "DEFINES += -Wno-error=format-overflow" >> /nss/coreconf/config.mk
RUN echo "DEFINES += -Wno-error=maybe-uninitialized" >> /nss/coreconf/config.mk
ENV BUILD_OPT=1
ENV USE_64=1
ENV ENABLE_TLS_1_3=1
ENV HOST=nss
ENV DOMSUF=local

RUN make nss_build_all
RUN make -j install
RUN mv /dist/Linux* /dist/Linux
RUN ldconfig

ENV PLATFORM="Linux"
ENV DYLD_LIBRARY_PATH="/dist/$PLATFORM/lib"
ENV LD_LIBRARY_PATH=/dist/$PLATFORM/lib:/lib:$LD_LIBRARY_PATH
ENV PATH="/dist/$PLATFORM/bin:$PATH"

RUN mkdir nssdb
RUN certutil -N -d sql:nssdb --empty-password

COPY run_server.sh /run_server.sh
COPY run_client.sh /run_client.sh

