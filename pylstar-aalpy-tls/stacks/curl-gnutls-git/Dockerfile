ARG COMMIT=3.7.0
FROM tls-test-bed/gnutls:${COMMIT}

RUN apt install -y --no-install-recommends autoconf automake libtool m4

RUN git clone https://github.com/curl/curl
RUN cd curl && git checkout -b current curl-7_75_0
RUN cd curl && autoreconf -fi
RUN cd curl && ./configure --with-gnutls=/usr/lib
RUN cd curl && make -j
RUN cd curl && make install
RUN ldconfig
RUN rm /run_server.sh

COPY run_client.sh /run_client.sh
