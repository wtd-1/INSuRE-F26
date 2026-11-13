ARG COMMIT=v4.7.0-stable
FROM tls-test-bed/wolfssl:${COMMIT}

RUN git clone https://github.com/curl/curl
RUN cd curl && git checkout -b current curl-7_75_0
RUN cd curl && autoreconf -fi
RUN cd curl && ./configure --with-wolfssl=/usr/local
RUN cd curl && make -j
RUN cd curl && make install
RUN ldconfig
RUN rm /run_server.sh

COPY run_client.sh /run_client.sh
