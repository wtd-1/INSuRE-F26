FROM python:3.10-buster

WORKDIR /root

RUN git clone https://gitlab.com/gaspians/pylstar-tls && cd pylstar-tls && git checkout -b current v0.3

# scapy 2.4.5 (pulled in by pylstar-tls) uses cryptography.utils.register_interface,
# which was removed in cryptography 38.
RUN pip install -r pylstar-tls/requirements.txt && pip install "cryptography<38"

COPY probe_server.sh probe_client.sh /
