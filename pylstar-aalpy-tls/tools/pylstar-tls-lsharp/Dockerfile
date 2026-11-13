# pylstar-tls using AALpy's L# as its learning algorithm instead of pylstar's L*.
#
# Built on top of the regular pylstar-tls image, so both learners share exactly
# the same pylstar-tls code. pylstar-tls itself is not modified: run_lsharp.py
# swaps the learner class from outside (see lsharp_learner.py).
FROM tls-test-bed/pylstar-tls

RUN pip install aalpy==2.0.0

COPY lsharp_learner.py run_lsharp.py test_lsharp_offline.py /opt/lsharp/
COPY testdata /opt/lsharp/testdata

# Replace the base image's entry points with L# ones (same arguments).
COPY probe_server.sh probe_client.sh /
RUN chmod +x /probe_server.sh /probe_client.sh
