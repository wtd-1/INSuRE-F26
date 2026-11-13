# Renders inferred state machines (.automaton files) as Graphviz graphs, using
# pylstar-tls's own automaton2dot.py script.
#
# automaton2dot.py first appeared in pylstar-tls v0.4 and needs that version's
# automata package, while inference uses v0.3. So v0.5 is checked out in a
# separate folder, used only by this tool; the v0.3 install is not touched.
FROM tls-test-bed/pylstar-tls

# Debian buster is EOL; its packages now live on archive.debian.org.
RUN echo "deb http://archive.debian.org/debian buster main" > /etc/apt/sources.list && echo "deb http://archive.debian.org/debian-security buster/updates main" >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y --no-install-recommends graphviz && apt-get clean

RUN git clone --depth 1 --branch v0.5 https://gitlab.com/gaspians/pylstar-tls /opt/pylstar-tls-v0.5

COPY render.sh /render.sh
RUN chmod +x /render.sh
