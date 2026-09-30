"""Parse cpsa4 output into per-goal records.

A cpsa4 output file is a sequence of top-level S-expressions. Each analysis
(one per defgoal) starts with a defprotocol form, continues with one
defskeleton per step, and ends with (comment "Nothing left to do") when the
search finished. A goal whose block has no such comment did not finish (the
run aborted on the strand bound or the step limit).
"""
import re

# The 16 goals of BASELINE-v1, in file order. pov is the role whose complete
# run the goal quantifies over; the peer is the other protocol role.
GOALS = [
    ("S1", "tls13", "client", "Client->server injective agreement"),
    ("S2", "tls13", "server", "Server->client injective agreement"),
    ("S3", "tls13", "client", "Client view: c ap traffic key secrecy"),
    ("S4", "tls13", "client", "Client view: s ap traffic key secrecy"),
    ("S5", "tls13", "server", "Server view: s ap traffic key secrecy"),
    ("S6", "tls13", "server", "Server view: c ap traffic key secrecy"),
    ("S7", "tls13fs", "client", "PFS, client view (server key leaked later)"),
    ("S8", "tls13fs", "server", "PFS, server view (server key leaked later)"),
    ("M1", "tls13-mtls", "client", "Client->server injective agreement"),
    ("M2", "tls13-mtls", "server", "Server->client injective agreement"),
    ("M3", "tls13-mtls", "client", "Client view: c ap traffic key secrecy"),
    ("M4", "tls13-mtls", "client", "Client view: s ap traffic key secrecy"),
    ("M5", "tls13-mtls", "server", "Server view: s ap traffic key secrecy"),
    ("M6", "tls13-mtls", "server", "Server view: c ap traffic key secrecy"),
    ("M7", "tls13mtlspfs", "client", "PFS, client view (server key leaked later)"),
    ("M8", "tls13mtlspfs", "server", "PFS, server view (client key leaked later)"),
]
PEER = {"client": "server", "server": "client"}


def forms(text):
    """Split text into top-level S-expressions (strings and comments aware)."""
    out, depth, start, i, n, instr = [], 0, None, 0, len(text), False
    while i < n:
        c = text[i]
        if instr:
            if c == "\\":
                i += 1
            elif c == '"':
                instr = False
        elif c == '"':
            instr = True
        elif c == ";":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "(":
            if depth == 0:
                start = i
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                out.append(text[start:i + 1])
        i += 1
    return out


def parse(path):
    """Return (cpsa_version, [goal record]) for one cpsa4 output file."""
    text = open(path).read()
    m = re.search(r'\(comment "CPSA ([0-9.]+)"\)', text)
    version = m.group(1) if m else "?"
    blocks = []
    for f in forms(text):
        head = f[1:].split(None, 1)[0]
        if head == "defprotocol":
            blocks.append({"proto": f.split()[1], "skeletons": [], "finished": False})
        elif head == "defskeleton" and blocks:
            blocks[-1]["skeletons"].append(f)
        elif head == "comment" and blocks and "Nothing left to do" in f:
            blocks[-1]["finished"] = True
    records = []
    for idx, (gid, proto, pov, name) in enumerate(GOALS):
        if idx >= len(blocks):
            records.append(dict(goal=gid, proto=proto, name=name, verdict="NOT_RUN",
                                search_complete=False, skeletons=0, shapes=0,
                                peer_strand_added=False))
            continue
        b = blocks[idx]
        assert b["proto"] == proto, f"goal {gid}: expected protocol {proto}, found {b['proto']}"
        shapes = [s for s in b["skeletons"] if re.search(r"\(shape\)", s)]
        failing = [s for s in shapes if not re.search(r"\(satisfies\s+yes\)", s)]
        peer = PEER[pov]
        peer_added = any(re.search(r"\(defstrand %s \d+" % peer, s) for s in b["skeletons"])
        # A shape is a realized execution, so a failing shape is a
        # counterexample even when the search was cut off. Only the absence of
        # a counterexample needs a finished search.
        if failing:
            verdict = "VIOLATED"
        elif not b["finished"]:
            verdict = "INCOMPLETE"
        else:
            verdict = "HOLDS"
        records.append(dict(goal=gid, proto=proto, name=name, verdict=verdict,
                            search_complete=b["finished"],
                            skeletons=len(b["skeletons"]), shapes=len(shapes),
                            peer_strand_added=peer_added))
    return version, records
