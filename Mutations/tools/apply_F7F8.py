"""Apply fixes F7 and F8 (Task B) to a BASELINE-v1 .scm file.

Usage: python3 apply_F7F8.py <in.scm> <out.scm>

Works on both the instrumented baseline and the plain reference: it only
touches the tls13mtlspfs protocol and its two goals (M7, M8).

F7  The tls13mtlspfs client loads its signing key from local storage before
    its first message, and declares that state gen-st, as the server role
    already does. M7 (the client-view PFS goal) is renumbered for the extra
    client node, and its (non cpk) hypothesis is dropped because the key is
    now carried in state; secrecy of a stored key is modelled by cert-gen's
    uniq-gen and the explicit privkey-disclose role, as in tls13fs.
F8  M8 (server-view PFS, client key leaked) orders the leak after the
    server's last send (node 5) instead of node 2. Node 2 is copied from S8,
    where it is the server's last use of its own key; the server last uses
    the client's key when it verifies the client flight at node 3, a receive
    node, which CPSA does not accept as the source of an ordering.
"""
import re, sys


def apply(t):
    p0 = t.index("(defprotocol tls13mtlspfs")
    head, tail = t[:p0], t[p0:]
    c0 = tail.index("(defrole client")
    c1 = tail.index("(defrole server")
    client = tail[c0:c1]
    old = "     (response text)\n     )\n    (trace\n     (mTLS send recv"
    new = ("     (response text)\n"
           "     (cpriv-stor locn)  ;; F7: client local storage for its signing key\n"
           "     )\n    (trace\n"
           "     (load cpriv-stor (pv c cpk (invk cpk)))  ;; F7: key comes from storage\n"
           "     (mTLS send recv")
    assert client.count(old) == 1
    client = client.replace(old, new)
    end = client.rindex("    )\n")
    client = client[:end] + "    (gen-st (pv c cpk (invk cpk)))  ;; F7\n" + client[end:]
    tail = tail[:c0] + client + tail[c1:]
    gs = [m.start() for m in re.finditer(r"\(defgoal tls13mtlspfs", tail)]
    assert len(gs) == 2
    m7, m8 = tail[gs[0]:gs[1]], tail[gs[1]:]
    for a, b in [('(p "client" z 5)', '(p "client" z 6)'),
                 ("(prec z 2 z-1 0)", "(prec z 3 z-1 0)"),
                 ("(uniq-at cr z 0)", "(uniq-at cr z 1)"),
                 ("(uniq-at request z 3)", "(uniq-at request z 4)"),
                 ("      (non cpk)\n", "")]:
        assert m7.count(a) == 1, a
        m7 = m7.replace(a, b)
    assert m8.count("(prec z 2 z-1 0)") == 1 and '(p "privkey-disclose" "pk" z-1 cpk)' in m8
    m8 = m8.replace("(prec z 2 z-1 0)", "(prec z 5 z-1 0)")
    return head + tail[:gs[0]] + m7 + m8


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    t = apply(open(src).read())
    t = t.replace("BASELINE-v1", "BASELINE-v2")
    open(dst, "w").write(t)
