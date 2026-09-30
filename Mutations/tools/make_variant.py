"""Create Mutations/<id>/ from BASELINE-v2 by applying exactly one line edit.

Usage: python3 make_variant.py <id> [<id> ...]

Each edit is (file, anchor, old, new): `old` must be the line immediately
after the unique line `anchor`. The script refuses to write a variant whose
diff against BASELINE-v2 is not exactly one changed line (zero for controls).
"""
import difflib, os, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
MUT = os.path.dirname(HERE)
BASE = os.path.join(MUT, "BASELINE-v2")
MACROS, SCM = "TLS1.3_macros.lisp", "tls13_baseline.scm"

# id: (family, operator, description, edit or None)
VARIANTS = {
    "m0": ("S", "none (control)", "Baseline, server-only authentication family.", None),
    "m1": ("S", "message removal",
           "Delete the server CertificateVerify from both roles (wire and every transcript).",
           (MACROS, "				   ca)",
            "    (CertificateVerify (ServerSignedMesgs client_random server_random client_expt server_expt server serverpubkey ca) serverprivkey))",
            "    (^))")),
    "m2": ("S", "message-field removal",
           "Remove client_random and the client key share (the ClientHello) from the transcript signed by the server CertificateVerify.",
           (MACROS, "			     server_expt server serverpubkey ca)",
            "    (ServerCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey ca))",
            "    (^ (ServerHello server_random server_expt) (Certificate server serverpubkey ca)))")),
    "m3": ("S", "message removal",
           "Delete the Finished message (server and client).",
           (MACROS, "(defmacro (FinishedSel present deleted)", "    present)", "    deleted)")),
    "m3c": ("S", "message removal",
            "Delete only the client Finished.",
            (MACROS, "(defmacro (ClientFinishedSel present deleted)",
             "    (FinishedSel present deleted))", "    deleted)")),
    "m3s": ("S", "message removal",
            "Delete only the server Finished (wire and client Finished transcript).",
            (MACROS, "(defmacro (ServerFinishedSel present deleted)",
             "    (FinishedSel present deleted))", "    deleted)")),
    "m4": ("S", "freshness removal",
           "Delete uniq-gen for the server DH exponent (server may reuse a fixed exponent).",
           (MACROS, "(defmacro (ServerDHFresh exponent)", "    (uniq-gen exponent))", "    (^))")),
    "m4c": ("S", "freshness removal",
            "Delete uniq-gen for the client DH exponent (symmetry check on m4).",
            (MACROS, "(defmacro (ClientDHFresh exponent)", "    (uniq-gen exponent))", "    (^))")),
    "m5": ("M", "none (control)", "Baseline, mutual-authentication family.", None),
    "m6": ("M", "message removal",
           "Delete the client CertificateVerify; keep the client Certificate.",
           (MACROS, "				   handshakesecret)",
            "    (CertificateVerify (ClientCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey ca handshakesecret) clientprivkey))",
            "    (^))")),
    "m7": ("M", "message removal",
           "Delete the client Certificate; keep the client CertificateVerify.",
           (MACROS, "(defmacro (ClientCertificate party publickey ca)",
            '    (cat party publickey (enc (hash "client" party publickey) (privk ca))))',
            "    (^))")),
    "m8": ("M", "message removal",
           "Delete CertificateVerify from both roles (server and client).",
           (MACROS, "(defmacro (CertificateVerify messages key)",
            "    (enc (hash messages) key))", "    (^))")),
}


def apply_edit(lines, anchor, old, new):
    hits = [i for i, l in enumerate(lines) if l == anchor]
    assert len(hits) == 1, f"anchor not unique ({len(hits)} hits): {anchor!r}"
    i = hits[0] + 1
    assert lines[i] == old, f"line after anchor is {lines[i]!r}, expected {old!r}"
    return lines[:i] + [new] + lines[i + 1:]


def make(vid):
    family, op, desc, edit = VARIANTS[vid]
    d = os.path.join(MUT, vid)
    os.makedirs(d, exist_ok=True)
    diff_text = ""
    for fname in (MACROS, SCM):
        src = open(os.path.join(BASE, fname)).read().split("\n")
        out = src
        if edit and edit[0] == fname:
            out = apply_edit(src, *edit[1:])
        changed = sum(1 for a, b in zip(src, out) if a != b)
        assert len(src) == len(out) and changed == (1 if edit and edit[0] == fname else 0)
        open(os.path.join(d, fname), "w").write("\n".join(out))
        diff_text += "".join(difflib.unified_diff(
            [l + "\n" for l in src], [l + "\n" for l in out],
            fromfile=f"BASELINE-v2/{fname}", tofile=f"{vid}/{fname}"))
    open(os.path.join(d, "variant.diff"), "w").write(diff_text)
    fam = {"S": "server-only authentication (goals S1-S8)",
           "M": "mutual authentication (goals M1-M8)"}[family]
    open(os.path.join(d, "VARIANT.md"), "w").write(
        f"# {vid}\n\n- Family: {fam}\n- Mutation operator: {op}\n- Edit: {desc}\n"
        f"- Base: BASELINE-v2 (see ../BASELINE-v2/MANIFEST.sha256)\n"
        f"- Diff: variant.diff ({'no edit' if edit is None else 'one line'})\n")
    print(f"{vid}: written ({'control' if edit is None else 'one-line edit in ' + edit[0]})")


if __name__ == "__main__":
    for v in sys.argv[1:]:
        make(v)
