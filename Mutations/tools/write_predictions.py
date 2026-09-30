"""Write predictions.csv for variants m1..m8 (m0 and m5 already written)."""
import csv, os

MUT = "/Users/wtdoan/Documents/INSuRE_Project/Mutations"
GOALS = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8",
         "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"]
H, V = "HOLDS", "VIOLATED"
BASE = {"S1": H, "S2": V, "S3": H, "S4": H, "S5": V, "S6": V, "S7": H, "S8": V,
        "M1": H, "M2": H, "M3": H, "M4": H, "M5": H, "M6": H, "M7": H, "M8": H}
SSIDE = ("S2", "S5", "S6", "S8")
SSIDE_WHY = "Already violated in m0 (server-only authentication); removing a mechanism cannot restore it."
PFS_NOTE = " Assumes a faithful PFS model in which a client strand can be added (Task B)."

P = {}

# m1: server CertificateVerify deleted everywhere.
w = "No server signature: the replayable server certificate plus an adversary DH share lets the adversary play the server."
P["m1"] = {g: (V, w) for g in ("S1", "S3", "S4", "S7", "M1", "M3", "M4", "M7")}
P["m1"].update({g: (V, SSIDE_WHY) for g in SSIDE})
w = "Client CertificateVerify still signs ClientHello, ServerHello and the server Certificate, binding both DH shares to an honest client run."
P["m1"].update({g: (H, w) for g in ("M2", "M5", "M6")})
P["m1"]["M8"] = (H, w + PFS_NOTE)

# m2: ClientHello removed from the server-signed transcript only.
w = ("The signature no longer covers g^x, but the server flight is encrypted and MACed under keys derived from g^xy and cr, "
     "which the adversary cannot compute; the Finished transcripts still contain the ClientHello.")
P["m2"] = {g: (BASE[g], w if BASE[g] == H else SSIDE_WHY) for g in GOALS}

# m3, m3c, m3s: Finished deletions.
w = ("Every goal here is carried by a CertificateVerify signature over the DH shares plus key derivation from g^xy; "
     "the Finished MAC adds no guarantee the goals measure (no negotiated parameters in the model).")
for v in ("m3", "m3c", "m3s"):
    P[v] = {g: (BASE[g], w if BASE[g] == H else SSIDE_WHY) for g in GOALS}

# m4: server exponent not uniq-gen; goal hypotheses unchanged.
w = "Client-view goals do not assume (ugen y); a non-fresh server exponent may be adversary-generated, so g^xy is computable."
P["m4"] = {g: (V, w) for g in ("S1", "S3", "S4", "S7", "M1", "M3", "M4", "M7")}
P["m4"].update({g: (V, SSIDE_WHY) for g in SSIDE})
w = "Server-view goals assume (ugen y) in their hypotheses, which restores freshness for the server under analysis."
P["m4"].update({g: (H, w) for g in ("M2", "M5", "M6")})
P["m4"]["M8"] = (H, w + PFS_NOTE)

# m4c: client exponent not uniq-gen; goal hypotheses unchanged.
w = "Client-view goals assume (ugen x) in their hypotheses, which restores freshness for the client under analysis."
P["m4c"] = {g: (H, w) for g in ("S1", "S3", "S4", "S7", "M1", "M3", "M4", "M7")}
P["m4c"].update({g: (V, SSIDE_WHY) for g in SSIDE})
w = ("Server-view goals do not assume (ugen x); the adversary may know the client exponent, so it can compute g^xy and "
     "forge the client's request (a client at height 3 suffices).")
P["m4c"].update({g: (V, w) for g in ("M2", "M5", "M6")})
P["m4c"]["M8"] = (V, w + PFS_NOTE)

# m6: client CertificateVerify deleted, Certificate kept.
w = "Server-only family has no client CertificateVerify; unchanged."
P["m6"] = {g: (BASE[g], w if BASE[g] == H else SSIDE_WHY) for g in GOALS[:8]}
w = "Server CertificateVerify intact; client-view goals unaffected."
P["m6"].update({g: (H, w) for g in ("M1", "M3", "M4", "M7")})
w = "Client certificate is a public, replayable value; without a client signature the adversary pairs it with its own DH share."
P["m6"].update({g: (V, w) for g in ("M2", "M5", "M6")})
P["m6"]["M8"] = (V, w + " The adversary obtains the keys with no compromise, so PFS must fail." + PFS_NOTE)

# m7: client Certificate deleted, CertificateVerify kept.
w = "Server-only family has no client Certificate; unchanged."
P["m7"] = {g: (BASE[g], w if BASE[g] == H else SSIDE_WHY) for g in GOALS[:8]}
w = ("Agreement is over all parameters including the client name c; with the certificate gone, c occurs in no message, "
     "so nothing forces the peer's c to match.")
P["m7"].update({g: (V, w) for g in ("M1", "M2")})
w = ("Client CertificateVerify under the uncompromised key (invk cpk) still binds the DH shares; the goals fix cpk in their "
     "hypotheses, standing in for the certificate's key binding.")
P["m7"].update({g: (H, w) for g in ("M3", "M4", "M5", "M6", "M7")})
P["m7"]["M8"] = (H, w + PFS_NOTE)

# m8: CertificateVerify deleted from both roles.
w = "No signatures at all: certificates are replayable and the adversary can play either role."
P["m8"] = {g: (V, w) for g in GOALS if not g in SSIDE}
P["m8"].update({g: (V, SSIDE_WHY) for g in SSIDE})
P["m8"]["M8"] = (V, w + PFS_NOTE)
P["m8"]["S7"] = (V, "Same edit as m1 within the server-only family: " + w)

for v, preds in P.items():
    assert sorted(preds) == sorted(GOALS), (v, sorted(set(GOALS) - set(preds)))
    path = os.path.join(MUT, v, "predictions.csv")
    assert not os.path.exists(path), f"{path} exists; predictions are write-once"
    with open(path, "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["goal", "predicted", "rationale"])
        for g in GOALS:
            wr.writerow([g, *preds[g]])
    print(v, " ".join(f"{g}={preds[g][0][0]}" for g in GOALS))
