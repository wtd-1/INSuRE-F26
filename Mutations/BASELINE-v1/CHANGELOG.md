# BASELINE-v1 CHANGELOG

Frozen 2026-09-30 (see `FROZEN`, `MANIFEST.sha256`). Superseded for the
results table by BASELINE-v2 (Task B fixes F7, F8); kept unchanged as the
model on which Task A was run (`../m0/taskA_on_BASELINE-v1/`).

Sources:
- `BIDS/CPSA Models/TLS1.3_macros.lisp` and `BIDS/CPSA Models/tls13_final.scm`
  (protocols `tls13`, `tls13fs`; goals S1-S8).
- `Mutations/Pooya_m6/tls13_m6.scm` (protocols `tls13-mtls`, `tls13mtlspfs`;
  goals M1-M8). The group's original files are not modified.

Classification: **T** = transcription error (the model did not say what its
authors evidently meant). **D** = modelling decision (changes what is
modelled; each has a paragraph in `../README.md`, "Modelling decisions").

| Id | Class | Where | Change |
|---|---|---|---|
| F1 | T | Pooya_m5 `.scm` | `include` named `TLS1.3_M5_Delete_CertificateVerify.lisp`, a file that does not exist. Resolved by construction: the baseline has one macro file and one `.scm`. |
| F2 | T | `tls13-mtls` server role | Key arguments `(invk spk) spk` swapped relative to the client role (`spk (invk spk)`). Server now passes `spk (invk spk)`, matching the client and the server-only `tls13` protocol. |
| F3 | D | `tls13mtlspfs` roles, goal M7 | Client passed `spk (invk spk)`, server `(invk spk) spk` (mismatch, T). Both now use the `tls13fs` convention in which the variable names the private key: `(invk spk) spk` and `(invk cpk) cpk`. Consequence: `privkey-disclose` leaks the key that actually signs (before, it leaked the client's public key). M7 hypothesis `(non (invk cpk))` became `(non cpk)`. Choosing the convention is a modelling decision. |
| F4 | T | macro `ClientCertVerifyMesgs` | Called `ServerFinishedMesgs` with `server_expt client_expt` swapped. Only the mTLS path uses this macro, so the server-only family is unaffected. |
| F5 | D | new macro `ClientCertificate` | Client certificates are signed over `(hash "client" name key)`; server certificates keep `(hash name key)`. Without the tag CPSA explained each server certificate as some client's certificate, recursively, and never terminated. Models X.509 clientAuth extended key usage (RFC 5280, 4.2.1.12). |
| F6 | D | goal M2 | Required peer height `(p "client" z-0 5)` became `4`. Height 5 means the client received the server's last message, which the server can never observe. |
| R1 | none | both files | Instrumentation refactor: every mutation point is a named macro whose baseline body is the original term (`ServerCertificateVerify`, `ServerSignedMesgs`, `ClientCertificateVerify`, `FinishedSel`/`ServerFinishedSel`/`ClientFinishedSel`, `ServerDHFresh`, `ClientDHFresh`). **No semantic change**: `check_expansion.sh` shows the `cpsa4 -e` expansion equals that of the plain fixed model in `reference_uninstrumented/` (4 protocols, 16 goals). |

Task A result on this baseline: m0 reproduces the four documented failures
(S2, S5, S6, S8) and m5 reports HOLDS for M1-M8, but M8's search tree never
adds a client strand (vacuous). See `../investigations/B_pfs_anomaly/`.
