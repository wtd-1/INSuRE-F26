# m2

- Family: server-only authentication (goals S1-S8)
- Mutation operator: message-field removal
- Edit: Remove client_random and the client key share (the ClientHello) from the transcript signed by the server CertificateVerify.
- Base: BASELINE-v2 (see ../BASELINE-v2/MANIFEST.sha256)
- Diff: variant.diff (one line)
