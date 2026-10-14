# Interface the generated CPSA model must follow

So that fixed security goals can be checked against your model, use exactly
these names. Everything else (term structure, macros, key derivation) is up
to you.

- Protocol name `mtls13`. Use algebra `diffie-hellman`.
- Two roles, named `client` and `server`.
- Both roles declare these variables, with these sorts:
  - `s c ca` : `name` (server, client, certification authority)
  - `cr sr` : `text` (client random, server random)
  - `spk cpk` : `akey` (server and client public keys; the private key of
    `k` is `(invk k)`)
  - `request response` : `text`
  - In the **client** role: `x` : `rndx` (its own exponent) and `y` : `expt`
    (the server's, seen only as `g^y`).
  - In the **server** role: `y` : `rndx` (its own exponent) and `x` : `expt`.
- Each role has exactly five events, in this order:
  - client: send message 1, receive message 2, send message 3, send message
    4, receive message 5.
  - server: receive message 1, send message 2, receive message 3, receive
    message 4, send message 5.
- The client role declares `(uniq-gen x)` and the server role declares
  `(uniq-gen y)`.
- Do not add `defrule`, `defgoal` or `defskeleton` forms. They are added
  afterwards.
- Output a single fenced code block containing any `defmacro` forms you want,
  followed by the one `defprotocol` form. Do not use `include` or `herald`.
