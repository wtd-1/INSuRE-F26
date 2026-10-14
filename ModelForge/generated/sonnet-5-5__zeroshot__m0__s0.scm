(defmacro (gx) (exp (gen) x))
(defmacro (gy) (exp (gen) y))
(defmacro (zc) (exp (exp (gen) y) x))
(defmacro (zs) (exp (exp (gen) x) y))

(defmacro (ch) (cat cr (gx)))
(defmacro (sh) (cat sr (gy)))

(defmacro (hsec z) (hash "hs" z))
(defmacro (msec z) (hash "ms" (hsec z)))
(defmacro (chts z) (hash "chts" (hsec z) cr sr))
(defmacro (shts z) (hash "shts" (hsec z) cr sr))
(defmacro (capp z) (hash "capp" cr sr (msec z)))
(defmacro (sapp z) (hash "sapp" cr sr (msec z)))
(defmacro (fk k) (hash "fin" k))

(defmacro (scert) (enc "cert" s spk (invk (pubk ca))))
(defmacro (ccert) (enc "cert" c cpk (invk (pubk ca))))

(defmacro (ts1) (cat (ch) (sh) (scert)))
(defmacro (scv) (enc "sig" (ts1) (invk spk)))
(defmacro (ts2) (cat (ts1) (scv)))
(defmacro (sfin z) (hash (fk (shts z)) (ts2)))

(defmacro (tc1 z) (cat (ch) (sh) (scert) (scv) (sfin z) (ccert)))
(defmacro (ccv z) (enc "sig" (tc1 z) (invk cpk)))
(defmacro (tc2 z) (cat (tc1 z) (ccv z)))
(defmacro (cfin z) (hash (fk (chts z)) (tc2 z)))

(defmacro (msg2 z)
  (cat (sh) (enc (scert) (scv) (sfin z) (shts z))))
(defmacro (msg3 z)
  (enc (ccert) (ccv z) (cfin z) (chts z)))
(defmacro (msg4 z) (enc request (capp z)))
(defmacro (msg5 z) (enc response (sapp z)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (ch))
      (recv (msg2 (zc)))
      (send (msg3 (zc)))
      (send (msg4 (zc)))
      (recv (msg5 (zc))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (ch))
      (send (msg2 (zs)))
      (recv (msg3 (zs)))
      (recv (msg4 (zs)))
      (send (msg5 (zs))))
    (uniq-gen y)))
