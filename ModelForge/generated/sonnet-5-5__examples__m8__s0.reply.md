```scheme
(defmacro (hello1) (cat cr (exp (gen) x)))
(defmacro (hello2) (cat sr (exp (gen) y)))
(defmacro (cert n k ca) (cat n k (enc n k (privk ca))))
(defmacro (scert) (cert s spk ca))
(defmacro (ccert) (cert c cpk ca))

(defmacro (hsec z) (hash "handshake" z))
(defmacro (chk z) (hash "c hs traffic" (hsec z) cr sr))
(defmacro (shk z) (hash "s hs traffic" (hsec z) cr sr))
(defmacro (msec z) (hash "master" (hsec z)))
(defmacro (cak z) (hash "c ap traffic" cr sr (msec z)))
(defmacro (sak z) (hash "s ap traffic" cr sr (msec z)))
(defmacro (fkey k) (hash "finished" k))

(defmacro (sfin z)
  (hash (fkey (shk z)) (hello1) (hello2) (scert)))
(defmacro (cfin z)
  (hash (fkey (chk z)) (hello1) (hello2) (scert) (sfin z) (ccert)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (hello1))
     (recv (cat (hello2)
                (enc (scert) (sfin (exp (exp (gen) y) x))
                     (shk (exp (exp (gen) y) x)))))
     (send (enc (ccert) (cfin (exp (exp (gen) y) x))
                (chk (exp (exp (gen) y) x))))
     (send (enc request (cak (exp (exp (gen) y) x))))
     (recv (enc response (sak (exp (exp (gen) y) x)))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (hello1))
     (send (cat (hello2)
                (enc (scert) (sfin (exp (exp (gen) x) y))
                     (shk (exp (exp (gen) x) y)))))
     (recv (enc (ccert) (cfin (exp (exp (gen) x) y))
                (chk (exp (exp (gen) x) y))))
     (recv (enc request (cak (exp (exp (gen) x) y))))
     (send (enc response (sak (exp (exp (gen) x) y)))))
    (uniq-gen y)))
```