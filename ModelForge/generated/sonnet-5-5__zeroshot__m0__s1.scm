(defmacro (gx) (exp (gen) x))
(defmacro (gy) (exp (gen) y))
(defmacro (secret) (exp (exp (gen) y) x))

(defmacro (hs) (hash (cat "hs" (secret))))
(defmacro (ms) (hash (cat "ms" (hs))))
(defmacro (chk) (hash (cat "cht" (hs) cr sr)))
(defmacro (shk) (hash (cat "sht" (hs) cr sr)))
(defmacro (cak) (hash (cat "cat" cr sr (ms))))
(defmacro (sak) (hash (cat "sat" cr sr (ms))))
(defmacro (cfk) (hash (cat "cfk" (chk))))
(defmacro (sfk) (hash (cat "sfk" (shk))))

(defmacro (cert n k)
  (cat n k (enc "cert" n k (privk ca))))

(defmacro (chello) (cat cr (gx)))
(defmacro (shello) (cat sr (gy)))
(defmacro (scert) (cert s spk))
(defmacro (ccert) (cert c cpk))

(defmacro (t1) (cat (chello) (shello) (scert)))
(defmacro (scv) (enc (hash (cat "scv" (t1))) (invk spk)))
(defmacro (t2) (cat (t1) (scv)))
(defmacro (sfin) (hash (cat "sfin" (sfk) (t2))))
(defmacro (t3) (cat (t2) (sfin) (ccert)))
(defmacro (ccv) (enc (hash (cat "ccv" (t3))) (invk cpk)))
(defmacro (t4) (cat (t3) (ccv)))
(defmacro (cfin) (hash (cat "cfin" (cfk) (t4))))

(defmacro (msg1) (chello))
(defmacro (msg2) (cat (shello) (enc (scert) (scv) (sfin) (shk))))
(defmacro (msg3) (enc (ccert) (ccv) (cfin) (chk)))
(defmacro (msg4) (enc request (cak)))
(defmacro (msg5) (enc response (sak)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (msg1))
      (recv (msg2))
      (send (msg3))
      (send (msg4))
      (recv (msg5)))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (msg1))
      (send (msg2))
      (recv (msg3))
      (recv (msg4))
      (send (msg5)))
    (uniq-gen y)))
