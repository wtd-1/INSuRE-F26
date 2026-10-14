```scheme
(defmacro (ch cr gx) (cat cr gx))
(defmacro (sh sr gy) (cat sr gy))
(defmacro (cert n k ca) (cat n k (enc n k (privk ca))))

(defmacro (hsec z) (hash (cat "hs" z)))
(defmacro (msec z) (hash (cat "ms" (hsec z))))
(defmacro (chk z cr sr) (hash (cat "c hs traffic" (hsec z) cr sr)))
(defmacro (shk z cr sr) (hash (cat "s hs traffic" (hsec z) cr sr)))
(defmacro (cak z cr sr) (hash (cat "c ap traffic" cr sr (msec z))))
(defmacro (sak z cr sr) (hash (cat "s ap traffic" cr sr (msec z))))

(defmacro (fin k tr) (hash (cat "finished" (hash (cat "fk" k)) tr)))

(defmacro (tr1 cr gx sr gy s spk ca)
  (cat (ch cr gx) (sh sr gy) (cert s spk ca)))

(defmacro (sfin z cr gx sr gy s spk ca)
  (fin (shk z cr sr) (tr1 cr gx sr gy s spk ca)))

(defmacro (tr2 z cr gx sr gy s spk ca c cpk)
  (cat (tr1 cr gx sr gy s spk ca)
       (sfin z cr gx sr gy s spk ca)
       (cert c cpk ca)))

(defmacro (cv z cr gx sr gy s spk ca c cpk)
  (enc (hash (tr2 z cr gx sr gy s spk ca c cpk)) (invk cpk)))

(defmacro (cfin z cr gx sr gy s spk ca c cpk)
  (fin (chk z cr sr)
       (cat (tr2 z cr gx sr gy s spk ca c cpk)
            (cv z cr gx sr gy s spk ca c cpk))))

(defmacro (msg2 z cr gx sr gy s spk ca)
  (cat (sh sr gy)
       (enc (cert s spk ca)
            (sfin z cr gx sr gy s spk ca)
            (shk z cr sr))))

(defmacro (msg3 z cr gx sr gy s spk ca c cpk)
  (enc (cert c cpk ca)
       (cv z cr gx sr gy s spk ca c cpk)
       (cfin z cr gx sr gy s spk ca c cpk)
       (chk z cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (ch cr (exp (gen) x)))
     (recv (msg2 (exp (exp (gen) y) x) cr (exp (gen) x)
                 sr (exp (gen) y) s spk ca))
     (send (msg3 (exp (exp (gen) y) x) cr (exp (gen) x)
                 sr (exp (gen) y) s spk ca c cpk))
     (send (enc request (cak (exp (exp (gen) y) x) cr sr)))
     (recv (enc response (sak (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (ch cr (exp (gen) x)))
     (send (msg2 (exp (exp (gen) x) y) cr (exp (gen) x)
                 sr (exp (gen) y) s spk ca))
     (recv (msg3 (exp (exp (gen) x) y) cr (exp (gen) x)
                 sr (exp (gen) y) s spk ca c cpk))
     (recv (enc request (cak (exp (exp (gen) x) y) cr sr)))
     (send (enc response (sak (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)))
```