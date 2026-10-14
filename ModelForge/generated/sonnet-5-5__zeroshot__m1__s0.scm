(defmacro (hello cr gx sr gy) (cat cr gx sr gy))

(defmacro (shts ss cr sr) (hash "shts" (hash "hs" ss) cr sr))
(defmacro (chts ss cr sr) (hash "chts" (hash "hs" ss) cr sr))
(defmacro (sats ss cr sr) (hash "sats" cr sr (hash "ms" (hash "hs" ss))))
(defmacro (cats ss cr sr) (hash "cats" cr sr (hash "ms" (hash "hs" ss))))

(defmacro (cert n k ca) (enc "cert" n k (privk ca)))

(defmacro (fin key label tr) (hash (hash "fk" key) label tr))

(defmacro (t2 h s spk ca) (cat h (cert s spk ca)))

(defmacro (sfin sk h s spk ca)
  (fin sk "sfin" (t2 h s spk ca)))

(defmacro (t4 sk h s spk ca c cpk)
  (cat (t2 h s spk ca) (sfin sk h s spk ca) (cert c cpk ca)))

(defmacro (cvf sk h s spk ca c cpk)
  (enc (hash "cv" (t4 sk h s spk ca c cpk)) (invk cpk)))

(defmacro (cfin ck sk h s spk ca c cpk)
  (fin ck "cfin" (cat (t4 sk h s spk ca c cpk) (cvf sk h s spk ca c cpk))))

(defmacro (m2 sr gy sk h s spk ca)
  (cat sr gy (enc (cert s spk ca) (sfin sk h s spk ca) sk)))

(defmacro (m3 ck sk h s spk ca c cpk)
  (enc (cert c cpk ca)
       (cvf sk h s spk ca c cpk)
       (cfin ck sk h s spk ca c cpk)
       ck))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (exp (gen) x)))
     (recv (m2 sr (exp (gen) y)
               (shts (exp (exp (gen) y) x) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca))
     (send (m3 (chts (exp (exp (gen) y) x) cr sr)
               (shts (exp (exp (gen) y) x) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca c cpk))
     (send (enc request (cats (exp (exp (gen) y) x) cr sr)))
     (recv (enc response (sats (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x)
    (uniq-orig cr request)
    (non-orig (invk cpk) (privk ca)))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (exp (gen) x)))
     (send (m2 sr (exp (gen) y)
               (shts (exp (exp (gen) x) y) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca))
     (recv (m3 (chts (exp (exp (gen) x) y) cr sr)
               (shts (exp (exp (gen) x) y) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca c cpk))
     (recv (enc request (cats (exp (exp (gen) x) y) cr sr)))
     (send (enc response (sats (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)
    (uniq-orig sr)
    (non-orig (invk spk) (privk ca))))
