(defmacro (cert n k ca)
  (cat n k (enc n k (privk ca))))

(defmacro (sgn l k m)
  (enc (hash (cat l m)) (invk k)))

(defmacro (mac k m)
  (hash (cat "fin" (hash (cat "fk" k)) m)))

(defmacro (dhs x y)
  (exp (exp (gen) y) x))

(defmacro (hsec x y)
  (hash (cat "hs" (dhs x y))))

(defmacro (msec x y)
  (hash (cat "ms" (hsec x y))))

(defmacro (hk l x y cr sr)
  (hash (cat l (hsec x y) cr sr)))

(defmacro (ak l x y cr sr)
  (hash (cat l cr sr (msec x y))))

(defmacro (hl cr x sr y)
  (cat cr (exp (gen) x) sr (exp (gen) y)))

(defmacro (tr1 cr x sr y s spk ca)
  (cat (hl cr x sr y) (cert s spk ca)))

(defmacro (tr2 cr x sr y s spk ca)
  (cat (tr1 cr x sr y s spk ca)
       (sgn "scv" spk (tr1 cr x sr y s spk ca))))

(defmacro (tr3 cr x sr y s spk ca)
  (cat (tr2 cr x sr y s spk ca)
       (mac (hk "shts" x y cr sr) (tr2 cr x sr y s spk ca))))

(defmacro (tr4 cr x sr y s spk ca c cpk)
  (cat (tr3 cr x sr y s spk ca) (cert c cpk ca)))

(defmacro (tr5 cr x sr y s spk ca c cpk)
  (cat (tr4 cr x sr y s spk ca c cpk)
       (sgn "ccv" cpk (tr4 cr x sr y s spk ca c cpk))))

(defmacro (msg2 cr x sr y s spk ca)
  (enc (cert s spk ca)
       (sgn "scv" spk (tr1 cr x sr y s spk ca))
       (mac (hk "shts" x y cr sr) (tr2 cr x sr y s spk ca))
       (hk "shts" x y cr sr)))

(defmacro (msg3 cr x sr y s spk ca c cpk)
  (enc (cert c cpk ca)
       (sgn "ccv" cpk (tr4 cr x sr y s spk ca c cpk))
       (mac (hk "chts" x y cr sr) (tr5 cr x sr y s spk ca c cpk))
       (hk "chts" x y cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (exp (gen) x)))
     (recv (cat sr (exp (gen) y) (msg2 cr x sr y s spk ca)))
     (send (msg3 cr x sr y s spk ca c cpk))
     (send (enc request (ak "cats" x y cr sr)))
     (recv (enc response (ak "sats" x y cr sr))))
    (uniq-orig cr request)
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (exp (gen) x)))
     (send (cat sr (exp (gen) y) (msg2 cr x sr y s spk ca)))
     (recv (msg3 cr x sr y s spk ca c cpk))
     (recv (enc request (ak "cats" x y cr sr)))
     (send (enc response (ak "sats" x y cr sr))))
    (uniq-orig sr)
    (uniq-gen y)))
