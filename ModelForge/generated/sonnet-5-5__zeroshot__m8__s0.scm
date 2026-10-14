(defmacro (cert n pk ca)
  (enc "cert" n pk (invk (pubk ca))))

(defmacro (tr1 cr sr gx gy s spk ca)
  (cat cr gx sr gy (cert s spk ca)))

(defmacro (sht z cr sr)
  (hash "sht" (hash "hs" z) cr sr))

(defmacro (cht z cr sr)
  (hash "cht" (hash "hs" z) cr sr))

(defmacro (sat z cr sr)
  (hash "sat" cr sr (hash "ms" (hash "hs" z))))

(defmacro (cat-key z cr sr)
  (hash "cat" cr sr (hash "ms" (hash "hs" z))))

(defmacro (sfin z cr sr gx gy s spk ca)
  (hash (hash "sfk" (sht z cr sr))
        (tr1 cr sr gx gy s spk ca)))

(defmacro (cfin z cr sr gx gy s spk ca n pk)
  (hash (hash "cfk" (cht z cr sr))
        (cat (tr1 cr sr gx gy s spk ca)
             (sfin z cr sr gx gy s spk ca)
             (cert n pk ca))))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (cat cr (exp (gen) x)))
      (recv (cat sr (exp (gen) y)
                 (enc (cert s spk ca)
                      (sfin (exp (exp (gen) y) x) cr sr
                            (exp (gen) x) (exp (gen) y) s spk ca)
                      (sht (exp (exp (gen) y) x) cr sr))))
      (send (enc (cert c cpk ca)
                 (cfin (exp (exp (gen) y) x) cr sr
                       (exp (gen) x) (exp (gen) y) s spk ca c cpk)
                 (cht (exp (exp (gen) y) x) cr sr)))
      (send (enc request (cat-key (exp (exp (gen) y) x) cr sr)))
      (recv (enc response (sat (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (cat cr (exp (gen) x)))
      (send (cat sr (exp (gen) y)
                 (enc (cert s spk ca)
                      (sfin (exp (exp (gen) x) y) cr sr
                            (exp (gen) x) (exp (gen) y) s spk ca)
                      (sht (exp (exp (gen) x) y) cr sr))))
      (recv (enc (cert c cpk ca)
                 (cfin (exp (exp (gen) x) y) cr sr
                       (exp (gen) x) (exp (gen) y) s spk ca c cpk)
                 (cht (exp (exp (gen) x) y) cr sr)))
      (recv (enc request (cat-key (exp (exp (gen) x) y) cr sr)))
      (send (enc response (sat (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)))
