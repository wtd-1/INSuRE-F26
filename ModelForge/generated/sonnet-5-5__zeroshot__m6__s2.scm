(defmacro (cert n k ca)
  (cat n k (enc "cert" n k (privk ca))))

(defmacro (hk l z cr sr)
  (hash (hash "hs" z) l cr sr))

(defmacro (ak l z cr sr)
  (hash l cr sr (hash "ms" (hash "hs" z))))

(defmacro (fk k)
  (hash "fin" k))

(defmacro (ta cr gx sr gy s spk ca)
  (cat cr gx sr gy (cert s spk ca)))

(defmacro (scv cr gx sr gy s spk ca)
  (enc (hash "scv" (ta cr gx sr gy s spk ca)) (invk spk)))

(defmacro (tb cr gx sr gy s spk ca)
  (cat (ta cr gx sr gy s spk ca) (scv cr gx sr gy s spk ca)))

(defmacro (sfm cr gx sr gy s spk ca z)
  (hash "sf" (fk (hk "s" z cr sr)) (tb cr gx sr gy s spk ca)))

(defmacro (tc cr gx sr gy s spk ca z c cpk)
  (cat (tb cr gx sr gy s spk ca)
       (sfm cr gx sr gy s spk ca z)
       (cert c cpk ca)))

(defmacro (cfm cr gx sr gy s spk ca z c cpk)
  (hash "cf" (fk (hk "c" z cr sr)) (tc cr gx sr gy s spk ca z c cpk)))

(defmacro (m1 cr gx)
  (cat cr gx))

(defmacro (m2 cr gx sr gy s spk ca z)
  (cat sr gy
       (enc (cert s spk ca)
            (scv cr gx sr gy s spk ca)
            (sfm cr gx sr gy s spk ca z)
            (hk "s" z cr sr))))

(defmacro (m3 cr gx sr gy s spk ca z c cpk)
  (enc (cert c cpk ca)
       (cfm cr gx sr gy s spk ca z c cpk)
       (hk "c" z cr sr)))

(defmacro (m4 request z cr sr)
  (enc request (ak "c ap" z cr sr)))

(defmacro (m5 response z cr sr)
  (enc response (ak "s ap" z cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (m1 cr (exp (gen) x)))
     (recv (m2 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) y) x)))
     (send (m3 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) y) x) c cpk))
     (send (m4 request (exp (exp (gen) y) x) cr sr))
     (recv (m5 response (exp (exp (gen) y) x) cr sr)))
    (uniq-gen x)
    (uniq-orig cr))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (m1 cr (exp (gen) x)))
     (send (m2 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) x) y)))
     (recv (m3 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) x) y) c cpk))
     (recv (m4 request (exp (exp (gen) x) y) cr sr))
     (send (m5 response (exp (exp (gen) x) y) cr sr)))
    (uniq-gen y)
    (uniq-orig sr)))
