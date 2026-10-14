(defmacro (hs x y)
  (hash "hs" (exp (exp (gen) x) y)))

(defmacro (chk x y cr sr)
  (hash "chk" (hs x y) cr sr))

(defmacro (shk x y cr sr)
  (hash "shk" (hs x y) cr sr))

(defmacro (ms x y)
  (hash "ms" (hs x y)))

(defmacro (cak x y cr sr)
  (hash "cak" cr sr (ms x y)))

(defmacro (sak x y cr sr)
  (hash "sak" cr sr (ms x y)))

(defmacro (cert n k ca)
  (cat n k (enc "cert" n k (invk (pubk ca)))))

(defmacro (th1 cr sr x y)
  (cat cr (exp (gen) x) sr (exp (gen) y)))

(defmacro (th2 cr sr x y s spk ca)
  (cat (th1 cr sr x y) (cert s spk ca)))

(defmacro (scv cr sr x y s spk ca)
  (enc "scv" (hash (th2 cr sr x y s spk ca)) (invk spk)))

(defmacro (th3 cr sr x y s spk ca)
  (cat (th2 cr sr x y s spk ca) (scv cr sr x y s spk ca)))

(defmacro (sfin cr sr x y s spk ca)
  (hash "sfin" (hash "sfk" (shk x y cr sr))
        (th3 cr sr x y s spk ca)))

(defmacro (th4 cr sr x y s spk ca c cpk)
  (cat (th3 cr sr x y s spk ca)
       (sfin cr sr x y s spk ca)
       (cert c cpk ca)))

(defmacro (cfin cr sr x y s spk ca c cpk)
  (hash "cfin" (hash "cfk" (chk x y cr sr))
        (th4 cr sr x y s spk ca c cpk)))

(defmacro (flight2 cr sr x y s spk ca)
  (enc (cert s spk ca)
       (scv cr sr x y s spk ca)
       (sfin cr sr x y s spk ca)
       (shk x y cr sr)))

(defmacro (flight3 cr sr x y s spk ca c cpk)
  (enc (cert c cpk ca)
       (cfin cr sr x y s spk ca c cpk)
       (chk x y cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (exp (gen) x)))
     (recv (cat sr (exp (gen) y) (flight2 cr sr x y s spk ca)))
     (send (flight3 cr sr x y s spk ca c cpk))
     (send (enc request (cak x y cr sr)))
     (recv (enc response (sak x y cr sr))))
    (non-orig (invk (pubk ca)))
    (uniq-orig cr request)
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (exp (gen) x)))
     (send (cat sr (exp (gen) y) (flight2 cr sr x y s spk ca)))
     (recv (flight3 cr sr x y s spk ca c cpk))
     (recv (enc request (cak x y cr sr)))
     (send (enc response (sak x y cr sr))))
    (non-orig (invk (pubk ca)))
    (uniq-orig sr response)
    (uniq-gen y)))
