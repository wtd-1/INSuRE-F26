```lisp
(defmacro (cert n k ca)
  (cat n k (enc "cert" n k (invk (pubk ca)))))

(defmacro (hsec dh) (hash "hs" dh))
(defmacro (msec dh) (hash "ms" (hsec dh)))
(defmacro (chk dh cr sr) (hash "chk" (hsec dh) cr sr))
(defmacro (shk dh cr sr) (hash "shk" (hsec dh) cr sr))
(defmacro (cak dh cr sr) (hash "cak" cr sr (msec dh)))
(defmacro (sak dh cr sr) (hash "sak" cr sr (msec dh)))

(defmacro (fin k tr) (hash (hash "fk" k) tr))

(defmacro (t1 cr gx sr gy s spk ca)
  (cat cr gx sr gy (cert s spk ca)))

(defmacro (scv cr gx sr gy s spk ca)
  (enc "scv" (hash (t1 cr gx sr gy s spk ca)) (invk spk)))

(defmacro (t2 cr gx sr gy s spk ca)
  (cat (t1 cr gx sr gy s spk ca) (scv cr gx sr gy s spk ca)))

(defmacro (sfin cr gx sr gy s spk ca dh)
  (fin (shk dh cr sr) (t2 cr gx sr gy s spk ca)))

(defmacro (smsg cr gx sr gy s spk ca dh)
  (enc (cert s spk ca)
       (scv cr gx sr gy s spk ca)
       (sfin cr gx sr gy s spk ca dh)
       (shk dh cr sr)))

(defmacro (t3 cr gx sr gy s spk ca dh c cpk)
  (cat (t2 cr gx sr gy s spk ca)
       (sfin cr gx sr gy s spk ca dh)
       (cert c cpk ca)))

(defmacro (ccv cr gx sr gy s spk ca dh c cpk)
  (enc "ccv" (hash (t3 cr gx sr gy s spk ca dh c cpk)) (invk cpk)))

(defmacro (cfin cr gx sr gy s spk ca dh c cpk)
  (fin (chk dh cr sr)
       (cat (t3 cr gx sr gy s spk ca dh c cpk)
            (ccv cr gx sr gy s spk ca dh c cpk))))

(defmacro (cmsg cr gx sr gy s spk ca dh c cpk)
  (enc (cert c cpk ca)
       (ccv cr gx sr gy s spk ca dh c cpk)
       (cfin cr gx sr gy s spk ca dh c cpk)
       (chk dh cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (exp (gen) x)))
     (recv (cat sr (exp (gen) y)
                (smsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                      (exp (exp (gen) y) x))))
     (send (cmsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                 (exp (exp (gen) y) x) c cpk))
     (send (enc "req" request (cak (exp (exp (gen) y) x) cr sr)))
     (recv (enc "resp" response (sak (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (exp (gen) x)))
     (send (cat sr (exp (gen) y)
                (smsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                      (exp (exp (gen) x) y))))
     (recv (cmsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                 (exp (exp (gen) x) y) c cpk))
     (recv (enc "req" request (cak (exp (exp (gen) x) y) cr sr)))
     (send (enc "resp" response (sak (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)))
```