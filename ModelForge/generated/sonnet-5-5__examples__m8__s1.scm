(defmacro (pub e) (exp (gen) e))

(defmacro (hsec z) (hash (cat "hsec" z)))
(defmacro (msec z) (hash (cat "msec" (hsec z))))
(defmacro (chk z cr sr) (hash (cat "chts" (hsec z) cr sr)))
(defmacro (shk z cr sr) (hash (cat "shts" (hsec z) cr sr)))
(defmacro (cak z cr sr) (hash (cat "cats" cr sr (msec z))))
(defmacro (sak z cr sr) (hash (cat "sats" cr sr (msec z))))

(defmacro (cert n k ca) (cat n k (enc n k (privk ca))))

(defmacro (fin k tr) (hash (cat "finished" (hash (cat "fkey" k)) tr)))

(defmacro (th1 cr gx sr gy s spk ca)
  (cat cr gx sr gy (cert s spk ca)))

(defmacro (sfin z cr gx sr gy s spk ca)
  (fin (shk z cr sr) (th1 cr gx sr gy s spk ca)))

(defmacro (th2 z cr gx sr gy s spk ca c cpk)
  (cat (th1 cr gx sr gy s spk ca)
       (sfin z cr gx sr gy s spk ca)
       (cert c cpk ca)))

(defmacro (cfin z cr gx sr gy s spk ca c cpk)
  (fin (chk z cr sr) (th2 z cr gx sr gy s spk ca c cpk)))

(defmacro (msg2 z cr gx sr gy s spk ca)
  (cat sr gy
       (enc (cert s spk ca)
            (sfin z cr gx sr gy s spk ca)
            (shk z cr sr))))

(defmacro (msg3 z cr gx sr gy s spk ca c cpk)
  (enc (cert c cpk ca)
       (cfin z cr gx sr gy s spk ca c cpk)
       (chk z cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (pub x)))
     (recv (msg2 (exp (pub y) x) cr (pub x) sr (pub y) s spk ca))
     (send (msg3 (exp (pub y) x) cr (pub x) sr (pub y) s spk ca c cpk))
     (send (enc request (cak (exp (pub y) x) cr sr)))
     (recv (enc response (sak (exp (pub y) x) cr sr))))
    (uniq-gen x)
    (uniq-orig cr request))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (pub x)))
     (send (msg2 (exp (pub x) y) cr (pub x) sr (pub y) s spk ca))
     (recv (msg3 (exp (pub x) y) cr (pub x) sr (pub y) s spk ca c cpk))
     (recv (enc request (cak (exp (pub x) y) cr sr)))
     (send (enc response (sak (exp (pub x) y) cr sr))))
    (uniq-gen y)
    (uniq-orig sr response)))
