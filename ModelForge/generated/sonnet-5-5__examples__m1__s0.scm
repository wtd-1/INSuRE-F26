(defmacro (gx e) (exp (gen) e))

(defmacro (cert n k ca)
  (cat n k (enc "cert" n k (privk ca))))

(defmacro (hsec z) (hash (cat "hs" z)))

(defmacro (msec z) (hash (cat "ms" (hsec z))))

(defmacro (hk lbl z cr sr)
  (hash (cat lbl (hsec z) cr sr)))

(defmacro (ak lbl z cr sr)
  (hash (cat lbl cr sr (msec z))))

(defmacro (fin k tr)
  (hash (cat "fin" (hash (cat "fk" k)) tr)))

(defmacro (th1 cr sr x y s spk ca)
  (cat cr (gx x) sr (gx y) (cert s spk ca)))

(defmacro (sfin z cr sr x y s spk ca)
  (fin (hk "shs" z cr sr) (th1 cr sr x y s spk ca)))

(defmacro (th2 z cr sr x y s spk ca)
  (cat (th1 cr sr x y s spk ca) (sfin z cr sr x y s spk ca)))

(defmacro (th3 z cr sr x y s spk ca c cpk)
  (cat (th2 z cr sr x y s spk ca) (cert c cpk ca)))

(defmacro (ccv z cr sr x y s spk ca c cpk)
  (enc "cv" (th3 z cr sr x y s spk ca c cpk) (invk cpk)))

(defmacro (cfin z cr sr x y s spk ca c cpk)
  (fin (hk "chs" z cr sr)
       (cat (th3 z cr sr x y s spk ca c cpk)
            (ccv z cr sr x y s spk ca c cpk))))

(defmacro (msg1 cr x)
  (cat cr (gx x)))

(defmacro (msg2 z cr sr x y s spk ca)
  (cat sr (gx y)
       (enc (cert s spk ca)
            (sfin z cr sr x y s spk ca)
            (hk "shs" z cr sr))))

(defmacro (msg3 z cr sr x y s spk ca c cpk)
  (enc (cert c cpk ca)
       (ccv z cr sr x y s spk ca c cpk)
       (cfin z cr sr x y s spk ca c cpk)
       (hk "chs" z cr sr)))

(defmacro (msg4 z cr sr request)
  (enc "req" request (ak "cap" z cr sr)))

(defmacro (msg5 z cr sr response)
  (enc "resp" response (ak "sap" z cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (msg1 cr x))
     (recv (msg2 (exp (gx y) x) cr sr x y s spk ca))
     (send (msg3 (exp (gx y) x) cr sr x y s spk ca c cpk))
     (send (msg4 (exp (gx y) x) cr sr request))
     (recv (msg5 (exp (gx y) x) cr sr response)))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (msg1 cr x))
     (send (msg2 (exp (gx x) y) cr sr x y s spk ca))
     (recv (msg3 (exp (gx x) y) cr sr x y s spk ca c cpk))
     (recv (msg4 (exp (gx x) y) cr sr request))
     (send (msg5 (exp (gx x) y) cr sr response)))
    (uniq-gen y)))
