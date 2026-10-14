(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

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

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
