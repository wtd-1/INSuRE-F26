(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

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

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
