(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (hello r e) (cat r (exp (gen) e)))
(defmacro (cert n k ca) (enc n k (privk ca)))
(defmacro (hsec z) (hash "hs" z))
(defmacro (chk z cr sr) (hash (hsec z) "c hs" cr sr))
(defmacro (shk z cr sr) (hash (hsec z) "s hs" cr sr))
(defmacro (msec z) (hash "ms" (hsec z)))
(defmacro (cak z cr sr) (hash "c ap" cr sr (msec z)))
(defmacro (sak z cr sr) (hash "s ap" cr sr (msec z)))
(defmacro (t1 cr sr x y s spk ca)
  (cat (hello cr x) (hello sr y) (cert s spk ca)))
(defmacro (sfin z cr sr x y s spk ca)
  (hash (hash "finished" (shk z cr sr)) (t1 cr sr x y s spk ca)))
(defmacro (t2 z cr sr x y s spk ca c cpk)
  (cat (t1 cr sr x y s spk ca)
       (sfin z cr sr x y s spk ca)
       (cert c cpk ca)))
(defmacro (cfin z cr sr x y s spk ca c cpk)
  (hash (hash "finished" (chk z cr sr))
        (t2 z cr sr x y s spk ca c cpk)))
(defmacro (sflight z cr sr x y s spk ca)
  (enc (cert s spk ca)
       (sfin z cr sr x y s spk ca)
       (shk z cr sr)))
(defmacro (cflight z cr sr x y s spk ca c cpk)
  (enc (cert c cpk ca)
       (cfin z cr sr x y s spk ca c cpk)
       (chk z cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (hello cr x))
     (recv (cat (hello sr y)
                (sflight (exp (exp (gen) y) x) cr sr x y s spk ca)))
     (send (cflight (exp (exp (gen) y) x) cr sr x y s spk ca c cpk))
     (send (enc request (cak (exp (exp (gen) y) x) cr sr)))
     (recv (enc response (sak (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (hello cr x))
     (send (cat (hello sr y)
                (sflight (exp (exp (gen) x) y) cr sr x y s spk ca)))
     (recv (cflight (exp (exp (gen) x) y) cr sr x y s spk ca c cpk))
     (recv (enc request (cak (exp (exp (gen) x) y) cr sr)))
     (send (enc response (sak (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
