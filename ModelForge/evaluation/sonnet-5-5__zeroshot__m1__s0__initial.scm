(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (hello cr gx sr gy) (cat cr gx sr gy))

(defmacro (shts ss cr sr) (hash "shts" (hash "hs" ss) cr sr))
(defmacro (chts ss cr sr) (hash "chts" (hash "hs" ss) cr sr))
(defmacro (sats ss cr sr) (hash "sats" cr sr (hash "ms" (hash "hs" ss))))
(defmacro (cats ss cr sr) (hash "cats" cr sr (hash "ms" (hash "hs" ss))))

(defmacro (cert n k ca) (enc "cert" n k (privk ca)))

(defmacro (fin key label tr) (hash (hash "fk" key) label tr))

(defmacro (t2 h s spk ca) (cat h (cert s spk ca)))

(defmacro (sfin sk h s spk ca)
  (fin sk "sfin" (t2 h s spk ca)))

(defmacro (t4 sk h s spk ca c cpk)
  (cat (t2 h s spk ca) (sfin sk h s spk ca) (cert c cpk ca)))

(defmacro (cvf sk h s spk ca c cpk)
  (enc (hash "cv" (t4 sk h s spk ca c cpk)) (invk cpk)))

(defmacro (cfin ck sk h s spk ca c cpk)
  (fin ck "cfin" (cat (t4 sk h s spk ca c cpk) (cvf sk h s spk ca c cpk))))

(defmacro (m2 sr gy sk h s spk ca)
  (cat sr gy (enc (cert s spk ca) (sfin sk h s spk ca) sk)))

(defmacro (m3 ck sk h s spk ca c cpk)
  (enc (cert c cpk ca)
       (cvf sk h s spk ca c cpk)
       (cfin ck sk h s spk ca c cpk)
       ck))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (exp (gen) x)))
     (recv (m2 sr (exp (gen) y)
               (shts (exp (exp (gen) y) x) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca))
     (send (m3 (chts (exp (exp (gen) y) x) cr sr)
               (shts (exp (exp (gen) y) x) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca c cpk))
     (send (enc request (cats (exp (exp (gen) y) x) cr sr)))
     (recv (enc response (sats (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x)
    (uniq-orig cr request)
    (non-orig (invk cpk) (privk ca)))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (exp (gen) x)))
     (send (m2 sr (exp (gen) y)
               (shts (exp (exp (gen) x) y) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca))
     (recv (m3 (chts (exp (exp (gen) x) y) cr sr)
               (shts (exp (exp (gen) x) y) cr sr)
               (hello cr (exp (gen) x) sr (exp (gen) y))
               s spk ca c cpk))
     (recv (enc request (cats (exp (exp (gen) x) y) cr sr)))
     (send (enc response (sats (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)
    (uniq-orig sr)
    (non-orig (invk spk) (privk ca))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
