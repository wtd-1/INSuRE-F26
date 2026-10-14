(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (gx v) (exp (gen) v))
(defmacro (cert n k) (cat n k (enc (cat "cert" n k) (privk ca))))
(defmacro (hs z) (hash (cat "hs" z)))
(defmacro (chk z) (hash (cat (hs z) "chs" cr sr)))
(defmacro (shk z) (hash (cat (hs z) "shs" cr sr)))
(defmacro (ms z) (hash (cat "ms" (hs z))))
(defmacro (cak z) (hash (cat "cap" cr sr (ms z))))
(defmacro (sak z) (hash (cat "sap" cr sr (ms z))))
(defmacro (fk k) (hash (cat "fin" k)))
(defmacro (tr1 gxv gyv) (cat cr gxv sr gyv (cert s spk)))
(defmacro (scv gxv gyv) (enc (hash (tr1 gxv gyv)) (invk spk)))
(defmacro (tr2 gxv gyv) (cat (tr1 gxv gyv) (scv gxv gyv)))
(defmacro (sfin gxv gyv z)
  (hash (cat (fk (shk z)) (tr2 gxv gyv))))
(defmacro (tr3 gxv gyv z)
  (cat (tr2 gxv gyv) (sfin gxv gyv z) (cert c cpk)))
(defmacro (cfin gxv gyv z)
  (hash (cat (fk (chk z)) (tr3 gxv gyv z))))
(defmacro (msg1 gxv) (cat cr gxv))
(defmacro (msg2 gxv gyv z)
  (cat sr gyv
       (enc (cert s spk) (scv gxv gyv) (sfin gxv gyv z) (shk z))))
(defmacro (msg3 gxv gyv z)
  (enc (cert c cpk) (cfin gxv gyv z) (chk z)))
(defmacro (msg4 z) (enc request (cak z)))
(defmacro (msg5 z) (enc response (sak z)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (msg1 (gx x)))
     (recv (msg2 (gx x) (gx y) (exp (gx y) x)))
     (send (msg3 (gx x) (gx y) (exp (gx y) x)))
     (send (msg4 (exp (gx y) x)))
     (recv (msg5 (exp (gx y) x))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (msg1 (gx x)))
     (send (msg2 (gx x) (gx y) (exp (gx x) y)))
     (recv (msg3 (gx x) (gx y) (exp (gx x) y)))
     (recv (msg4 (exp (gx x) y)))
     (send (msg5 (exp (gx x) y))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
