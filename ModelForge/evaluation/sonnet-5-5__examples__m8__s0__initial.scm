(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (hello1) (cat cr (exp (gen) x)))
(defmacro (hello2) (cat sr (exp (gen) y)))
(defmacro (cert n k ca) (cat n k (enc n k (privk ca))))
(defmacro (scert) (cert s spk ca))
(defmacro (ccert) (cert c cpk ca))

(defmacro (hsec z) (hash "handshake" z))
(defmacro (chk z) (hash "c hs traffic" (hsec z) cr sr))
(defmacro (shk z) (hash "s hs traffic" (hsec z) cr sr))
(defmacro (msec z) (hash "master" (hsec z)))
(defmacro (cak z) (hash "c ap traffic" cr sr (msec z)))
(defmacro (sak z) (hash "s ap traffic" cr sr (msec z)))
(defmacro (fkey k) (hash "finished" k))

(defmacro (sfin z)
  (hash (fkey (shk z)) (hello1) (hello2) (scert)))
(defmacro (cfin z)
  (hash (fkey (chk z)) (hello1) (hello2) (scert) (sfin z) (ccert)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (hello1))
     (recv (cat (hello2)
                (enc (scert) (sfin (exp (exp (gen) y) x))
                     (shk (exp (exp (gen) y) x)))))
     (send (enc (ccert) (cfin (exp (exp (gen) y) x))
                (chk (exp (exp (gen) y) x))))
     (send (enc request (cak (exp (exp (gen) y) x))))
     (recv (enc response (sak (exp (exp (gen) y) x)))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (hello1))
     (send (cat (hello2)
                (enc (scert) (sfin (exp (exp (gen) x) y))
                     (shk (exp (exp (gen) x) y)))))
     (recv (enc (ccert) (cfin (exp (exp (gen) x) y))
                (chk (exp (exp (gen) x) y))))
     (recv (enc request (cak (exp (exp (gen) x) y))))
     (send (enc response (sak (exp (exp (gen) x) y)))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
