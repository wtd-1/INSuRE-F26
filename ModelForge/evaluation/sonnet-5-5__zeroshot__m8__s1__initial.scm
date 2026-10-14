(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (ch cr x) (cat cr (exp (gen) x)))
(defmacro (sh sr y) (cat sr (exp (gen) y)))
(defmacro (cert n k ca) (enc "cert" n k (invk ca)))

(defmacro (hsec z) (hash "hs" z))
(defmacro (msec z) (hash "ms" (hsec z)))
(defmacro (chk z cr sr) (hash "chk" (hsec z) cr sr))
(defmacro (shk z cr sr) (hash "shk" (hsec z) cr sr))
(defmacro (cak z cr sr) (hash "cak" cr sr (msec z)))
(defmacro (sak z cr sr) (hash "sak" cr sr (msec z)))
(defmacro (fin k tr) (hash (hash "fin" k) tr))

(defmacro (t1 cr x sr y s spk ca)
  (cat (ch cr x) (sh sr y) (cert s spk ca)))
(defmacro (sfin z cr x sr y s spk ca)
  (fin (shk z cr sr) (t1 cr x sr y s spk ca)))
(defmacro (t2 z cr x sr y s spk c cpk ca)
  (cat (t1 cr x sr y s spk ca)
       (sfin z cr x sr y s spk ca)
       (cert c cpk ca)))
(defmacro (cfin z cr x sr y s spk c cpk ca)
  (fin (chk z cr sr) (t2 z cr x sr y s spk c cpk ca)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (ch cr x))
      (recv (cat (sh sr y)
                 (enc (cert s spk ca)
                      (sfin (exp (exp (gen) y) x) cr x sr y s spk ca)
                      (shk (exp (exp (gen) y) x) cr sr))))
      (send (enc (cert c cpk ca)
                 (cfin (exp (exp (gen) y) x) cr x sr y s spk c cpk ca)
                 (chk (exp (exp (gen) y) x) cr sr)))
      (send (enc request (cak (exp (exp (gen) y) x) cr sr)))
      (recv (enc response (sak (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (ch cr x))
      (send (cat (sh sr y)
                 (enc (cert s spk ca)
                      (sfin (exp (exp (gen) x) y) cr x sr y s spk ca)
                      (shk (exp (exp (gen) x) y) cr sr))))
      (recv (enc (cert c cpk ca)
                 (cfin (exp (exp (gen) x) y) cr x sr y s spk c cpk ca)
                 (chk (exp (exp (gen) x) y) cr sr)))
      (recv (enc request (cak (exp (exp (gen) x) y) cr sr)))
      (send (enc response (sak (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
