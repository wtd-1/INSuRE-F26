(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (dhs a b) (exp (exp (gen) a) b))

(defmacro (hsec sec) (hash "hs" sec))

(defmacro (chk sec cr sr) (hash (cat "chs" (hsec sec) cr sr)))
(defmacro (shk sec cr sr) (hash (cat "shs" (hsec sec) cr sr)))

(defmacro (msec sec) (hash (cat "ms" (hsec sec))))

(defmacro (cak sec cr sr) (hash (cat "cap" (msec sec) cr sr)))
(defmacro (sak sec cr sr) (hash (cat "sap" (msec sec) cr sr)))

(defmacro (cfk sec cr sr) (hash (cat "cfin" (chk sec cr sr))))
(defmacro (sfk sec cr sr) (hash (cat "sfin" (shk sec cr sr))))

(defmacro (chello cr x) (cat cr (exp (gen) x)))
(defmacro (shello sr y) (cat sr (exp (gen) y)))

(defmacro (scert s spk ca) (cat s spk (enc s spk (privk ca))))
(defmacro (ccert c cpk ca) (cat c cpk (enc c cpk (privk ca))))

(defmacro (tr1 cr sr x y s spk ca)
  (cat (chello cr x) (shello sr y) (scert s spk ca)))

(defmacro (sfin sec cr sr x y s spk ca)
  (hash (cat (sfk sec cr sr) (tr1 cr sr x y s spk ca))))

(defmacro (tr2 sec cr sr x y s spk c cpk ca)
  (cat (tr1 cr sr x y s spk ca)
       (sfin sec cr sr x y s spk ca)
       (ccert c cpk ca)))

(defmacro (ccv sec cr sr x y s spk c cpk ca)
  (enc (hash (tr2 sec cr sr x y s spk c cpk ca)) (invk cpk)))

(defmacro (cfin sec cr sr x y s spk c cpk ca)
  (hash (cat (cfk sec cr sr)
             (tr2 sec cr sr x y s spk c cpk ca)
             (ccv sec cr sr x y s spk c cpk ca))))

(defmacro (msg2 sec cr sr x y s spk ca)
  (cat (shello sr y)
       (enc (scert s spk ca)
            (sfin sec cr sr x y s spk ca)
            (shk sec cr sr))))

(defmacro (msg3 sec cr sr x y s spk c cpk ca)
  (enc (ccert c cpk ca)
       (ccv sec cr sr x y s spk c cpk ca)
       (cfin sec cr sr x y s spk c cpk ca)
       (chk sec cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (chello cr x))
     (recv (msg2 (dhs y x) cr sr x y s spk ca))
     (send (msg3 (dhs y x) cr sr x y s spk c cpk ca))
     (send (enc request (cak (dhs y x) cr sr)))
     (recv (enc response (sak (dhs y x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (chello cr x))
     (send (msg2 (dhs x y) cr sr x y s spk ca))
     (recv (msg3 (dhs x y) cr sr x y s spk c cpk ca))
     (recv (enc request (cak (dhs x y) cr sr)))
     (send (enc response (sak (dhs x y) cr sr))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
