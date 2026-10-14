(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (ch) (cat cr (exp (gen) x)))
(defmacro (sh) (cat sr (exp (gen) y)))
(defmacro (scert) (cat s spk (enc (cat s spk) (privk ca))))
(defmacro (ccert) (cat c cpk (enc (cat c cpk) (privk ca))))

(defmacro (dhs) (exp (gen) (mul x y)))
(defmacro (hs) (hash (cat "hs" (dhs))))
(defmacro (chts) (hash (cat "chts" (hs) cr sr)))
(defmacro (shts) (hash (cat "shts" (hs) cr sr)))
(defmacro (ms) (hash (cat "ms" (hs))))
(defmacro (cats) (hash (cat "cats" cr sr (ms))))
(defmacro (sats) (hash (cat "sats" cr sr (ms))))
(defmacro (cfk) (hash (cat "cfin" (chts))))
(defmacro (sfk) (hash (cat "sfin" (shts))))

(defmacro (t1) (cat (ch) (sh) (scert)))
(defmacro (scv) (enc (hash (t1)) (invk spk)))
(defmacro (t2) (cat (t1) (scv)))
(defmacro (sfin) (hash (cat (sfk) (t2))))
(defmacro (t3) (cat (t2) (sfin) (ccert)))
(defmacro (ccv) (enc (hash (t3)) (invk cpk)))
(defmacro (t4) (cat (t3) (ccv)))
(defmacro (cfin) (hash (cat (cfk) (t4))))

(defmacro (msg1) (ch))
(defmacro (msg2) (cat (sh) (enc (scert) (scv) (sfin) (shts))))
(defmacro (msg3) (enc (ccert) (ccv) (cfin) (chts)))
(defmacro (msg4) (enc request (cats)))
(defmacro (msg5) (enc response (sats)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (msg1))
     (recv (msg2))
     (send (msg3))
     (send (msg4))
     (recv (msg5)))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (msg1))
     (send (msg2))
     (recv (msg3))
     (recv (msg4))
     (send (msg5)))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
