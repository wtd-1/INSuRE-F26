(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (gx) (exp (gen) x))
(defmacro (gy) (exp (gen) y))
(defmacro (zc) (exp (exp (gen) y) x))
(defmacro (zs) (exp (exp (gen) x) y))

(defmacro (ch) (cat cr (gx)))
(defmacro (sh) (cat sr (gy)))

(defmacro (hsec z) (hash "hs" z))
(defmacro (msec z) (hash "ms" (hsec z)))
(defmacro (chts z) (hash "chts" (hsec z) cr sr))
(defmacro (shts z) (hash "shts" (hsec z) cr sr))
(defmacro (capp z) (hash "capp" cr sr (msec z)))
(defmacro (sapp z) (hash "sapp" cr sr (msec z)))
(defmacro (fk k) (hash "fin" k))

(defmacro (scert) (enc "cert" s spk (invk (pubk ca))))
(defmacro (ccert) (enc "cert" c cpk (invk (pubk ca))))

(defmacro (ts1) (cat (ch) (sh) (scert)))
(defmacro (scv) (enc "sig" (ts1) (invk spk)))
(defmacro (ts2) (cat (ts1) (scv)))
(defmacro (sfin z) (hash (fk (shts z)) (ts2)))

(defmacro (tc1 z) (cat (ch) (sh) (scert) (scv) (sfin z) (ccert)))
(defmacro (ccv z) (enc "sig" (tc1 z) (invk cpk)))
(defmacro (tc2 z) (cat (tc1 z) (ccv z)))
(defmacro (cfin z) (hash (fk (chts z)) (tc2 z)))

(defmacro (msg2 z)
  (cat (sh) (enc (scert) (scv) (sfin z) (shts z))))
(defmacro (msg3 z)
  (enc (ccert) (ccv z) (cfin z) (chts z)))
(defmacro (msg4 z) (enc request (capp z)))
(defmacro (msg5 z) (enc response (sapp z)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (ch))
      (recv (msg2 (zc)))
      (send (msg3 (zc)))
      (send (msg4 (zc)))
      (recv (msg5 (zc))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (ch))
      (send (msg2 (zs)))
      (recv (msg3 (zs)))
      (recv (msg4 (zs)))
      (send (msg5 (zs))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
