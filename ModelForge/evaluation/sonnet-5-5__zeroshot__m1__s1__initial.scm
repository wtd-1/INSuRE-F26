(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (ch cr x) (cat cr (exp (gen) x)))
(defmacro (sh sr y) (cat sr (exp (gen) y)))
(defmacro (cert n k ca) (cat n k (enc "cert" n k (privk ca))))

(defmacro (hs x y) (hash "hs" (exp (exp (gen) x) y)))
(defmacro (ms x y) (hash "ms" (hs x y)))
(defmacro (chk cr sr x y) (hash "chs" (hs x y) cr sr))
(defmacro (shk cr sr x y) (hash "shs" (hs x y) cr sr))
(defmacro (cak cr sr x y) (hash "cas" cr sr (ms x y)))
(defmacro (sak cr sr x y) (hash "sas" cr sr (ms x y)))

(defmacro (sfin cr sr x y s spk ca)
  (hash (hash "sfin" (shk cr sr x y))
        (cat (ch cr x) (sh sr y) (cert s spk ca))))

(defmacro (tr2 cr sr x y s spk c cpk ca)
  (cat (ch cr x) (sh sr y) (cert s spk ca)
       (sfin cr sr x y s spk ca) (cert c cpk ca)))

(defmacro (ccv cr sr x y s spk c cpk ca)
  (enc (hash (tr2 cr sr x y s spk c cpk ca)) (invk cpk)))

(defmacro (cfin cr sr x y s spk c cpk ca)
  (hash (hash "cfin" (chk cr sr x y))
        (cat (tr2 cr sr x y s spk c cpk ca)
             (ccv cr sr x y s spk c cpk ca))))

(defmacro (m2 cr sr x y s spk ca)
  (cat (sh sr y)
       (enc (cert s spk ca) (sfin cr sr x y s spk ca) (shk cr sr x y))))

(defmacro (m3 cr sr x y s spk c cpk ca)
  (enc (cert c cpk ca)
       (ccv cr sr x y s spk c cpk ca)
       (cfin cr sr x y s spk c cpk ca)
       (chk cr sr x y)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr request response text)
          (spk cpk akey) (x rndx) (y expt))
    (trace
      (send (ch cr x))
      (recv (m2 cr sr x y s spk ca))
      (send (m3 cr sr x y s spk c cpk ca))
      (send (enc request (cak cr sr x y)))
      (recv (enc response (sak cr sr x y))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr request response text)
          (spk cpk akey) (y rndx) (x expt))
    (trace
      (recv (ch cr x))
      (send (m2 cr sr x y s spk ca))
      (recv (m3 cr sr x y s spk c cpk ca))
      (recv (enc request (cak cr sr x y)))
      (send (enc response (sak cr sr x y))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
