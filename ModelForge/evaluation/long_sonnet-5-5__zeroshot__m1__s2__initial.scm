(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (ch cr x) (cat cr (exp (gen) x)))
(defmacro (sh sr y) (cat sr (exp (gen) y)))
(defmacro (cert n k ca) (cat n k (enc "cert" n k (privk ca))))

(defmacro (hs dh) (hash "hs" dh))
(defmacro (ms dh) (hash "ms" (hs dh)))
(defmacro (hk lbl dh cr sr) (hash lbl (hs dh) cr sr))
(defmacro (ak lbl dh cr sr) (hash lbl cr sr (ms dh)))
(defmacro (fin k tr) (hash "mac" (hash "fin" k) tr))

(defmacro (tr2 cr x sr y s spk ca)
  (cat (ch cr x) (sh sr y) (cert s spk ca)))

(defmacro (tr3 cr x sr y s spk ca c cpk)
  (cat (tr2 cr x sr y s spk ca) (cert c cpk ca)))

(defmacro (ccv cr x sr y s spk ca c cpk)
  (enc (hash (tr3 cr x sr y s spk ca c cpk)) (invk cpk)))

(defmacro (tr4 cr x sr y s spk ca c cpk)
  (cat (tr3 cr x sr y s spk ca c cpk)
       (ccv cr x sr y s spk ca c cpk)))

(defmacro (msg2 cr x sr y s spk ca dh)
  (cat (sh sr y)
       (enc (cert s spk ca)
            (fin (hk "shtk" dh cr sr) (tr2 cr x sr y s spk ca))
            (hk "shtk" dh cr sr))))

(defmacro (msg3 cr x sr y s spk ca c cpk dh)
  (enc (cert c cpk ca)
       (ccv cr x sr y s spk ca c cpk)
       (fin (hk "chtk" dh cr sr) (tr4 cr x sr y s spk ca c cpk))
       (hk "chtk" dh cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (ch cr x))
      (recv (msg2 cr x sr y s spk ca (exp (exp (gen) y) x)))
      (send (msg3 cr x sr y s spk ca c cpk (exp (exp (gen) y) x)))
      (send (enc request (ak "capp" (exp (exp (gen) y) x) cr sr)))
      (recv (enc response (ak "sapp" (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x)
    (uniq-orig cr request)
    (non-orig (invk cpk) (privk ca)))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (ch cr x))
      (send (msg2 cr x sr y s spk ca (exp (exp (gen) x) y)))
      (recv (msg3 cr x sr y s spk ca c cpk (exp (exp (gen) x) y)))
      (recv (enc request (ak "capp" (exp (exp (gen) x) y) cr sr)))
      (send (enc response (ak "sapp" (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)
    (uniq-orig sr response)
    (non-orig (privk ca))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
