(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (cert n k ca)
  (cat n k (enc "cert" n k (privk ca))))

(defmacro (hk l z cr sr)
  (hash (hash "hs" z) l cr sr))

(defmacro (ak l z cr sr)
  (hash l cr sr (hash "ms" (hash "hs" z))))

(defmacro (fk k)
  (hash "fin" k))

(defmacro (ta cr gx sr gy s spk ca)
  (cat cr gx sr gy (cert s spk ca)))

(defmacro (scv cr gx sr gy s spk ca)
  (enc (hash "scv" (ta cr gx sr gy s spk ca)) (invk spk)))

(defmacro (tb cr gx sr gy s spk ca)
  (cat (ta cr gx sr gy s spk ca) (scv cr gx sr gy s spk ca)))

(defmacro (sfm cr gx sr gy s spk ca z)
  (hash "sf" (fk (hk "s" z cr sr)) (tb cr gx sr gy s spk ca)))

(defmacro (tc cr gx sr gy s spk ca z c cpk)
  (cat (tb cr gx sr gy s spk ca)
       (sfm cr gx sr gy s spk ca z)
       (cert c cpk ca)))

(defmacro (cfm cr gx sr gy s spk ca z c cpk)
  (hash "cf" (fk (hk "c" z cr sr)) (tc cr gx sr gy s spk ca z c cpk)))

(defmacro (m1 cr gx)
  (cat cr gx))

(defmacro (m2 cr gx sr gy s spk ca z)
  (cat sr gy
       (enc (cert s spk ca)
            (scv cr gx sr gy s spk ca)
            (sfm cr gx sr gy s spk ca z)
            (hk "s" z cr sr))))

(defmacro (m3 cr gx sr gy s spk ca z c cpk)
  (enc (cert c cpk ca)
       (cfm cr gx sr gy s spk ca z c cpk)
       (hk "c" z cr sr)))

(defmacro (m4 request z cr sr)
  (enc request (ak "c ap" z cr sr)))

(defmacro (m5 response z cr sr)
  (enc response (ak "s ap" z cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (m1 cr (exp (gen) x)))
     (recv (m2 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) y) x)))
     (send (m3 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) y) x) c cpk))
     (send (m4 request (exp (exp (gen) y) x) cr sr))
     (recv (m5 response (exp (exp (gen) y) x) cr sr)))
    (uniq-gen x)
    (uniq-orig cr))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (m1 cr (exp (gen) x)))
     (send (m2 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) x) y)))
     (recv (m3 cr (exp (gen) x) sr (exp (gen) y) s spk ca
               (exp (exp (gen) x) y) c cpk))
     (recv (m4 request (exp (exp (gen) x) y) cr sr))
     (send (m5 response (exp (exp (gen) x) y) cr sr)))
    (uniq-gen y)
    (uniq-orig sr)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
