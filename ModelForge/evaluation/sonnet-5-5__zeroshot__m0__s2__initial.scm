(herald "ModelForge-style generated model" (bound 30) (algebra diffie-hellman))

(defmacro (cert n k ca)
  (cat n k (enc "cert" n k (invk (pubk ca)))))

(defmacro (hsec dh) (hash "hs" dh))
(defmacro (msec dh) (hash "ms" (hsec dh)))
(defmacro (chk dh cr sr) (hash "chk" (hsec dh) cr sr))
(defmacro (shk dh cr sr) (hash "shk" (hsec dh) cr sr))
(defmacro (cak dh cr sr) (hash "cak" cr sr (msec dh)))
(defmacro (sak dh cr sr) (hash "sak" cr sr (msec dh)))

(defmacro (fin k tr) (hash (hash "fk" k) tr))

(defmacro (t1 cr gx sr gy s spk ca)
  (cat cr gx sr gy (cert s spk ca)))

(defmacro (scv cr gx sr gy s spk ca)
  (enc "scv" (hash (t1 cr gx sr gy s spk ca)) (invk spk)))

(defmacro (t2 cr gx sr gy s spk ca)
  (cat (t1 cr gx sr gy s spk ca) (scv cr gx sr gy s spk ca)))

(defmacro (sfin cr gx sr gy s spk ca dh)
  (fin (shk dh cr sr) (t2 cr gx sr gy s spk ca)))

(defmacro (smsg cr gx sr gy s spk ca dh)
  (enc (cert s spk ca)
       (scv cr gx sr gy s spk ca)
       (sfin cr gx sr gy s spk ca dh)
       (shk dh cr sr)))

(defmacro (t3 cr gx sr gy s spk ca dh c cpk)
  (cat (t2 cr gx sr gy s spk ca)
       (sfin cr gx sr gy s spk ca dh)
       (cert c cpk ca)))

(defmacro (ccv cr gx sr gy s spk ca dh c cpk)
  (enc "ccv" (hash (t3 cr gx sr gy s spk ca dh c cpk)) (invk cpk)))

(defmacro (cfin cr gx sr gy s spk ca dh c cpk)
  (fin (chk dh cr sr)
       (cat (t3 cr gx sr gy s spk ca dh c cpk)
            (ccv cr gx sr gy s spk ca dh c cpk))))

(defmacro (cmsg cr gx sr gy s spk ca dh c cpk)
  (enc (cert c cpk ca)
       (ccv cr gx sr gy s spk ca dh c cpk)
       (cfin cr gx sr gy s spk ca dh c cpk)
       (chk dh cr sr)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
     (send (cat cr (exp (gen) x)))
     (recv (cat sr (exp (gen) y)
                (smsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                      (exp (exp (gen) y) x))))
     (send (cmsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                 (exp (exp (gen) y) x) c cpk))
     (send (enc "req" request (cak (exp (exp (gen) y) x) cr sr)))
     (recv (enc "resp" response (sak (exp (exp (gen) y) x) cr sr))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
     (recv (cat cr (exp (gen) x)))
     (send (cat sr (exp (gen) y)
                (smsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                      (exp (exp (gen) x) y))))
     (recv (cmsg cr (exp (gen) x) sr (exp (gen) y) s spk ca
                 (exp (exp (gen) x) y) c cpk))
     (recv (enc "req" request (cak (exp (exp (gen) x) y) cr sr)))
     (send (enc "resp" response (sak (exp (exp (gen) x) y) cr sr))))
    (uniq-gen y)))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr text) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr text) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr text) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
