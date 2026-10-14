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
