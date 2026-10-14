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
