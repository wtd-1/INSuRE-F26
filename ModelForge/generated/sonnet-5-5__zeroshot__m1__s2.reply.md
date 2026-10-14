```lisp
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
```