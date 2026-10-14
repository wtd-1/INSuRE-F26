```lisp
(defmacro (chello cr x)
  (cat cr (exp (gen) x)))

(defmacro (shello sr y)
  (cat sr (exp (gen) y)))

(defmacro (certf n k ca)
  (cat n k (enc n k (privk ca))))

(defmacro (hsec x y)
  (hash "hs" (exp (exp (gen) y) x)))

(defmacro (msec x y)
  (hash "ms" (hsec x y)))

(defmacro (chts cr sr x y)
  (hash "chts" (hsec x y) cr sr))

(defmacro (shts cr sr x y)
  (hash "shts" (hsec x y) cr sr))

(defmacro (capk cr sr x y)
  (hash "capts" cr sr (msec x y)))

(defmacro (sapk cr sr x y)
  (hash "sapts" cr sr (msec x y)))

(defmacro (fkey k)
  (hash "finished" k))

(defmacro (trs cr sr x y s spk ca)
  (cat (chello cr x) (shello sr y) (certf s spk ca)))

(defmacro (sfin cr sr x y s spk ca)
  (hash (fkey (shts cr sr x y)) (trs cr sr x y s spk ca)))

(defmacro (trc cr sr x y s spk ca c cpk)
  (cat (trs cr sr x y s spk ca)
       (sfin cr sr x y s spk ca)
       (certf c cpk ca)))

(defmacro (cfin cr sr x y s spk ca c cpk)
  (hash (fkey (chts cr sr x y)) (trc cr sr x y s spk ca c cpk)))

(defmacro (msg2 cr sr x y s spk ca)
  (cat (shello sr y)
       (enc (certf s spk ca)
            (sfin cr sr x y s spk ca)
            (shts cr sr x y))))

(defmacro (msg3 cr sr x y s spk ca c cpk)
  (enc (certf c cpk ca)
       (cfin cr sr x y s spk ca c cpk)
       (chts cr sr x y)))

(defprotocol mtls13 diffie-hellman
  (defrole client
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (x rndx) (y expt))
    (trace
      (send (chello cr x))
      (recv (msg2 cr sr x y s spk ca))
      (send (msg3 cr sr x y s spk ca c cpk))
      (send (enc request (capk cr sr x y)))
      (recv (enc response (sapk cr sr x y))))
    (uniq-gen x))
  (defrole server
    (vars (s c ca name) (cr sr text) (spk cpk akey)
          (request response text) (y rndx) (x expt))
    (trace
      (recv (chello cr x))
      (send (msg2 cr sr x y s spk ca))
      (recv (msg3 cr sr x y s spk ca c cpk))
      (recv (enc request (capk cr sr x y)))
      (send (enc response (sapk cr sr x y))))
    (uniq-gen y)))
```