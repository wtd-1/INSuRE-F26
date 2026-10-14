(herald "M8 investigation: m8_with_lemmas_m0" (bound 30))

(include "../../../BASELINE-v2/TLS1.3_macros.lisp")

(defmacro (MS exponent1 exponent2)
  (MasterSecret (HandshakeSecret (DHpublic exponent1) exponent2)))

(defprotocol tls13mtlspfs basic

  (defrole client
    (vars
     (s ca c name)
     (cr sr random32)
     (x rndx)
     (y expt)
     (spk akey)
     (cpk akey)
     (request text)
     (response text)
     (cpriv-stor locn)  ;; F7: client local storage for its signing key
     )
    (trace
     (load cpriv-stor (pv c cpk (invk cpk)))  ;; F7: key comes from storage
     (mTLS send recv cr sr x y s (invk spk) spk
           c (invk cpk) cpk ca
           (HandshakeSecret (DHpublic y) x))
     (send (enc request (ClientApKey cr sr (MS y x))))
     (recv (enc response (ServerApKey cr sr (MS y x))))
     )
    (ClientDHFresh x) ;; R1 mutation point m4c
    (gen-st (pv c cpk (invk cpk)))  ;; F7
    )

  (defrole server
    (vars
     (s ca c name)
     (cr sr random32)
     (y rndx)
     (x expt)
     (spk akey)
     (cpk akey)
     (request text)
     (response text)
     (priv-stor locn)
     )
    (trace
     (load priv-stor (pv s spk (invk spk)))
     (mTLS recv send cr sr x y s (invk spk) spk
           c (invk cpk) cpk ca
           (HandshakeSecret (DHpublic x) y))
     (recv (enc request (ClientApKey cr sr (MS x y))))
     (send (enc response (ServerApKey cr sr (MS x y))))
     )
    (ServerDHFresh y) ;; R1 mutation point m4
    (gen-st (pv s spk (invk spk)))
    )

  ;; Long-term certificate/private-key storage.  This role can generate
  ;; either the server or client signing key.
  (defrole cert-gen
    (vars
     (self name)
     (pk akey)
     (priv-stor locn)
     (ignore mesg)
     )
    (trace
     (load priv-stor ignore)
     (stor priv-stor (pv self pk (invk pk)))
     )
    (uniq-gen pk)
    )

  (defrole privkey-disclose
    (vars
     (self name)
     (pk akey)
     (priv-stor locn)
     )
    (trace
     (load priv-stor (pv self pk (invk pk)))
     (stor priv-stor "nil")
     (send pk)
     )
    (gen-st (pv self pk (invk pk)))
    )

  (defrule undisclosed-not-disclosed
    (forall
     ((z strd) (pk akey))
     (implies
      (and (fact undisclosed pk)
           (p "privkey-disclose" z 2)
           (p "privkey-disclose" "pk" z pk))
      (false))))

  (defrule cert-gen-once-interference
    (forall
     ((z1 z2 strd) (self name))
     (implies
      (and (fact cert-gen-once self)
           (p "cert-gen" z1 2)
           (p "cert-gen" "self" z1 self)
           (p "cert-gen" z2 2)
           (p "cert-gen" "self" z2 self))
      (= z1 z2))))

  (defrule client-exponent-unavailable
    (forall ((x rndx) (z z-0 strd))
      (implies (and (p "client" z 2) (p "" z-0 2) (p "client" "x" z x)
                    (p "" "x" z-0 x) (ugen x)) (false))))

  (defrule server-exponent-unavailable
    (forall ((y rndx) (z z-0 strd))
      (implies (and (p "server" z 3) (p "" z-0 2) (p "server" "y" z y)
                    (p "" "x" z-0 y) (ugen y)) (false))))

  (defrule server-dh-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (exp (gen) (mul x y)))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-chs-key-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (hash (exp (gen) (mul x y)) "c hs traffic" cr sr))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-chs-pre-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (cat (exp (gen) (mul x y)) "c hs traffic" cr sr))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-shs-key-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (hash (exp (gen) (mul x y)) "s hs traffic" cr sr))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-shs-pre-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (cat (exp (gen) (mul x y)) "s hs traffic" cr sr))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-ms-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (hash (exp (gen) (mul x y)) "derived"))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-ms-pre-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (cat (exp (gen) (mul x y)) "derived"))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-sap-key-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (hash "s ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-sap-pre-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (cat "s ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-cap-key-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (hash "c ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (defrule server-cap-pre-unavailable-pfs
    (forall ((cr sr random32) (cpk akey) (self name) (priv-stor locn) (y rndx) (x expt)
               (z z-0 z-1 strd))
      (implies (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
                    (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "cpk" z cpk)
                    (p "server" "y" z y) (p "server" "x" z x)
                    (p "" "x" z-0 (cat "c ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
                    (p "privkey-disclose" "pk" z-1 cpk)
                    (p "privkey-disclose" "self" z-1 self)
                    (p "privkey-disclose" "priv-stor" z-1 priv-stor)
                    (prec z 5 z-1 0) (ugen y) (uniq-at sr z 2)) (false))))

  (lang
   (random32 atom)
   (pv (tuple 3))
   )
  )

(defgoal tls13mtlspfs
  (forall
    ((sr cr random32) (response request text) (spk cpk akey)
     (ca s c self name) (priv-stor locn) (y rndx) (x expt)
     (z z-0 z-1 strd))
    (implies
     (and
      (p "server" z 6)
      (p "" z-0 2)
      (p "privkey-disclose" z-1 3)
      (p "server" "cr" z cr)
      (p "server" "sr" z sr)
      (p "server" "request" z request)
      (p "server" "response" z response)
      (p "server" "spk" z spk)
      (p "server" "cpk" z cpk)
      (p "server" "s" z s)
      (p "server" "c" z c)
      (p "server" "ca" z ca)
      (p "server" "y" z y)
      (p "server" "x" z x)
      (p "" "x" z-0 response)
      (p "privkey-disclose" "pk" z-1 cpk)
      (p "privkey-disclose" "self" z-1 self)
      (p "privkey-disclose" "priv-stor" z-1 priv-stor)
      (prec z 5 z-1 0)
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 2)
      (uniq-at response z 5))
     (false))))
