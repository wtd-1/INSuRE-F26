(herald "M8 investigation: step1_m6" (bound 30))

(include "../../../m6/TLS1.3_macros.lisp")

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

  (lang
   (random32 atom)
   (pv (tuple 3))
   )
  )

(defgoal tls13mtlspfs
  (forall ((cr sr random32) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd))
    (implies (and (p "server" z 4) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y)
                  (fact undisclosed cpk) (non (privk ca)) (ugen y) (uniq-at sr z 2))
      (exists ((z-0 strd)) (and (p "client" z-0 4)
        (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))
