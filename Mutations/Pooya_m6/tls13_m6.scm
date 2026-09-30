(herald "Verification of TLS 1.3 mutual authentication properties"
	)

;; Companion CPSA model for mutual TLS (mTLS).
;;
;; This model follows the structure of tls13_final.scm, but uses the mTLS
;; macro from TLS1.3_macros.lisp.  The client authenticates to the server
;; with a certificate in addition to the server's certificate authentication.
;; This m6 variant removes the client's CertificateVerify signature while
;; retaining the server's CertificateVerify.
;;
;; This is a CPSA symbolic abstraction of the TLS modes analyzed in the
;; accompanying model.  It covers injective agreement, application-key
;; secrecy, and forward secrecy under later compromise of either signing key;
;; it does not model every TLS 1.3 option or implementation detail.

(include "TLS1.3_M6_Delete_ClientSignature.lisp")

;; Shortcut for the TLS 1.3 master secret.
(defmacro (MS exponent1 exponent2)
  (MasterSecret (HandshakeSecret (DHpublic exponent1) exponent2)))

(defprotocol tls13-mtls basic

  ;; ------------------------------------------------------------
  ;; Client: server and client are both authenticated.
  ;; ------------------------------------------------------------
  (defrole client
    (vars
     (s ca c name)             ;; server, CA, client
     (cr sr random32)          ;; TLS ClientHello/ServerHello randoms
     (x rndx)                  ;; client DH exponent
     (y expt)                  ;; server DH exponent
     (spk akey)                ;; server public key
     (cpk akey)                ;; client public key
     (request text)
     (response text)
     )
    (trace
     (mTLS send recv cr sr x y s spk (invk spk)
           c cpk (invk cpk) ca
           (HandshakeSecret (DHpublic y) x))
     (send (enc request (ClientApKey cr sr (MS y x))))
     (recv (enc response (ServerApKey cr sr (MS y x))))
     )
    (uniq-gen x)
    )

  ;; ------------------------------------------------------------
  ;; Server: client presents a certificate, but m6 removes its signature.
  ;; ------------------------------------------------------------
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
     )
    (trace
     (mTLS recv send cr sr x y s (invk spk) spk
           c cpk (invk cpk) ca
           (HandshakeSecret (DHpublic x) y))
     (recv (enc request (ClientApKey cr sr (MS x y))))
     (send (enc response (ServerApKey cr sr (MS x y))))
     )
    (uniq-gen y)
    )

  (lang
   (random32 atom)
   )
  )

;; ============================================================
;; Mutual authentication: Injective Agreement
;; ============================================================

;; A completed client run agrees with a completed server run on the
;; handshake parameters.  The client's server authentication is provided
;; by the server certificate, CertificateVerify, and Finished messages.  The
;; client's CertificateVerify is absent in this m6 variant.

(defgoal tls13-mtls
  (forall
    ((cr sr random32) (spk cpk akey) (s ca c name)
     (x rndx) (y expt) (z strd))
    (implies
     (and
      (p "client" z 5)
      (p "client" "cr" z cr)
      (p "client" "sr" z sr)
      (p "client" "spk" z spk)
      (p "client" "cpk" z cpk)
      (p "client" "s" z s)
      (p "client" "c" z c)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (non (invk spk))
      (non (invk cpk))
      (non (privk ca))
      (ugen x)
      (uniq-at cr z 0))
     (exists
      ((z-0 strd))
      (and
       (p "server" z-0 5)
       (p "server" "cr" z-0 cr)
       (p "server" "sr" z-0 sr)
       (p "server" "spk" z-0 spk)
       (p "server" "cpk" z-0 cpk)
       (p "server" "s" z-0 s)
       (p "server" "c" z-0 c)
       (p "server" "ca" z-0 ca)
       (p "server" "y" z-0 y)
       (p "server" "x" z-0 x))))))

;; A completed server run agrees with a completed client run.  This is the
;; direction that is unavailable in the server-only model: the server has
;; evidence that the peer possesses the client's private signing key.

(defgoal tls13-mtls
  (forall
    ((cr sr random32) (spk cpk akey) (s ca c name)
     (x expt) (y rndx) (z strd))
    (implies
     (and
      (p "server" z 5)
      (p "server" "cr" z cr)
      (p "server" "sr" z sr)
      (p "server" "spk" z spk)
      (p "server" "cpk" z cpk)
      (p "server" "s" z s)
      (p "server" "c" z c)
      (p "server" "ca" z ca)
      (p "server" "x" z x)
      (p "server" "y" z y)
      (non (invk cpk))
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 1))
     (exists
      ((z-0 strd))
      (and
       (p "client" z-0 5)
       (p "client" "cr" z-0 cr)
       (p "client" "sr" z-0 sr)
       (p "client" "spk" z-0 spk)
       (p "client" "cpk" z-0 cpk)
       (p "client" "s" z-0 s)
       (p "client" "c" z-0 c)
       (p "client" "ca" z-0 ca)
       (p "client" "x" z-0 x)
       (p "client" "y" z-0 y))))))

;; ============================================================
;; Session-key secrecy
;; ============================================================

;; Client perspective: client application traffic keys are not leaked.

(defgoal tls13-mtls
  (forall
    ((cr sr random32) (request response text)
     (spk cpk akey) (s ca c name)
     (x rndx) (y expt) (z z-0 strd))
    (implies
     (and
      (p "client" z 5)
      (p "" z-0 2)
      (p "client" "cr" z cr)
      (p "client" "sr" z sr)
      (p "client" "request" z request)
      (p "client" "response" z response)
      (p "client" "spk" z spk)
      (p "client" "cpk" z cpk)
      (p "client" "s" z s)
      (p "client" "c" z c)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (p "" "x" z-0
         (hash "c ap traffic" cr sr
               (hash (exp (gen) (mul x y)) "derived")))
      (non (invk spk))
      (non (invk cpk))
      (non (privk ca))
      (ugen x)
      (uniq-at cr z 0))
     (false))))

(defgoal tls13-mtls
  (forall
    ((cr sr random32) (request response text)
     (spk cpk akey) (s ca c name)
     (x rndx) (y expt) (z z-0 strd))
    (implies
     (and
      (p "client" z 5)
      (p "" z-0 2)
      (p "client" "cr" z cr)
      (p "client" "sr" z sr)
      (p "client" "request" z request)
      (p "client" "response" z response)
      (p "client" "spk" z spk)
      (p "client" "cpk" z cpk)
      (p "client" "s" z s)
      (p "client" "c" z c)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (p "" "x" z-0
         (hash "s ap traffic" cr sr
               (hash (exp (gen) (mul x y)) "derived")))
      (non (invk spk))
      (non (invk cpk))
      (non (privk ca))
      (ugen x)
      (uniq-at cr z 0))
     (false))))

;; Server perspective: because the client is authenticated, the same
;; application-key secrecy argument can be made from the server side.

(defgoal tls13-mtls
  (forall
    ((cr sr random32) (request text)
     (spk cpk akey) (s ca c name)
     (x expt) (y rndx) (z z-0 strd))
    (implies
     (and
      (p "server" z 5)
      (p "" z-0 2)
      (p "server" "cr" z cr)
      (p "server" "sr" z sr)
      (p "server" "request" z request)
      (p "server" "spk" z spk)
      (p "server" "cpk" z cpk)
      (p "server" "s" z s)
      (p "server" "c" z c)
      (p "server" "ca" z ca)
      (p "server" "y" z y)
      (p "server" "x" z x)
      (p "" "x" z-0
         (hash "s ap traffic" cr sr
               (hash (exp (gen) (mul x y)) "derived")))
      (non (invk cpk))
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 1))
     (false))))

(defgoal tls13-mtls
  (forall
    ((cr sr random32) (request text)
     (spk cpk akey) (s ca c name)
     (x expt) (y rndx) (z z-0 strd))
    (implies
     (and
      (p "server" z 5)
      (p "" z-0 2)
      (p "server" "cr" z cr)
      (p "server" "sr" z sr)
      (p "server" "request" z request)
      (p "server" "spk" z spk)
      (p "server" "cpk" z cpk)
      (p "server" "s" z s)
      (p "server" "c" z c)
      (p "server" "ca" z ca)
      (p "server" "y" z y)
      (p "server" "x" z x)
      (p "" "x" z-0
         (hash "c ap traffic" cr sr
               (hash (exp (gen) (mul x y)) "derived")))
      (non (invk cpk))
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 1))
     (false))))

;; ============================================================
;; Perfect Forward Secrecy
;; ============================================================
;;
;; PFS requires long-term signing-key compromise roles.  The two disclosure
;; roles below model compromise of the server and client private keys after
;; the handshake.  The session DH exponents remain uniquely generated.

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
     )
    (trace
     (mTLS send recv cr sr x y s spk (invk spk)
           c cpk (invk cpk) ca
           (HandshakeSecret (DHpublic y) x))
     (send (enc request (ClientApKey cr sr (MS y x))))
     (recv (enc response (ServerApKey cr sr (MS y x))))
     )
    (uniq-gen x)
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
           c cpk (invk cpk) ca
           (HandshakeSecret (DHpublic x) y))
     (recv (enc request (ClientApKey cr sr (MS x y))))
     (send (enc response (ServerApKey cr sr (MS x y))))
     )
    (uniq-gen y)
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

;; PFS from the client's perspective: compromise of the server signing key
;; after completion does not reveal the application traffic key.

(defgoal tls13mtlspfs
  (forall
    ((cr sr random32) (request response text) (spk cpk akey)
     (ca s c self name) (priv-stor locn) (x rndx) (y expt)
     (z z-0 z-1 strd))
    (implies
     (and
      (p "client" z 5)
      (p "" z-0 2)
      (p "privkey-disclose" z-1 3)
      (p "client" "cr" z cr)
      (p "client" "sr" z sr)
      (p "client" "request" z request)
      (p "client" "response" z response)
      (p "client" "spk" z spk)
      (p "client" "cpk" z cpk)
      (p "client" "s" z s)
      (p "client" "c" z c)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (p "" "x" z-0 request)
      (p "privkey-disclose" "pk" z-1 spk)
      (p "privkey-disclose" "self" z-1 self)
      (p "privkey-disclose" "priv-stor" z-1 priv-stor)
      (prec z 2 z-1 0)
      (non (invk cpk))
      (non (privk ca))
      (ugen x)
      (uniq-at cr z 0)
      (uniq-at request z 3))
     (false))))

;; PFS from the server's perspective: compromise of the client signing key
;; after completion does not reveal the application traffic key.

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
      (prec z 2 z-1 0)
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 2)
      (uniq-at response z 5))
     (false))))
