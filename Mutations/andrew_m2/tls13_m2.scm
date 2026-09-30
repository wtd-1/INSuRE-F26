(herald "Verification of TLS 1.3 security properties proven in Tamarin analysis"
	)

;; The goals expressed in this file are meant to establish that the CPSA models
;; and analysis of the six security properties verified in Cremers, et al, "A
;; Comprehensive Symbolic Analysis of TLS 1.3" are consistent with that of the
;; Tamarin analysis described in that paper. These models of the protocol are
;; not a comprehensive analysis and are instead an analysis of only those modes
;; of TLS 1.3 that are used by RFC 8773. This file is only the analysis of
;; TLS 1.3 server authentication only. A second file contains the mutual
;; authentication models. 

(include "TLS1.3_M2_Remove_Client_Key_Share.lisp")

;; The following macro is a shortcut to create the TLS master secret.

(defmacro (MS exponent1 exponent2)
  (MasterSecret (HandshakeSecret (DHpublic exponent1) exponent2)))


(defprotocol tls13 basic

  (defrole client 
    (vars
     (s ca name) ;; s - server, ca - certificate authority
     (cr sr random32) ;; cr - client random, sr - server random for TLS
     (x rndx) ;; client's Diffie-Hellman secret
     (y expt) ;; server's Diffie-Hellman secret
     (spk akey) ;; server's public key
     (request text) ;; request sent from client
     (response text) ;; response sent from server
     )
    (trace
     (TLS send recv cr sr x y s spk (invk spk) ca
	  (HandshakeSecret (DHpublic y) x)) ;; establish TLS session with server
     (send (enc request (ClientApKey cr sr (MS y x)))) ;; exchange protected by
     (recv (enc response (ServerApKey cr sr (MS y x)))) ; TLS session keys
     )
    (uniq-gen x)
    )

  (defrole server
    (vars
     (s ca name) ;; s - server, ca - certificate authority
     (cr sr random32) ;; cr - client random, sr - server random for TLS
     (y rndx) ;; client's Diffie-Hellman secret
     (x expt) ;; server's Diffie-Hellman secret
     (spk akey) ;; server's public key
     (request text) ;; request sent from client
     (response text) ;; response sent from server
     )
    (trace
     (TLS recv send cr sr x y s spk (invk spk) ca
	  (HandshakeSecret (DHpublic x) y)) ;; establish TLS session with client
     (recv (enc request (ClientApKey cr sr (MS x y)))) ;; exchange protected by
     (send (enc response (ServerApKey cr sr (MS x y)))) ; TLS session keys
     )
    (uniq-gen y)
    )

  (lang
   (random32 atom)
   )
  )

;; Security properties of TLS

;; Property: Injective Agreement. 

(defgoal tls13
  (forall  ;; Clients
    ((cr sr random32) (spk akey) (s ca name) (x rndx) (y expt) (z strd))
    (implies
     (and
      (p "client" z 5)         ;; Complete run of client handshake including 
      (p "client" "cr" z cr)   ;; handshake variables used to generate session
      (p "client" "sr" z sr)   ;; keys
      (p "client" "spk" z spk)
      (p "client" "s" z s)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
                               ;; Assumption on handshake variables for client
      (non (invk spk))         ;; Server private key is uncompromised
      (non (privk ca))         ;; Cert Authority private key is uncompromised
      (ugen x)                 ;; Client DH exponent freshly generated
      (uniq-at cr z 0))        ;; Client random freshly generated
     (exists
      ((z-0 strd))       
      (and
       (p "server" z-0 4)         ;; There exists a server with the same name 
       (p "server" "cr" z-0 cr)   ;; and public key as the one held by the
       (p "server" "sr" z-0 sr)   ;; client that completed the handshake and it
       (p "server" "spk" z-0 spk) ;; agrees on all the values of the handshake
       (p "server" "s" z-0 s)     ;; variables with the client.
       (p "server" "ca" z-0 ca)
       (p "server" "y" z-0 y)
       (p "server" "x" z-0 x))))))

;; The following goal cannot be satisfied in a server-only authentication. There
;; is no basis for the server to know if they are connected to a client.

(defgoal tls13
  (forall  ;; Servers
    ((cr sr random32) (spk akey) (s ca name) (x expt) (y rndx) (z strd))
    (implies
     (and
      (p "server" z 4)         ;; Complete run of server handshake including 
      (p "server" "cr" z cr)   ;; handshake variables used to generate session
      (p "server" "sr" z sr)   ;; keys
      (p "server" "spk" z spk)
      (p "server" "s" z s)
      (p "server" "ca" z ca)
      (p "server" "x" z x)
      (p "server" "y" z y)
                               ;; Assumption on handshake variables for server
      (non (privk ca))         ;; Cert Authority private key is uncompromised
      (ugen y)                 ;; Server DH exponent freshly generated
      (uniq-at sr z 1))        ;; Server random freshly generated
     (exists
      ((z-0 strd))       
      (and
       (p "client" z-0 4)         ;; There exists a client with the server's 
       (p "client" "cr" z-0 cr)   ;; name and public key as the one held by the
       (p "client" "sr" z-0 sr)   ;; server that completed the handshake and it
       (p "client" "spk" z-0 spk) ;; agrees on all the values of the handshake
       (p "client" "s" z-0 s)     ;; variables with that server.
       (p "client" "ca" z-0 ca)
       (p "client" "y" z-0 y)
       (p "client" "x" z-0 x))))))

;; Secrecy of the session keys. Satisfaction of the following
;; goal will establish that if a run of the client completes the handshake, the
;; client and the server will agree on the values used to establish all session
;; keys and the keys are unavailable to the adversary. Verifying that the keys
;; are unavailable to the adversary involves the use of listeners for the
;; session keys. We have simplified the model in that we are not using the MAC
;; keys. For TLS 1.3 server-only authentication, as the client is
;; unauthenticated, it cannot be determined if a run of the server guarantees
;; that a client agrees on the keys. As such, the goal is only satisfied from 
;; the client's perspective.

;; Client perspective, check for leak of client write and server write keys.

(defgoal tls13
  (forall
    ((cr sr random32) (request response text) (spk akey) (s ca name)
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
      (p "client" "s" z s)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (p "" "x" z-0
         (hash "c ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
      (non (invk spk))
      (non (privk ca))
      (ugen x)
      (uniq-at cr z 0))
     (false))))

(defgoal tls13
  (forall
    ((cr sr random32) (request response text) (spk akey) (s ca name)
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
      (p "client" "s" z s)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (p "" "x" z-0
         (hash "s ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
      (non (invk spk))
      (non (privk ca))
      (ugen x)
      (uniq-at cr z 0))
     (false))))

;; Server's Perspective. Cannot be satisfied due to the inability of the server
;; to determine where the messages originated.

(defgoal tls13
  (forall
    ((cr sr random32) (request text) (spk akey) (s ca name) (x expt)
      (y rndx) (z z-0 strd))
    (implies
     (and
      (p "server" z 4)
      (p "" z-0 2)
      (p "server" "cr" z cr)
      (p "server" "sr" z sr)
      (p "server" "request" z request)
      (p "server" "spk" z spk)
      (p "server" "s" z s)
      (p "server" "ca" z ca)
      (p "server" "y" z y)
      (p "server" "x" z x)
      (p "" "x" z-0
         (hash "s ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 1))
     (false))))

(defgoal tls13
  (forall
    ((cr sr random32) (request text) (spk akey) (s ca name) (x expt)
      (y rndx) (z z-0 strd))
    (implies
     (and
      (p "server" z 4)
      (p "" z-0 2)
      (p "server" "cr" z cr)
      (p "server" "sr" z sr)
      (p "server" "request" z request)
      (p "server" "spk" z spk)
      (p "server" "s" z s)
      (p "server" "ca" z ca)
      (p "server" "y" z y)
      (p "server" "x" z x)
      (p "" "x" z-0
         (hash "c ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
      (non (privk ca))
      (ugen y)
      (uniq-at sr z 1))
     (false))))

;; Perfect Forward Secrecy. This requires the addition of roles to compromise
;; the longterm secrets to prove that it does not reveal any messages sent
;; prior to the compromise. The theorem states that if a long term key is
;; compromised after a TLS handshake is completed, the messages transmitted by
;; the keys generated in that handshake are uncompromised.

;; Modified protocol specification: includes certificate generation role,
;; needed to compromise the private key and private key disclosure role to
;; compromise private key by leaking it to the adversary.

(defprotocol tls13fs basic

  (defrole client 
    (vars
     (s ca name) ;; s - server, ca - certificate authority
     (cr sr random32) ;; cr - client random, sr - server random for TLS
     (x rndx) ;; client's Diffie-Hellman secret
     (y expt) ;; server's Diffie-Hellman secret
     (spk akey) ;; server's private key of public/private key pair
     (request text) ;; request sent from client
     (response text) ;; response sent from server
     )
    (trace
     (TLS send recv cr sr x y s (invk spk) spk ca
	  (HandshakeSecret (DHpublic y) x)) ;; establish TLS session with server
     (send (enc request (ClientApKey cr sr (MS y x)))) ;; exchange protected by
     (recv (enc response (ServerApKey cr sr (MS y x)))) ; TLS session keys
     )
    (uniq-gen x)
    )

  (defrole server
    (vars
     (s ca name) ;; s - server, ca - certificate authority
     (cr sr random32) ;; cr - client random, sr - server random for TLS
     (y rndx) ;; client's Diffie-Hellman secret
     (x expt) ;; server's Diffie-Hellman secret
     (spk akey) ;; server's private key of public/private key pair
     (request text) ;; request sent from client
     (response text) ;; response sent from server
     (priv-stor locn) ;; server local storage
     )
    (trace
     (load priv-stor (pv s spk (invk spk)))
     (TLS recv send cr sr x y s (invk spk) spk ca
	  (HandshakeSecret (DHpublic x) y)) ;; establish TLS session with client
     (recv (enc request (ClientApKey cr sr (MS x y)))) ;; exchange protected by
     (send (enc response (ServerApKey cr sr (MS x y)))) ; TLS session keys
     )
    (uniq-gen y)
    (gen-st (pv s spk (invk spk)))
    )

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
	   (p "privkey-disclose" "pk" z pk)
	   )
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

;; Perfect Forward Secrecy from the client's perspective

(defgoal tls13fs
  (forall
    ((cr sr random32) (request response text) (spk akey)
      (ca s self name) (priv-stor locn) (x rndx) (y expt)
      (z z-0 z-1 strd))
    (implies
      (and (p "client" z 5) (p "" z-0 2) (p "privkey-disclose" z-1 3)
        (p "client" "cr" z cr) (p "client" "sr" z sr)
        (p "client" "request" z request)
        (p "client" "response" z response) (p "client" "spk" z spk)
        (p "client" "s" z s) (p "client" "ca" z ca) (p "client" "x" z x)
        (p "client" "y" z y) (p "" "x" z-0 request)
        (p "privkey-disclose" "pk" z-1 spk)
        (p "privkey-disclose" "self" z-1 self)
        (p "privkey-disclose" "priv-stor" z-1 priv-stor)
        (prec z 2 z-1 0) (non (privk ca)) (ugen x) (uniq-at cr z 0)
        (uniq-at request z 3))
      (false))))

;; Perfect Forward Secrecy from the server's perspective. This cannot be
;; satisfied due to the inability of the server to authenticate the client in
;; server only authentication. 

(defgoal tls13fs
  (forall
    ((sr cr random32) (response request text) (spk akey)
      (ca s self name) (priv-stor priv-stor-0 locn) (y rndx) (x expt)
      (z z-0 z-1 strd))
    (implies
      (and (p "server" z 6) (p "" z-0 2) (p "privkey-disclose" z-1 3)
        (p "server" "cr" z cr) (p "server" "sr" z sr)
        (p "server" "request" z request)
        (p "server" "response" z response) (p "server" "spk" z spk)
        (p "server" "s" z s) (p "server" "ca" z ca)
        (p "server" "priv-stor" z priv-stor) (p "server" "y" z y)
        (p "server" "x" z x) (p "" "x" z-0 response)
        (p "privkey-disclose" "pk" z-1 spk)
        (p "privkey-disclose" "self" z-1 self)
        (p "privkey-disclose" "priv-stor" z-1 priv-stor-0)
        (prec z 2 z-1 0) (non (privk ca)) (ugen y) (uniq-at sr z 2)
        (uniq-at response z 5))
      (false))))
