(herald "Verification of TLS 1.3 rules to assist in mTLS verification"
	(try-old-strands)
	)

(include "../../CPSA Models/validation/mutant_macros/TLS1.3_macros_m1.lisp")

(defmacro (MS exponent1 exponent2)
  (MasterSecret (HandshakeSecret (DHpublic exponent1) exponent2)))

(defprotocol mtls13 basic

  (defrole client 
    (vars
     (s c ca name) ;; s - server, ca - certificate authority
     (cr sr random32) ;; cr - client random, sr - server random for TLS
     (x rndx) ;; client's Diffie-Hellman secret
     (y expt) ;; server's Diffie-Hellman secret
     (spk cpk akey) ;; server's public key
     (request text) ;; request sent from client
     (response text) ;; response sent from server
     )
    (trace
     (mTLS send recv cr sr x y s spk (invk spk) c cpk (invk cpk) ca
	  (HandshakeSecret (DHpublic y) x)) ;; establish TLS session with server
     (send (enc request (ClientApKey cr sr (MS y x)))) ;; exchange protected by
     (recv (enc response (ServerApKey cr sr (MS y x)))) ; TLS session keys
     )
    (uniq-gen x)
    )

  (defrole server
    (vars
     (s c ca name) ;; s - server, ca - certificate authority
     (cr sr random32) ;; cr - client random, sr - server random for TLS
     (y rndx) ;; client's Diffie-Hellman secret
     (x expt) ;; server's Diffie-Hellman secret
     (spk cpk akey) ;; server's public key
     (request text) ;; request sent from client
     (response text) ;; response sent from server
     )
    (trace
     (mTLS recv send cr sr x y s spk (invk spk) c cpk (invk cpk) ca
	  (HandshakeSecret (DHpublic x) y)) ;; establish TLS session with client
     (recv (enc request (ClientApKey cr sr (MS x y)))) ;; exchange protected by
     (send (enc response (ServerApKey cr sr (MS x y)))) ; TLS session keys
     )
    (uniq-gen y)
    )

  ;; Rule to prevent clients from acting as both client and server
  
  (defrule clients-servers-distinct
    (forall ((z0 z1 strd) (c name))
	    (implies
	     (and
	      (p "client" "c" z0 c)
	      (p "client" "s" z1 c))
	     (false))))

  ;; Rules that exponents of legitimate participants are unavailable to the
  ;; adversary. Proven in mtls0.scm
  
  (defrule client-exponent-unavailable
    (forall ;; Clients
     ((x rndx) (z z-0 strd))
     (implies
      (and
       (p "client" z 1)
       (p "" z-0 2)
       (p "client" "x" z x)
       (p "" "x" z-0 x)
       (ugen x)
       )
      (false)
      )
     )
    )

  (defrule server-exponent-unavailable
    (forall ;; Servers
     ((y rndx) (z z-0 strd))
     (implies
      (and
       (p "server" z 2)
       (p "" z-0 2)
       (p "server" "y" z y)
       (p "" "x" z-0 y)
       (ugen y)
       )
      (false)
      )
     )
    )

  ;; Rules that the Diffie-Hellman values of legitimate participants are
  ;; unavailable to the adversary. Proven in mtls1.scm
  
(defrule diffie-hellman-value-between-legitimate-parties-unavailable-1
  (forall ;; Clients
   ((cr random32) (spk akey) (s ca name) (x rndx) (y expt) (z z-0 strd))
   (implies
    (and
     (p "client" z 2)
     (p "" z-0 2)
     (p "client" "cr" z cr)
     (p "client" "x" z x)
     (p "client" "y" z y)
     (p "" "x" z-0 (exp (gen) (mul x y)))
     (p "client" "s" z s)
     (p "client" "ca" z ca)
     (p "client" "spk" z spk)
     (non (invk spk))
     (ugen x)
     (uniq-at cr z 0)
     )
    (false)
    )
   )
  )

(defrule diffie-hellman-value-between-legitimate-parties-unavailable-2
  (forall ;; Servers
   ((sr random32) (cpk akey) (c ca name) (y rndx) (x expt) (z z-0 strd))
   (implies
    (and
     (p "server" z 3)
     (p "" z-0 2)
     (p "server" "sr" z sr)
     (p "server" "x" z x)
     (p "server" "y" z y)
     (p "" "x" z-0 (exp (gen) (mul x y)))
     (p "server" "c" z c)
     (p "server" "ca" z ca)
     (p "server" "cpk" z cpk)
     (non (invk cpk))
     (ugen y)
     (uniq-at sr z 1)
     )
    (false)
    )
   )
  )

  (lang
   (random32 atom)
   )
  )

(defgoal mtls13 (forall ((cr sr random32) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd)) (implies (and (p "client" z 5) (p "client" "cr" z cr) (p "client" "sr" z sr) (p "client" "spk" z spk) (p "client" "s" z s) (p "client" "cpk" z cpk) (p "client" "c" z c) (p "client" "ca" z ca) (p "client" "x" z x) (p "client" "y" z y) (uniq-at cr z 0) (ugen x) (non (invk spk))) (exists ((z-0 strd)) (and (p "server" z-0 5) (p "server" "cr" z-0 cr) (p "server" "sr" z-0 sr) (p "server" "spk" z-0 spk) (p "server" "s" z-0 s) (p "server" "cpk" z-0 cpk) (p "server" "c" z-0 c) (p "server" "ca" z-0 ca) (p "server" "x" z-0 x) (p "server" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr sr random32) (spk cpk akey) (s c ca name) (x expt) (y rndx) (z strd)) (implies (and (p "server" z 5) (p "server" "cr" z cr) (p "server" "sr" z sr) (p "server" "spk" z spk) (p "server" "s" z s) (p "server" "cpk" z cpk) (p "server" "c" z c) (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y) (uniq-at sr z 1) (ugen y) (non (invk cpk))) (exists ((z-0 strd)) (and (p "client" z-0 4) (p "client" "cr" z-0 cr) (p "client" "sr" z-0 sr) (p "client" "spk" z-0 spk) (p "client" "s" z-0 s) (p "client" "cpk" z-0 cpk) (p "client" "c" z-0 c) (p "client" "ca" z-0 ca) (p "client" "x" z-0 x) (p "client" "y" z-0 y))))))

(defgoal mtls13 (forall ((cr random32) (request text) (spk akey) (x rndx) (z z-0 strd)) (implies (and (p "client" z 5) (p "" z-0 2) (p "client" "cr" z cr) (p "client" "x" z x) (p "client" "spk" z spk) (p "client" "request" z request) (p "" "x" z-0 request) (non (invk spk)) (ugen x) (uniq-at cr z 0) (uniq-at request z 3)) (false))))

(defgoal mtls13 (forall ((sr random32) (response text) (cpk akey) (y rndx) (z z-0 strd)) (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "sr" z sr) (p "server" "y" z y) (p "server" "cpk" z cpk) (p "server" "response" z response) (p "" "x" z-0 response) (non (invk cpk)) (ugen y) (uniq-at sr z 1) (uniq-at response z 4)) (false))))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand client 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))

(defskeleton mtls13 (vars (spk cpk akey)) (defstrand server 5 (spk spk) (cpk cpk)) (non-orig (invk spk) (invk cpk)))
