(herald "Verification of TLS 1.3 rules to assist in mTLS verification"
	(try-old-strands)
	)

(include "../mutant_macros/TLS1.3_macros_m8.lisp")

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
  
;; rule diffie-hellman-value-between-legitimate-parties-unavailable-1 removed for this test

;; rule diffie-hellman-value-between-legitimate-parties-unavailable-2 removed for this test

  (lang
   (random32 atom)
   )
  )

(defgoal mtls13 (forall
  ((cr sr random32) (spk cpk akey) (s c ca name) (x rndx) (y expt) (z strd))
  (implies (and (p "client" z 5)
      (p "client" "cr" z cr)
      (p "client" "sr" z sr)
      (p "client" "spk" z spk)
      (p "client" "s" z s)
      (p "client" "cpk" z cpk)
      (p "client" "c" z c)
      (p "client" "ca" z ca)
      (p "client" "x" z x)
      (p "client" "y" z y)
      (uniq-at cr z 0) (ugen x) (non (invk spk)))
    (exists ((z-0 strd)) (and (p "server" z-0 5)
        (p "server" "cr" z-0 cr)
        (p "server" "sr" z-0 sr)
        (p "server" "spk" z-0 spk)
        (p "server" "s" z-0 s)
        (p "server" "cpk" z-0 cpk)
        (p "server" "c" z-0 c)
        (p "server" "ca" z-0 ca)
        (p "server" "x" z-0 x)
        (p "server" "y" z-0 y))))))
