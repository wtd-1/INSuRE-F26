(herald "Verification of TLS 1.3 rules to assist in mTLS verification"
	(try-old-strands)
	)

(include "../../TLS1.3_macros.lisp")

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

(defgoal mtls13 (forall
  ((cr sr random32) (cpk akey) (c ca name) (x expt) (y rndx) (z z-0 strd))
  (implies (and (p "server" z 5) (p "" z-0 2) (p "server" "cr" z cr)
      (p "server" "sr" z sr) (p "server" "cpk" z cpk) (p "server" "c" z c)
      (p "server" "ca" z ca) (p "server" "x" z x) (p "server" "y" z y)
      (p "" "x" z-0 (hash "c ap traffic" cr sr (hash (exp (gen) (mul x y)) "derived")))
      (non (invk cpk)) (uniq-at sr z 1) (ugen y)) (false))))
