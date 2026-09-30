;; TLS 1.3 macros for both server-only authentication and mutual authentication.
;;
;; BASELINE-v1 and BASELINE-v2 (identical macro file). Derived from BIDS/CPSA Models/TLS1.3_macros.lisp. See
;; CHANGELOG.md for the fixes applied here (F4, F5) and for the
;; instrumentation refactor (R1). R1 routes every mutation point through a
;; named macro whose baseline body is the original term, so each mutation
;; variant differs from this file in exactly one line. R1 does not change the
;; model: `cpsa4 -e` output is byte-identical to the un-instrumented fixed
;; model (see check_expansion.sh).
;;
;; Deletion is written as (^), which cpsa4 splices out of the enclosing list,
;; so a macro whose body is (^) removes its term everywhere it is used.

(defmacro (DHpublic exponent)
    (exp (gen) exponent))

;; Initial Hello messages provide values for key derivation (the only
;; unencrypted messages in the protocol). key_share can be a Diffie_Hellman
;; value, Pre-Shared Key (PSK) or both. We model using Diffie_Hellman.

(defmacro (ClientHello random exponent)
    (cat random (DHpublic exponent))) ;; key_share is DHpublic

(defmacro (ServerHello random exponent)
    (cat random (DHpublic exponent))) ;; key_share is DHpublic

;; Secret Derivation

(defmacro (HandshakeSecret key_share exponent)
    (exp key_share exponent))

(defmacro (MasterSecret secret)
    (hash secret "derived"))

;; Key derivations from computed secrets

(defmacro (ClientHandshakeKey client_random server_random secret)
    (hash secret "c hs traffic" client_random server_random))

(defmacro (ServerHandshakeKey client_random server_random secret)
    (hash secret "s hs traffic" client_random server_random))

;; simplified ApKey derivation, used by the applications for encryption (actual
;; derivation would include all messages received in the hash.)

(defmacro (ServerApKey client_random server_random master_secret)
    (hash "s ap traffic" client_random server_random master_secret))

(defmacro (ClientApKey client_random server_random master_secret)
    (hash "c ap traffic" client_random server_random master_secret))

(defmacro (finish_key key) ;; MAC key for the Finished message
    (hash "finished" key)) ;; uses handshake key

;; ====================================================================
;; MUTATION POINTS (R1). Each variant edits exactly one body line below.
;; ====================================================================

;; [m4] Freshness of the server's DH exponent (role annotation).
(defmacro (ServerDHFresh exponent)
    (^))

;; [m4c] Freshness of the client's DH exponent (role annotation).
(defmacro (ClientDHFresh exponent)
    (uniq-gen exponent))

;; [m8] CertificateVerify, both roles.
(defmacro (CertificateVerify messages key)
    (enc (hash messages) key))

;; [m7] Client Certificate. F5: tagged "client" (X.509 clientAuth key usage).
(defmacro (ClientCertificate party publickey ca)
    (cat party publickey (enc (hash "client" party publickey) (privk ca))))

;; [m2] Transcript covered by the server's CertificateVerify signature.
(defmacro (ServerSignedMesgs client_random server_random client_expt
			     server_expt server serverpubkey ca)
    (ServerCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey ca))

;; [m1] The server's CertificateVerify, on the wire and in every transcript.
(defmacro (ServerCertificateVerify client_random server_random client_expt
				   server_expt server serverpubkey serverprivkey
				   ca)
    (CertificateVerify (ServerSignedMesgs client_random server_random client_expt server_expt server serverpubkey ca) serverprivkey))

;; [m6] The client's CertificateVerify, on the wire and in every transcript.
(defmacro (ClientCertificateVerify client_random server_random client_expt
				   server_expt server serverpubkey serverprivkey
				   client clientpubkey clientprivkey ca
				   handshakesecret)
    (CertificateVerify (ClientCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey ca handshakesecret) clientprivkey))

;; [m3, m3s, m3c] Finished selectors. Each call site passes the present term
;; and its deleted form. Inside a list the deleted form is (^); where the
;; Finished is an entire message (server-only client flight) it is a public
;; constant, which keeps the node index stable and gives the adversary nothing.
(defmacro (FinishedSel present deleted)
    present)
(defmacro (ServerFinishedSel present deleted)
    (FinishedSel present deleted))
(defmacro (ClientFinishedSel present deleted)
    (FinishedSel present deleted))

;; ====================================================================

;; Encrypted handshake messages

(defmacro (Certificate party publickey ca)
    (cat party publickey (enc (hash party publickey) (privk ca))))

(defmacro (ServerCertVerifyMesgs client_random server_random client_expt
				 server_expt server serverpubkey ca)
    (^
     (ClientHello client_random client_expt)
     (ServerHello server_random server_expt)
     (Certificate server serverpubkey ca)))

;; F4: ServerFinishedMesgs takes client_expt before server_expt; the original
;; passed them swapped here.
(defmacro (ClientCertVerifyMesgs client_random server_random client_expt
				 server_expt server serverpubkey serverprivkey
				 client clientpubkey ca handshakesecret)
    (^
     (ServerCertVerifyMesgs client_random server_random client_expt server_expt
			    server serverpubkey ca)
     (ServerCertificateVerify client_random server_random client_expt
			      server_expt server serverpubkey serverprivkey ca)
     (ServerFinishedSel
      (ServerFinished client_random server_random client_expt server_expt
		      server serverpubkey serverprivkey ca handshakesecret)
      (^))
     (ClientCertificate client clientpubkey ca)))

(defmacro (Finish messages key)
    (hash (finish_key key) messages))

(defmacro (ServerFinishedMesgs client_random server_random client_expt
			       server_expt server serverpubkey serverprivkey ca)
    (^
     (ServerCertVerifyMesgs client_random server_random client_expt server_expt
			    server serverpubkey ca)
     (ServerCertificateVerify client_random server_random client_expt
			      server_expt server serverpubkey serverprivkey ca)))

(defmacro (ServerFinished client_random server_random client_expt server_expt
			  server serverpubkey serverprivkey ca handshakesecret)
    (Finish
     (ServerFinishedMesgs client_random server_random client_expt server_expt
			  server serverpubkey serverprivkey ca)
     (ServerHandshakeKey client_random server_random handshakesecret)))

(defmacro (ClientFinishedMesgs_nocert client_random server_random client_expt
				      server_expt server serverpubkey
				      serverprivkey ca handshakesecret)
    (^
     (ServerFinishedMesgs client_random server_random client_expt server_expt
			  server serverpubkey serverprivkey ca)
     (ServerFinishedSel
      (ServerFinished client_random server_random client_expt server_expt
		      server serverpubkey serverprivkey ca handshakesecret)
      (^))))

(defmacro (ClientFinishedMesgs client_random server_random client_expt
			       server_expt server serverpubkey serverprivkey
			       client clientpubkey clientprivkey ca
			       handshakesecret)
    (^
     (ClientCertVerifyMesgs client_random server_random client_expt server_expt
			    server serverpubkey serverprivkey client
			    clientpubkey ca handshakesecret)
     (ClientCertificateVerify client_random server_random client_expt
			      server_expt server serverpubkey serverprivkey
			      client clientpubkey clientprivkey ca
			      handshakesecret)))

;; TLS macros: Server Authentication (TLS) and Mutual Authentication (mTLS)

;; Notes on using the macros. d1 and d2 are direction and are replaced with
;; send and receive, depending upon whether it is the client and the server. The
;; handshakesecret exists as the client and the server compute the secret in
;; different ways. The handshakesecret should be replaced with the correct secret
;; computation for the given role. For a client with a client_random variable of
;; x and the server_random variable of y with client_random of cr and
;; server_random of sr, the handshakesecret = (HandshakeSecret (DHpublic y) x).
;; For the server it will be (HandshakeSecret (DHpublic x) y).

;; Server flight shared by TLS and mTLS.
(defmacro (ServerFlight client_random server_random client_expt server_expt
			server serverpubkey serverprivkey ca handshakesecret)
    (cat (ServerHello server_random server_expt)
	 (enc (Certificate server serverpubkey ca)
	      (ServerCertificateVerify client_random server_random client_expt
				       server_expt server serverpubkey
				       serverprivkey ca)
	      (ServerFinishedSel
	       (ServerFinished client_random server_random client_expt
			       server_expt server serverpubkey serverprivkey ca
			       handshakesecret)
	       (^))
	      (ServerHandshakeKey client_random server_random
				  handshakesecret))))

;; TLS with Server Authentication only (Handshake Protocol)
(defmacro (TLS d1 d2 client_random server_random client_expt server_expt server
	       serverpubkey serverprivkey ca handshakesecret)
    (^
     (d1 (ClientHello client_random client_expt))
     (d2 (ServerFlight client_random server_random client_expt server_expt
		       server serverpubkey serverprivkey ca handshakesecret))
     (d1 (ClientFinishedSel
	  (enc (Finish
		(ClientFinishedMesgs_nocert client_random server_random
					    client_expt server_expt server
					    serverpubkey serverprivkey ca
					    handshakesecret)
		(ClientHandshakeKey client_random server_random
				    handshakesecret))
	       (ClientHandshakeKey client_random server_random
				   handshakesecret))
	  "client-finished-deleted"))))

;; Mutual TLS (Handshake Protocol)
(defmacro (mTLS d1 d2 client_random server_random client_expt server_expt server
		serverpubkey serverprivkey client clientpubkey clientprivkey ca
		handshakesecret)
    (^
     (d1 (ClientHello client_random client_expt))
     (d2 (ServerFlight client_random server_random client_expt server_expt
		       server serverpubkey serverprivkey ca handshakesecret))
     (d1 (enc (ClientCertificate client clientpubkey ca)
	      (ClientCertificateVerify client_random server_random client_expt
				       server_expt server serverpubkey
				       serverprivkey client clientpubkey
				       clientprivkey ca handshakesecret)
	      (ClientFinishedSel
	       (Finish
		(ClientFinishedMesgs client_random server_random client_expt
				     server_expt server serverpubkey
				     serverprivkey client clientpubkey
				     clientprivkey ca handshakesecret)
		(ClientHandshakeKey client_random server_random
				    handshakesecret))
	       (^))
	      (ClientHandshakeKey client_random server_random
				  handshakesecret)))))
