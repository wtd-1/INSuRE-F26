;; m1: CertificateVerify signed with ['serverprivkey'] deleted ({'serverprivkey': 4} occurrences)

(defmacro (DHpublic exponent) (exp (gen) exponent))

(defmacro (ClientHello random exponent) (cat random (DHpublic exponent)))

(defmacro (ServerHello random exponent) (cat random (DHpublic exponent)))

(defmacro (HandshakeSecret key_share exponent) (exp key_share exponent))

(defmacro (MasterSecret secret) (hash secret "derived"))

(defmacro (ClientHandshakeKey client_random server_random secret) (hash secret "c hs traffic" client_random server_random))

(defmacro (ServerHandshakeKey client_random server_random secret) (hash secret "s hs traffic" client_random server_random))

(defmacro (ServerApKey client_random server_random master_secret) (hash "s ap traffic" client_random server_random master_secret))

(defmacro (ClientApKey client_random server_random master_secret) (hash "c ap traffic" client_random server_random master_secret))

(defmacro (finish_key key) (hash "finished" key))

(defmacro (Certificate party publickey ca) (cat party publickey (enc (hash party publickey) (privk ca))))

(defmacro (CertificateVerify messages key) (enc (hash messages) key))

(defmacro (ServerCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey ca) (^ (ClientHello client_random client_expt) (ServerHello server_random server_expt) (Certificate server serverpubkey ca)))

(defmacro (ClientCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey ca handshakesecret) (^ (ServerCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey ca) (^) (Finish (ServerFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey ca) (ServerHandshakeKey client_random server_random handshakesecret)) (Certificate client clientpubkey ca)))

(defmacro (Finish messages key) (hash (finish_key key) messages))

(defmacro (ServerFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey ca) (^ (ServerCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey ca) (^)))

(defmacro (ClientFinishedMesgs_nocert client_random server_random client_expt server_expt server serverpubkey serverprivkey ca handshakesecret) (^ (ServerFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey ca) (Finish (ServerFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey ca) (ServerHandshakeKey client_random server_random handshakesecret))))

(defmacro (ClientFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey clientprivkey ca handshakesecret) (^ (ClientCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey ca handshakesecret) (CertificateVerify (ClientCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey ca handshakesecret) clientprivkey)))

(defmacro (TLS d1 d2 client_random server_random client_expt server_expt server serverpubkey serverprivkey ca handshakesecret) (^ (d1 (ClientHello client_random client_expt)) (d2 (cat (ServerHello server_random server_expt) (enc (Certificate server serverpubkey ca) (^) (Finish (ServerFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey ca) (ServerHandshakeKey client_random server_random handshakesecret)) (ServerHandshakeKey client_random server_random handshakesecret)))) (d1 (enc (Finish (ClientFinishedMesgs_nocert client_random server_random client_expt server_expt server serverpubkey serverprivkey ca handshakesecret) (ClientHandshakeKey client_random server_random handshakesecret)) (ClientHandshakeKey client_random server_random handshakesecret)))))

(defmacro (mTLS d1 d2 client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey clientprivkey ca handshakesecret) (^ (d1 (ClientHello client_random client_expt)) (d2 (cat (ServerHello server_random server_expt) (enc (Certificate server serverpubkey ca) (^) (Finish (ServerFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey ca) (ServerHandshakeKey client_random server_random handshakesecret)) (ServerHandshakeKey client_random server_random handshakesecret)))) (d1 (enc (Certificate client clientpubkey ca) (CertificateVerify (ClientCertVerifyMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey ca handshakesecret) clientprivkey) (Finish (ClientFinishedMesgs client_random server_random client_expt server_expt server serverpubkey serverprivkey client clientpubkey clientprivkey ca handshakesecret) (ClientHandshakeKey client_random server_random handshakesecret)) (ClientHandshakeKey client_random server_random handshakesecret)))))
