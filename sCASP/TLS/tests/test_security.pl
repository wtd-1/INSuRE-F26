
% ==================================================
% TLS 1.3 Integrated Security Tests
% ==================================================

% --------------------------------------------------
% Test 1: Honest client accepts the genuine server
% --------------------------------------------------

test_honest_server_authentication :-

    honest_server_authentication(
        Certificate,
        CertificateVerify,
        Finished
    ),

    client_accepts_server(
        Certificate,
        CertificateVerify,
        Finished
    ).

% --------------------------------------------------
% Test 2: Mallory observes public DH shares
% --------------------------------------------------

test_public_dh_observation :-

    intruder_knows(exp(gen, client_x)),
    intruder_knows(exp(gen, server_y)).

% --------------------------------------------------
% Test 3: Mallory cannot learn handshake keys
% --------------------------------------------------

test_handshake_key_secrecy :-

    server_handshake_key_secret,
    client_handshake_key_secret.

% --------------------------------------------------
% Test 4: Mallory cannot learn application keys
% --------------------------------------------------

test_application_key_secrecy :-

    application_keys_secret.

% --------------------------------------------------
% Test 5: Mallory sees ciphertext but not plaintext
% --------------------------------------------------

test_encrypted_server_flight_protection :-

    tls13_security_exchange(
        exchange(
            _,
            _,
            EncryptedServerFlight,
            _,
            _,
            _
        )
    ),

    intruder_knows(EncryptedServerFlight),

    EncryptedServerFlight =
        enc(ServerFlight, ServerHandshakeKey),

    tls13_security_keys(
        keys(_, ServerHandshakeKey, _, _)
    ),

    not intruder_knows(ServerFlight).

% --------------------------------------------------
% Test 6: Client rejects a forged CertificateVerify
% --------------------------------------------------

test_reject_forged_certificate_verify :-

    honest_server_authentication(
        Certificate,
        _CorrectCertificateVerify,
        Finished
    ),

    server_cert_verify_transcript(
        cr,
        sr,
        client_x,
        server_y,
        server,
        server_pk,
        ca,
        Transcript
    ),

    not client_accepts_server(
        Certificate,
        enc(hash(Transcript), mallory_sk),
        Finished
    ).

% --------------------------------------------------
% Test 7: Client rejects a modified Finished message
% --------------------------------------------------

test_reject_modified_finished :-

    honest_server_authentication(
        Certificate,
        CertificateVerify,
        _CorrectFinished
    ),

    not client_accepts_server(
        Certificate,
        CertificateVerify,
        mallory_finished
    ).

% --------------------------------------------------
% Test 8: Client rejects Mallory's certificate
% --------------------------------------------------

test_reject_mallory_certificate :-

    honest_server_authentication(
        _Certificate,
        CertificateVerify,
        Finished
    ),

    not client_accepts_server(
        cat(
            mallory,
            mallory_pk,
            enc(hash(mallory, mallory_pk), privk(mallory))
        ),
        CertificateVerify,
        Finished
    ).


% --------------------------------------------------
% Test 9: Client completes the handshake successfully
% --------------------------------------------------

test_client_completes_handshake :-

    honest_server_authentication(
        Certificate,
        CertificateVerify,
        ServerFinished
    ),

    client_completes_handshake(
        Certificate,
        CertificateVerify,
        ServerFinished,
        EncryptedClientFinished
    ),

    tls13_security_keys(
        keys(ClientHandshakeKey, _, _, _)
    ),

    EncryptedClientFinished =
        enc(ClientFinished, ClientHandshakeKey).


% --------------------------------------------------
% Test 10: Client Finished has the expected contents
% --------------------------------------------------

test_client_finished_contents :-

    honest_server_authentication(
        Certificate,
        CertificateVerify,
        ServerFinished
    ),

    client_completes_handshake(
        Certificate,
        CertificateVerify,
        ServerFinished,
        enc(ClientFinished, ClientHandshakeKey)
    ),

    server_finished_transcript(
        cr, sr, client_x, server_y,
        server, server_pk, ca, server_sk,
        ServerTranscript
    ),

    tls13_security_keys(
        keys(ExpectedClientHandshakeKey, _, _, _)
    ),

    ClientHandshakeKey = ExpectedClientHandshakeKey,

    client_finished(
        ServerTranscript,
        ServerFinished,
        ExpectedClientHandshakeKey,
        ClientFinished
    ).


% --------------------------------------------------
% Test 11: Client rejects a forged CertificateVerify
% during handshake completion
% --------------------------------------------------

test_reject_forged_client_handshake :-

    honest_server_authentication(
        Certificate,
        _CorrectCertificateVerify,
        ServerFinished
    ),

    server_cert_verify_transcript(
        cr, sr, client_x, server_y,
        server, server_pk, ca, Transcript
    ),

    not client_completes_handshake(
        Certificate,
        enc(hash(Transcript), mallory_sk),
        ServerFinished,
        _
    ).


% --------------------------------------------------
% Test 12: Client rejects a modified server Finished
% during handshake completion
% --------------------------------------------------

test_reject_modified_client_handshake :-

    honest_server_authentication(
        Certificate,
        CertificateVerify,
        _CorrectServerFinished
    ),

    not client_completes_handshake(
        Certificate,
        CertificateVerify,
        mallory_finished,
        _
    ).

% --------------------------------------------------
% Run all tests
% --------------------------------------------------

test_tls13_security :-

    test_honest_server_authentication,
    test_public_dh_observation,
    test_handshake_key_secrecy,
    test_application_key_secrecy,
    test_encrypted_server_flight_protection,
    test_reject_forged_certificate_verify,
    test_reject_modified_finished,
    test_reject_mallory_certificate,
    test_client_completes_handshake,
    test_client_finished_contents,
    test_reject_forged_client_handshake,
    test_reject_modified_client_handshake.

?- test_tls13_security.