
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
    test_reject_mallory_certificate.

?- test_tls13_security.