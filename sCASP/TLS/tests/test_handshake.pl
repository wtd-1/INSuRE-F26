
% TLS 1.3 server-authenticated handshake construction tests

% Test 1: ClientHello
test_client_hello :-
    client_hello(cr, alice_x, Result),
    Result = cat(cr, exp(gen, alice_x)).

% Test 2: ServerHello
test_server_hello :-
    server_hello(sr, bob_y, Result),
    Result = cat(sr, exp(gen, bob_y)).

% Test 3: Server CertificateVerify transcript
test_server_cert_transcript :-
    server_cert_verify_transcript(
        cr, sr, alice_x, bob_y,
        server, server_pk, ca, Result),

    Result = transcript(
        cat(cr, exp(gen, alice_x)),
        cat(sr, exp(gen, bob_y)),
        cat(server, server_pk,
            enc(hash(server, server_pk), privk(ca)))
    ).

% Test 4: Server CertificateVerify
test_server_cert_verify :-
    server_certificate_verify(
        server_transcript, server_sk, Result),

    Result = enc(hash(server_transcript), server_sk).

% Test 5: Server Finished transcript
test_server_finished_transcript :-
    server_finished_transcript(
        cr, sr, alice_x, bob_y,
        server, server_pk, ca, server_sk, Result),

    Result = transcript(
        _,
        enc(_, server_sk)
    ).

% Test 6: Server Finished
test_server_finished :-
    server_finished(
        server_transcript,
        server_hs_key,
        Result),

    Result = hash(
        hash(finished, server_hs_key),
        server_transcript
    ).

% Test 7: Client Finished transcript
test_client_finished_transcript :-
    client_finished_transcript(
        server_transcript,
        server_finished_message,
        Result),

    Result = transcript(
        server_transcript,
        server_finished_message
    ).

% Test 8: Client Finished
test_client_finished :-
    client_finished(
        server_transcript,
        server_finished_message,
        client_hs_key,
        Result),

    Result = hash(
        hash(finished, client_hs_key),
        transcript(server_transcript, server_finished_message)
    ).

% Test 9: Server flight construction
test_server_flight :-
    server_flight(cert, cert_verify, finished, Result),
    Result = server_flight(cert, cert_verify, finished).

% Test 10: Encryption of server flight
test_encrypted_server_flight :-
    server_flight(cert, cert_verify, finished, Flight),

    encrypted_server_flight(
        Flight, server_hs_key, Result),

    Result = enc(
        server_flight(cert, cert_verify, finished),
        server_hs_key
    ).

% Run all tests
test_handshake :-
    test_client_hello,
    test_server_hello,
    test_server_cert_transcript,
    test_server_cert_verify,
    test_server_finished_transcript,
    test_server_finished,
    test_client_finished_transcript,
    test_client_finished,
    test_server_flight,
    test_encrypted_server_flight.

?- test_handshake.
