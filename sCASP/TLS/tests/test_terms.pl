
% TLS 1.3 symbolic term tests

% Test 1: DH public value
test_dh_public :-
    dh_public(alice_x, Result),
    Result = exp(gen, alice_x).

% Test 2: Both parties derive the same shared secret
test_dh_shared :-
    dh_shared(alice_x, bob_y, ClientSecret),
    dh_shared(alice_x, bob_y, ServerSecret),
    ClientSecret = ServerSecret.

% Test 3: Master secret construction
test_master_secret :-
    master_secret(hs_secret, Result),
    Result = hash(hs_secret, derived).

% Test 4: Client handshake traffic key
test_client_handshake_key :-
    client_handshake_key(cr, sr, hs_secret, Result),
    Result = hash(hs_secret, client_hs_traffic, cr, sr).

% Test 5: Server handshake traffic key
test_server_handshake_key :-
    server_handshake_key(cr, sr, hs_secret, Result),
    Result = hash(hs_secret, server_hs_traffic, cr, sr).

% Test 6: Client application traffic key
test_client_application_key :-
    client_application_key(cr, sr, ms_secret, Result),
    Result = hash(client_ap_traffic, cr, sr, ms_secret).

% Test 7: Server application traffic key
test_server_application_key :-
    server_application_key(cr, sr, ms_secret, Result),
    Result = hash(server_ap_traffic, cr, sr, ms_secret).

% Test 8: Finished key
test_finished_key :-
    finished_key(hs_key, Result),
    Result = hash(finished, hs_key).

% Test 9: Certificate construction
test_certificate :-
    certificate(server, server_pk, ca, Result),
    Result = cat(server, server_pk,
                 enc(hash(server, server_pk), privk(ca))).

% Test 10: CertificateVerify construction
test_certificate_verify :-
    certificate_verify(transcript, signing_key, Result),
    Result = enc(hash(transcript), signing_key).

test_dh_consistency :-
    dh_public(alice_x, DH),
    client_hello(cr, alice_x, Hello),
    Hello = cat(cr, DH).
	
% Run all tests
test_terms :-
    test_dh_public,
    test_dh_shared,
    test_master_secret,
    test_client_handshake_key,
    test_server_handshake_key,
    test_client_application_key,
    test_server_application_key,
    test_finished_key,
    test_certificate,
    test_certificate_verify,
    test_dh_consistency.

?- test_terms.
