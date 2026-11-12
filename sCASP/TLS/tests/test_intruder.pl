% ==================================================
% TLS 1.3 Intruder Tests
% ==================================================

% --------------------------------------------------
% Network messages observed by Mallory
% --------------------------------------------------

% Test 2: Concatenated message
network_message(
    cat(client_random, client_key_share)
).

% Test 3: Symmetric ciphertext with known key
network_message(
    enc(secret_message, mallory_session_key)
).

% Test 4: Symmetric ciphertext with unknown key
network_message(
    enc(protected_secret, unknown_session_key)
).

% Test 5: Hash whose preimage is unknown
network_message(
    hash(private_value, salt)
).

% Test 6: Public-key ciphertext addressed to Mallory
network_message(
    enc(mallory_private_message, pubk(mallory))
).

% Test 7: Public-key ciphertext addressed to the client
network_message(
    enc(client_private_message, pubk(client))
).

% Test 8: Signature from a known signer
network_message(
    enc(hash(server_signed_data), privk(server))
).

% Test 9: Signature from an unknown signer
network_message(
    enc(hash(unknown_signed_data), privk(unknown_signer))
).

% --------------------------------------------------
% Diffie-Hellman public shares observed by Mallory
% --------------------------------------------------

network_message(
    exp(gen, alice_x)
).

network_message(
    exp(gen, bob_y)
).

% Test 12: Three-part concatenation (certificate shape)
network_message(
    cat(cert_party, cert_key, cert_signature)
).

% Test 13: A key learned from one message opens another
network_message(
    enc(inner_key, mallory_session_key)
).

network_message(
    enc(nested_secret, inner_key)
).

% Test 14: Traffic protected by a key derived from a DH
% exchange whose client exponent has leaked
network_message(
    cat(leak_cr, exp(gen, leaked_x))
).

network_message(
    cat(leak_sr, exp(gen, leak_y))
).

network_message(
    enc(dh_protected_secret,
        hash(dh_secret(leaked_x, leak_y),
             client_hs_traffic, leak_cr, leak_sr))
).

% --------------------------------------------------
% Additional initial knowledge
% --------------------------------------------------

initial_knowledge(mallory, mallory_session_key).
initial_knowledge(mallory, leaked_x).

% --------------------------------------------------
% Test 1: Public knowledge
% --------------------------------------------------

test_public_knowledge :-
    intruder_knows(gen),
    intruder_knows(pubk(ca)).

% --------------------------------------------------
% Test 2: Message decomposition
% --------------------------------------------------

test_message_decomposition :-
    intruder_knows(client_random),
    intruder_knows(client_key_share).

% --------------------------------------------------
% Test 3: Symmetric decryption with known key
% --------------------------------------------------

test_symmetric_decryption :-
    intruder_can_decrypt_symmetric(
        enc(secret_message, mallory_session_key),
        secret_message
    ),
    intruder_knows(secret_message).

% --------------------------------------------------
% Test 4: Protection without symmetric key
% --------------------------------------------------

test_protection_without_key :-
    not intruder_knows(protected_secret).

% --------------------------------------------------
% Test 5: Hash preimage protection
% --------------------------------------------------

test_hash_one_way :-
    intruder_knows(hash(private_value, salt)),
    not intruder_knows(private_value).

% --------------------------------------------------
% Test 6: Public-key decryption using Mallory's key
% --------------------------------------------------

test_public_key_decryption :-
    intruder_can_decrypt_public_key(
        enc(mallory_private_message, pubk(mallory)),
        mallory_private_message
    ),
    intruder_knows(mallory_private_message).

% --------------------------------------------------
% Test 7: Cannot decrypt using only public key
% --------------------------------------------------

test_public_key_protection :-
    not intruder_knows(client_private_message).

% --------------------------------------------------
% Test 8: Signature verification with known public key
% --------------------------------------------------

test_signature_verification :-
    intruder_can_verify_signature(
        enc(hash(server_signed_data), privk(server)),
        hash(server_signed_data)
    ),
    intruder_knows(hash(server_signed_data)).

% --------------------------------------------------
% Test 9: Cannot verify without signer's public key
% --------------------------------------------------

test_signature_protection :-
    not intruder_knows(hash(unknown_signed_data)).

% --------------------------------------------------
% Test 10: Mallory observes public DH shares
% --------------------------------------------------

test_dh_public_share_observation :-
    intruder_knows(exp(gen, alice_x)),
    intruder_knows(exp(gen, bob_y)).

% --------------------------------------------------
% Test 11: Mallory cannot derive the DH shared secret
% --------------------------------------------------

test_dh_shared_secret_protection :-
    not intruder_knows(dh_secret(alice_x, bob_y)),
    not intruder_knows(alice_x),
    not intruder_knows(bob_y).

% --------------------------------------------------
% Test 12: Three-part concatenation decomposition
% --------------------------------------------------

test_triple_decomposition :-
    intruder_knows(cert_party),
    intruder_knows(cert_key),
    intruder_knows(cert_signature).

% --------------------------------------------------
% Test 13: Decryption with a derived key
% --------------------------------------------------

test_derived_key_decryption :-
    intruder_knows(inner_key),
    intruder_knows(nested_secret).

% --------------------------------------------------
% Test 14: Leaked DH exponent exposes traffic
% --------------------------------------------------

test_dh_compromise :-
    intruder_knows(dh_secret(leaked_x, leak_y)),
    intruder_knows(dh_protected_secret),
    not intruder_knows(leak_y).

% --------------------------------------------------
% Run all tests
% --------------------------------------------------

test_intruder :-
    test_public_knowledge,
    test_message_decomposition,
    test_symmetric_decryption,
    test_protection_without_key,
    test_hash_one_way,
    test_public_key_decryption,
    test_public_key_protection,
    test_signature_verification,
    test_signature_protection,
    test_dh_public_share_observation,
    test_dh_shared_secret_protection,
    test_triple_decomposition,
    test_derived_key_decryption,
    test_dh_compromise.
    
?- test_intruder.