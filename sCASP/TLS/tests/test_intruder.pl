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
    senc(secret_message, mallory_session_key)
).

% Test 4: Symmetric ciphertext with unknown key
network_message(
    senc(protected_secret, unknown_session_key)
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
% Additional initial knowledge
% --------------------------------------------------

initial_knowledge(mallory, mallory_session_key).

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
    test_signature_protection.

?- test_intruder.