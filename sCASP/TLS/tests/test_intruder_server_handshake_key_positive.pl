initial_knowledge(mallory, test_hs).
initial_knowledge(mallory, client_random).
initial_knowledge(mallory, server_random).

test_intruder_derives_server_handshake_key :-
    server_handshake_key(
        client_random,
        server_random,
        test_hs,
        Key
    ),
    intruder_knows(Key).

?- test_intruder_derives_server_handshake_key.
