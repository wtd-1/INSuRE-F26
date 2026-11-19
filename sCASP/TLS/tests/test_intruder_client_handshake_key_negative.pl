initial_knowledge(mallory, client_random).
initial_knowledge(mallory, server_random).
initial_knowledge(mallory, exp(gen, client_x)).
initial_knowledge(mallory, exp(gen, server_y)).

test_intruder_cannot_derive_client_handshake_key :-
    client_handshake_key(
        client_random,
        server_random,
        dh_secret(client_x, server_y),
        Key
    ),
    not intruder_knows(dh_secret(client_x, server_y)),
    not intruder_knows(Key).

?- test_intruder_cannot_derive_client_handshake_key.
