initial_knowledge(mallory, client_random).
initial_knowledge(mallory, server_random).
initial_knowledge(mallory, exp(gen, client_x)).
initial_knowledge(mallory, exp(gen, server_y)).

test_intruder_cannot_derive_server_application_key :-
    master_secret(dh_secret(client_x, server_y), MasterSecret),
    server_application_key(
        client_random,
        server_random,
        MasterSecret,
        ApplicationKey
    ),
    not intruder_knows(dh_secret(client_x, server_y)),
    not intruder_knows(MasterSecret),
    not intruder_knows(ApplicationKey).

?- test_intruder_cannot_derive_server_application_key.
