initial_knowledge(mallory, test_hs).
initial_knowledge(mallory, client_random).
initial_knowledge(mallory, server_random).

test_intruder_derives_server_application_key :-
    master_secret(test_hs, MasterSecret),
    server_application_key(
        client_random,
        server_random,
        MasterSecret,
        ApplicationKey
    ),
    intruder_knows(MasterSecret),
    intruder_knows(ApplicationKey).

?- test_intruder_derives_server_application_key.
