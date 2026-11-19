initial_knowledge(mallory, dh_secret(alice_x, server_y)).

test_known_shared_secret :-
    intruder_knows(dh_secret(alice_x, server_y)).

?- test_known_shared_secret.
