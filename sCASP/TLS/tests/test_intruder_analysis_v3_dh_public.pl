network_message(exp(gen, alice_x)).

test_intruder_knows_public_dh_share :-
    intruder_knows(exp(gen, alice_x)).

?- test_intruder_knows_public_dh_share.
