network_message(exp(gen, alice_x)).
network_message(exp(gen, server_y)).

test_public_shares_do_not_reveal_secret :-
    not intruder_knows(dh_secret(alice_x, server_y)).

?- test_public_shares_do_not_reveal_secret.
