network_message(exp(gen, alice_x)).

test_public_share_does_not_reveal_exponent :-
    not intruder_knows(alice_x).

?- test_public_share_does_not_reveal_exponent.
