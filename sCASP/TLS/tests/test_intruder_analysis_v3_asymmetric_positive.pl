initial_knowledge(mallory, privk(alice)).
network_message(enc(asymmetric_secret, pubk(alice))).

test_decrypt_with_private_key :-
    intruder_knows(asymmetric_secret).

?- test_decrypt_with_private_key.
