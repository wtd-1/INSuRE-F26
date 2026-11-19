network_message(enc(bob_secret, pubk(bob))).

test_cannot_decrypt_without_private_key :-
    not intruder_knows(bob_secret).

?- test_cannot_decrypt_without_private_key.
