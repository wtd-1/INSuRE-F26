network_message(enc(protected_secret, unknown_session_key)).
network_message(unknown_session_key).

test_decryption_with_observed_key :-
    intruder_knows(protected_secret).

?- test_decryption_with_observed_key.
