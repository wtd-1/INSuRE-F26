network_message(enc(protected_secret, unknown_session_key)).

test_protection_without_key :-
    not intruder_knows(protected_secret).

?- test_protection_without_key.
