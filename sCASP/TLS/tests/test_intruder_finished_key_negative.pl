test_intruder_cannot_derive_finished_key :-
    finished_key(test_handshake_key, FinishedKey),
    not intruder_knows(test_handshake_key),
    not intruder_knows(FinishedKey).

?- test_intruder_cannot_derive_finished_key.
