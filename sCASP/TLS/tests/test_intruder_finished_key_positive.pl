initial_knowledge(mallory, test_handshake_key).

test_intruder_derives_finished_key :-
    finished_key(test_handshake_key, FinishedKey),
    intruder_knows(FinishedKey).

?- test_intruder_derives_finished_key.
