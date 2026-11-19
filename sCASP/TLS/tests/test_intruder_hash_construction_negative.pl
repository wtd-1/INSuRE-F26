test_intruder_hash_unknown_input :-
    not intruder_knows(hash(privk(server), derived)).

?- test_intruder_hash_unknown_input.
