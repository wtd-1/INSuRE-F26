test_intruder_nested_hash_construction :-
    intruder_knows(
        hash(hash(finished, derived),
             'c hs traffic',
             client,
             server)
    ).

?- test_intruder_nested_hash_construction.
