test_session_keys :-
    tls13_session_keys(
        cr, sr, client_x, server_y,
        keys(CHK, SHK, CAK, SAK)),

    CHK = hash(_, 'c hs traffic', cr, sr),
    SHK = hash(_, 's hs traffic', cr, sr),
    CAK = hash('c ap traffic', cr, sr, _),
    SAK = hash('s ap traffic', cr, sr, _).

?- test_session_keys.
