
% Tests for the server-authenticated TLS roles.

% Test 1: Client and server can derive session keys.
test_session_keys :-
    tls13_session_keys(
        cr, sr, client_x, server_y,
        keys(CHK, SHK, CAK, SAK)),

    CHK = hash(_, client_hs_traffic, cr, sr),
    SHK = hash(_, server_hs_traffic, cr, sr),
    CAK = hash(client_ap_traffic, cr, sr, _),
    SAK = hash(server_ap_traffic, cr, sr, _).

% Test 2: Complete honest exchange.
test_honest_exchange :-
    tls13_honest_exchange(
        cr, sr, client_x, server_y,
        server, server_pk, server_sk, ca,
        request, response,
        Exchange),

    Exchange = exchange(
        cat(cr, exp(gen, client_x)),
        cat(sr, exp(gen, server_y)),
        enc(server_flight(_, _, _), _),
        enc(_, _),
        enc(request, _),
        enc(response, _)).

% Test 3: Application traffic keys are distinct.
test_distinct_traffic_keys :-
    tls13_session_keys(
        cr, sr, client_x, server_y,
        keys(_, _, CAK, SAK)),

    CAK = hash(client_ap_traffic, cr, sr, _),
    SAK = hash(server_ap_traffic, cr, sr, _).

% Run all role tests.
test_roles :-
    test_session_keys,
    test_honest_exchange,
    test_distinct_traffic_keys.

?- test_roles.
