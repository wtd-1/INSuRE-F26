% Focused checks for structural alignment with TLS1.3_macros.lisp.
% Load tls13_terms.pl, tls13_roles.pl, tls13_intruder.pl,
% tls13_analysis.pl, and this file in that order.

% No compromise in this structural-alignment scenario.
leaked(nothing).

% Exact key-schedule labels from the CPSA macros.
test_cpsa_key_schedule_labels :-
    tls13_session_keys(cr, sr, client_x, server_y,
                       keys(CHK, SHK, CAK, SAK)),
    CHK = hash(_, 'c hs traffic', cr, sr),
    SHK = hash(_, 's hs traffic', cr, sr),
    CAK = hash('c ap traffic', cr, sr, _),
    SAK = hash('s ap traffic', cr, sr, _).

% The CPSA TLS macro sends ServerHello concatenated with the
% encrypted server flight as one network event.
test_cpsa_server_flight_wire_event :-
    honest_exchange(exchange(ClientHello, ServerHello,
                             EncryptedServerFlight,
                             EncryptedClientFinished,
                             EncryptedRequest,
                             EncryptedResponse)),
    network_message(ClientHello),
    network_message(cat(ServerHello, EncryptedServerFlight)),
    network_message(EncryptedClientFinished),
    network_message(EncryptedRequest),
    network_message(EncryptedResponse),
    not network_message(ServerHello),
    not network_message(EncryptedServerFlight).

test_cpsa_alignment :-
    test_cpsa_key_schedule_labels,
    test_cpsa_server_flight_wire_event.

?- test_cpsa_alignment.
