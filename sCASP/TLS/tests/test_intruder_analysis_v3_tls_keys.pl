% TLS 1.3 intruder test:
% Mallory observes public DH shares and encrypted handshake messages.
% Mallory does not know either private DH exponent.

network_message(cat(cr, exp(gen, client_x))).
network_message(cat(sr, exp(gen, server_y))).

% Server flight encrypted with the server handshake key.
network_message(
    enc(
        server_flight(certificate, certificate_verify, server_finished),
        hash(dh_secret(client_x, server_y), 's hs traffic', cr, sr)
    )
).

% Client Finished encrypted with the client handshake key.
network_message(
    enc(
        client_finished,
        hash(dh_secret(client_x, server_y), 'c hs traffic', cr, sr)
    )
).

test_intruder_cannot_derive_handshake_keys :-
    tls13_session_keys(
        cr, sr, client_x, server_y,
        keys(CHK, SHK, _, _)
    ),

    CHK = hash(dh_secret(client_x, server_y), 'c hs traffic', cr, sr),
    SHK = hash(dh_secret(client_x, server_y), 's hs traffic', cr, sr),

    not intruder_knows(CHK),
    not intruder_knows(SHK).

?- test_intruder_cannot_derive_handshake_keys.
