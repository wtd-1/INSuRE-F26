network_message(cat(cr, exp(gen, client_x))).
network_message(cat(sr, exp(gen, server_y))).

network_message(
    enc(
        server_flight(certificate, certificate_verify, server_finished),
        hash(dh_secret(client_x, server_y), 's hs traffic', cr, sr)
    )
).

network_message(
    enc(
        client_finished,
        hash(dh_secret(client_x, server_y), 'c hs traffic', cr, sr)
    )
).

test_intruder_cannot_derive_handshake_secret :-
    not intruder_knows(dh_secret(client_x, server_y)).

?- test_intruder_cannot_derive_handshake_secret.
