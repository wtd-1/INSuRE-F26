network_message(
    cat(
        client_hello,
        enc(server_flight(certificate, certificate_verify, server_finished),
            unknown_session_key)
    )
).

% Mallory observes the decryption key separately.
network_message(unknown_session_key).

test_extract_certificate :-
    intruder_knows(certificate).

test_extract_certificate_verify :-
    intruder_knows(certificate_verify).

test_extract_server_finished :-
    intruder_knows(server_finished).

?- test_extract_certificate.
?- test_extract_certificate_verify.
?- test_extract_server_finished.
