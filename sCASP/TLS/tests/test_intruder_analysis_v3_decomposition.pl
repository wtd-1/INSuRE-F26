network_message(
    cat(
        client_hello,
        enc(server_flight(certificate, certificate_verify, server_finished),
            unknown_session_key)
    )
).

test_extract_client_hello :-
    intruder_knows(client_hello).

test_cannot_extract_encrypted_certificate :-
    not intruder_knows(certificate).

?- test_extract_client_hello.
?- test_cannot_extract_encrypted_certificate.
