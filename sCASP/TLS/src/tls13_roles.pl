
% TLS 1.3 server-authenticated roles
%
% Models one honest client/server execution.
% Requires tls13_terms.pl to be loaded separately.

% Derive keys from the shared DH secret.
tls13_session_keys(CR, SR, CX, SY,
                   keys(CHK, SHK, CAK, SAK)) :-
    dh_shared(CX, SY, HS),
    master_secret(HS, MS),
    client_handshake_key(CR, SR, HS, CHK),
    server_handshake_key(CR, SR, HS, SHK),
    client_application_key(CR, SR, MS, CAK),
    server_application_key(CR, SR, MS, SAK).

% Construct the server's authenticated flight.
tls13_server_flight(CR, SR, CX, SY,
                    Server, ServerPK, ServerSK, CA,
                    SHK, Hello, EncryptedFlight,
                    FinishedTranscript, ServerFinished) :-

    server_hello(SR, SY, Hello),

    certificate(Server, ServerPK, CA, Cert),

    server_cert_verify_transcript(
        CR, SR, CX, SY,
        Server, ServerPK, CA, CertTranscript),

    server_certificate_verify(
        CertTranscript, ServerSK, CertVerify),

    server_finished_transcript(
        CR, SR, CX, SY,
        Server, ServerPK, CA, ServerSK,
        FinishedTranscript),

    server_finished(
        FinishedTranscript, SHK, ServerFinished),

    server_flight(
        Cert, CertVerify, ServerFinished, Flight),

    encrypted_server_flight(
        Flight, SHK, EncryptedFlight).

% Construct the client's encrypted Finished message.
tls13_client_finished(ServerTranscript, ServerFinished,
                      CHK, EncryptedFinished) :-

    client_finished(
        ServerTranscript, ServerFinished,
        CHK, Finished),

    EncryptedFinished = enc(Finished, CHK).

% Complete honest execution.
tls13_honest_exchange(CR, SR, CX, SY,
                      Server, ServerPK, ServerSK, CA,
                      Request, Response,
                      exchange(ClientHello,
                               ServerHello,
                               EncryptedServerFlight,
                               EncryptedClientFinished,
                               EncryptedRequest,
                               EncryptedResponse)) :-

    client_hello(CR, CX, ClientHello),

    tls13_session_keys(
        CR, SR, CX, SY,
        keys(CHK, SHK, CAK, SAK)),

    tls13_server_flight(
        CR, SR, CX, SY,
        Server, ServerPK, ServerSK, CA,
        SHK, ServerHello, EncryptedServerFlight,
        ServerTranscript, ServerFinished),

    tls13_client_finished(
        ServerTranscript, ServerFinished,
        CHK, EncryptedClientFinished),

    EncryptedRequest = enc(Request, CAK),
    EncryptedResponse = enc(Response, SAK).
