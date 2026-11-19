
% ==================================================
% TLS 1.3 Integrated Security Model
% ==================================================
%
% Bounded symbolic model of an honest TLS 1.3
% client/server handshake with a network intruder.
%
% Requires:
%   tls13_terms.pl
%   tls13_roles.pl
%   tls13_intruder.pl
%
% This model abstracts cryptographic operations.
% It does not implement concrete TLS cryptography.

% --------------------------------------------------
% 1. Fixed honest-session parameters
% --------------------------------------------------

tls13_security_parameters(
    cr,
    sr,
    client_x,
    server_y,
    server,
    server_pk,
    server_sk,
    ca
).

% The server's signing key pair.
server_key_pair(server_pk, server_sk).

% --------------------------------------------------
% 2. Honest session keys
% --------------------------------------------------

tls13_security_keys(
    keys(ClientHandshakeKey,
         ServerHandshakeKey,
         ClientApplicationKey,
         ServerApplicationKey)
) :-
    tls13_session_keys(
        cr,
        sr,
        client_x,
        server_y,
        keys(ClientHandshakeKey,
             ServerHandshakeKey,
             ClientApplicationKey,
             ServerApplicationKey)
    ).

% --------------------------------------------------
% 3. Network messages
% --------------------------------------------------

% Public DH shares are visible to Mallory.
network_message(exp(gen, client_x)).
network_message(exp(gen, server_y)).

% The server flight is encrypted with the server
% handshake traffic key.
network_message(
    enc(
        server_flight_ciphertext,
        hash(dh_secret(client_x, server_y),
             's hs traffic',
             cr,
             sr)
    )
).

% The client Finished message is encrypted with the
% client handshake traffic key.
network_message(
    enc(
        client_finished_ciphertext,
        hash(dh_secret(client_x, server_y),
             'c hs traffic',
             cr,
             sr)
    )
).

% Application data records.
network_message(
    enc(
        application_request_ciphertext,
        hash('c ap traffic',
             cr,
             sr,
             hash(dh_secret(client_x, server_y), derived))
    )
).

network_message(
    enc(
        application_response_ciphertext,
        hash('s ap traffic',
             cr,
             sr,
             hash(dh_secret(client_x, server_y), derived))
    )
).

% --------------------------------------------------
% 4. Server flight delivery
% --------------------------------------------------

% The client receives the server's encrypted flight.
% The client can decrypt it using its independently
% derived server handshake traffic key.

server_flight_delivered :-
    network_message(
        enc(
            server_flight_ciphertext,
            hash(dh_secret(client_x, server_y),
                 's hs traffic',
                 cr,
                 sr)
        )
    ).

% --------------------------------------------------
% 5. Server certificate verification
% --------------------------------------------------

% The certificate must identify the expected server,
% contain the expected public key, and be signed by
% the trusted CA in this symbolic model.

valid_server_certificate(Certificate) :-
    certificate(server, server_pk, ca, Certificate).

% --------------------------------------------------
% 6. CertificateVerify verification
% --------------------------------------------------

% The expected server signing key must correspond
% to the public key in the trusted server certificate.

valid_server_certificate_verify(
    Transcript,
    enc(hash(Transcript), server_sk)
) :-
    server_key_pair(server_pk, server_sk).

% --------------------------------------------------
% 7. Finished verification
% --------------------------------------------------

valid_server_finished(
    FinishedTranscript,
    Finished
) :-
    tls13_security_keys(
        keys(_, ServerHandshakeKey, _, _)
    ),

    finish_message(
        FinishedTranscript,
        ServerHandshakeKey,
        Finished
    ).

% --------------------------------------------------
% 8. Client server-authentication decision
% --------------------------------------------------

% The client accepts the server only if:
%   1. The server flight was delivered.
%   2. The certificate identifies the expected server.
%   3. CertificateVerify matches the handshake transcript.
%   4. Finished matches the server handshake key.

client_accepts_server(
    Certificate,
    CertificateVerify,
    Finished
) :-

    server_flight_delivered,

    valid_server_certificate(Certificate),

    server_cert_verify_transcript(
        cr,
        sr,
        client_x,
        server_y,
        server,
        server_pk,
        ca,
        CertificateTranscript
    ),

    valid_server_certificate_verify(
        CertificateTranscript,
        CertificateVerify
    ),

    server_finished_transcript(
        cr,
        sr,
        client_x,
        server_y,
        server,
        server_pk,
        ca,
        server_sk,
        FinishedTranscript
    ),

    valid_server_finished(
        FinishedTranscript,
        Finished
    ).

% --------------------------------------------------
% 9. Construct the honest server authentication data
% --------------------------------------------------

honest_server_authentication(
    Certificate,
    CertificateVerify,
    Finished
) :-

    certificate(
        server,
        server_pk,
        ca,
        Certificate
    ),

    server_cert_verify_transcript(
        cr,
        sr,
        client_x,
        server_y,
        server,
        server_pk,
        ca,
        CertificateTranscript
    ),

    server_certificate_verify(
        CertificateTranscript,
        server_sk,
        CertificateVerify
    ),

    server_finished_transcript(
        cr,
        sr,
        client_x,
        server_y,
        server,
        server_pk,
        ca,
        server_sk,
        FinishedTranscript
    ),

    tls13_security_keys(
        keys(_, ServerHandshakeKey, _, _)
    ),

    server_finished(
        FinishedTranscript,
        ServerHandshakeKey,
        Finished
    ).

% --------------------------------------------------
% 10. Intruder security properties
% --------------------------------------------------

% Mallory must not learn the server handshake key.
server_handshake_key_secret :-
    not intruder_knows(
        hash(dh_secret(client_x, server_y),
             's hs traffic',
             cr,
             sr)
    ).

% Mallory must not learn the client handshake key.
client_handshake_key_secret :-
    not intruder_knows(
        hash(dh_secret(client_x, server_y),
             'c hs traffic',
             cr,
             sr)
    ).

% Mallory must not learn either application key.
application_keys_secret :-
    not intruder_knows(
        hash('c ap traffic',
             cr,
             sr,
             hash(dh_secret(client_x, server_y), derived))
    ),

    not intruder_knows(
        hash('s ap traffic',
             cr,
             sr,
             hash(dh_secret(client_x, server_y), derived))
    ).
