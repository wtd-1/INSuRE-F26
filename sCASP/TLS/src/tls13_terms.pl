
% TLS 1.3 symbolic term definitions
%
% These predicates construct symbolic terms.
% They do not perform real cryptographic operations.

% --------------------------------------------------
% Diffie-Hellman
% --------------------------------------------------

% Public DH value: g^x
dh_public(Exponent, exp(gen, Exponent)).

% Shared DH secret.
% Both client and server use the same canonical representation.
dh_shared(ClientExponent, ServerExponent,
          dh_shared(ClientExponent, ServerExponent)).

% --------------------------------------------------
% TLS 1.3 key schedule
% --------------------------------------------------

% Master secret
% MasterSecret = hash(HandshakeSecret, "derived")
master_secret(HandshakeSecret,
              hash(HandshakeSecret, derived)).

% Client handshake traffic key
client_handshake_key(CR, SR, HS,
    hash(HS, client_hs_traffic, CR, SR)).

% Server handshake traffic key
server_handshake_key(CR, SR, HS,
    hash(HS, server_hs_traffic, CR, SR)).

% Client application traffic key
client_application_key(CR, SR, MS,
    hash(client_ap_traffic, CR, SR, MS)).

% Server application traffic key
server_application_key(CR, SR, MS,
    hash(server_ap_traffic, CR, SR, MS)).

% Finished key
finished_key(HandshakeKey,
             hash(finished, HandshakeKey)).

% --------------------------------------------------
% Certificates and authentication
% --------------------------------------------------

% Certificate:
% cat(Party, PublicKey,
%     enc(hash(Party, PublicKey), privk(CA)))
certificate(Party, PublicKey, CA,
    cat(Party, PublicKey,
        enc(hash(Party, PublicKey), privk(CA)))).

% CertificateVerify:
% enc(hash(Messages), SigningKey)
certificate_verify(Messages, SigningKey,
    enc(hash(Messages), SigningKey)).



% ==================================================
% TLS 1.3 handshake message construction
% ==================================================

% ClientHello and ServerHello
client_hello(CR, ClientExponent,
             cat(CR, exp(gen, ClientExponent))).

server_hello(SR, ServerExponent,
             cat(SR, exp(gen, ServerExponent))).

% --------------------------------------------------
% Server CertificateVerify transcript
% --------------------------------------------------

% Transcript:
% ClientHello || ServerHello || Server Certificate

server_cert_verify_transcript(
    CR, SR, CX, SY, Server, ServerPK, CA,
    transcript(ClientHello, ServerHello, Certificate)) :-

    client_hello(CR, CX, ClientHello),
    server_hello(SR, SY, ServerHello),
    certificate(Server, ServerPK, CA, Certificate).

% Server CertificateVerify
server_certificate_verify(
    Transcript, ServerPrivateKey,
    enc(hash(Transcript), ServerPrivateKey)).

% --------------------------------------------------
% Server Finished
% --------------------------------------------------

% Transcript:
% ClientHello || ServerHello || Certificate ||
% CertificateVerify

server_finished_transcript(
    CR, SR, CX, SY, Server, ServerPK, CA, ServerPrivateKey,
    transcript(ServerCertTranscript, CertificateVerify)) :-

    server_cert_verify_transcript(
        CR, SR, CX, SY, Server, ServerPK, CA,
        ServerCertTranscript),

    server_certificate_verify(
        ServerCertTranscript,
        ServerPrivateKey,
        CertificateVerify).

% Finished message:
% hash(hash(finished, HandshakeKey), Transcript)

finish_message(Transcript, HandshakeKey,
               hash(hash(finished, HandshakeKey), Transcript)).

server_finished(
    Transcript, ServerHandshakeKey, Finished) :-
    finish_message(Transcript, ServerHandshakeKey, Finished).

% --------------------------------------------------
% Client Finished (server-only authentication)
% --------------------------------------------------

% Client Finished transcript includes the server Finished.

client_finished_transcript(
    ServerTranscript, ServerFinished,
    transcript(ServerTranscript, ServerFinished)).

client_finished(
    ServerTranscript, ServerFinished, ClientHandshakeKey,
    ClientFinished) :-

    client_finished_transcript(
        ServerTranscript, ServerFinished, ClientTranscript),

    finish_message(
        ClientTranscript, ClientHandshakeKey, ClientFinished).

% --------------------------------------------------
% Server flight
% --------------------------------------------------

% Symbolic representation of the encrypted server flight.

server_flight(
    Certificate,
    CertificateVerify,
    Finished,
    server_flight(Certificate, CertificateVerify, Finished)).

encrypted_server_flight(
    ServerFlight, ServerHandshakeKey,
    enc(ServerFlight, ServerHandshakeKey)).
