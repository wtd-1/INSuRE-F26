% ==================================================
% TLS 1.3 secrecy analysis
% ==================================================
%
% Requires tls13_terms.pl, tls13_roles.pl and
% tls13_intruder.pl to be loaded first, and a scenario
% file (tests/test_analysis_*.pl) that defines leaked/1.
%
% Mallory is a passive eavesdropper: she sees every
% message of one honest client/server exchange and
% applies the Dolev-Yao rules in tls13_intruder.pl.
% Each scenario hands her extra secrets through leaked/1
% and checks which session secrets she can then derive.
%
% Scope: this checks secrecy only. The CPSA goals in
% tls13_final.scm also cover authentication (injective
% agreement), which needs an active intruder that
% injects messages; that is not modelled here.

% --------------------------------------------------
% 1. Honest session
% --------------------------------------------------

% Session parameters:
%   cr, sr             client and server randoms
%   client_x, server_y DH exponents
%   server, ca         server and certificate authority
%   request, response  application data

honest_exchange(Exchange) :-
    tls13_honest_exchange(
        cr, sr, client_x, server_y,
        server, pubk(server), privk(server), ca,
        request, response,
        Exchange).

honest_session_keys(Keys) :-
    tls13_session_keys(cr, sr, client_x, server_y, Keys).

% --------------------------------------------------
% 2. Network: every message of the honest exchange
% --------------------------------------------------

network_message(M) :- honest_exchange(exchange(M, _, _, _, _, _)).
network_message(M) :- honest_exchange(exchange(_, M, _, _, _, _)).
network_message(M) :- honest_exchange(exchange(_, _, M, _, _, _)).
network_message(M) :- honest_exchange(exchange(_, _, _, M, _, _)).
network_message(M) :- honest_exchange(exchange(_, _, _, _, M, _)).
network_message(M) :- honest_exchange(exchange(_, _, _, _, _, M)).

% --------------------------------------------------
% 3. Compromise
% --------------------------------------------------

% Each scenario file defines leaked/1. Use
% leaked(nothing). for the uncompromised scenario.

initial_knowledge(mallory, Secret) :-
    leaked(Secret).

% --------------------------------------------------
% 4. Secrecy properties
% --------------------------------------------------

handshake_secret_secrecy :-
    dh_shared(client_x, server_y, HS),
    not intruder_knows(HS).

handshake_key_secrecy :-
    honest_session_keys(keys(CHK, SHK, _, _)),
    not intruder_knows(CHK),
    not intruder_knows(SHK).

application_key_secrecy :-
    honest_session_keys(keys(_, _, CAK, SAK)),
    not intruder_knows(CAK),
    not intruder_knows(SAK).

request_secrecy :-
    not intruder_knows(request).

response_secrecy :-
    not intruder_knows(response).

all_secrecy :-
    handshake_secret_secrecy,
    handshake_key_secrecy,
    application_key_secrecy,
    request_secrecy,
    response_secrecy.

% --------------------------------------------------
% 5. Exposure (expected when a session secret leaks)
% --------------------------------------------------

session_exposed :-
    dh_shared(client_x, server_y, HS),
    intruder_knows(HS),
    intruder_knows(request),
    intruder_knows(response).
