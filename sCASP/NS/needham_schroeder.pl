% ============================================================
% Needham-Schroeder Public-Key Protocol
% Reference: MITRE CPSA tst/ns.scm
%
% Original NS protocol (not Lowe-corrected)
% ============================================================

% ------------------------------------------------------------
% Message constructors
% ------------------------------------------------------------

% msg(X,Y) represents a message containing X and Y.
% enc(Message, PublicKey) represents public-key encryption.

% ------------------------------------------------------------
% Initiator role
% ------------------------------------------------------------

% Message 1: A -> B
% {N1, A}_Kb

init_event(A, B, N1, 1, send,
           enc(msg(N1, A), pubk(B))).

% Message 2: B -> A
% {N1, N2}_Ka

init_event(A, B, N1, N2, 2, recv,
           enc(msg(N1, N2), pubk(A))).

% Message 3: A -> B
% {N2}_Kb

init_event(A, B, N1, N2, 3, send,
           enc(N2, pubk(B))).

% ------------------------------------------------------------
% Responder role
% ------------------------------------------------------------

% Message 1: A -> B
% {N1, A}_Kb

resp_event(A, B, N1, N2, 1, recv,
           enc(msg(N1, A), pubk(B))).

% Message 2: B -> A
% {N1, N2}_Ka

resp_event(A, B, N1, N2, 2, send,
           enc(msg(N1, N2), pubk(A))).

% Message 3: A -> B
% {N2}_Kb

resp_event(A, B, N1, N2, 3, recv,
           enc(N2, pubk(B))).

% ------------------------------------------------------------
% Protocol consistency checks
% ------------------------------------------------------------

% The initiator's first message matches the responder's
% first message.

first_message_matches(A, B, N1) :-
    init_event(A, B, N1, 1, send, M),
    resp_event(A, B, N1, _, 1, recv, M).

% The responder's second message matches the initiator's
% second message.

second_message_matches(A, B, N1, N2) :-
    resp_event(A, B, N1, N2, 2, send, M),
    init_event(A, B, N1, N2, 2, recv, M).

% The initiator's third message matches the responder's
% third message.

third_message_matches(A, B, N1, N2) :-
    init_event(A, B, N1, N2, 3, send, M),
    resp_event(A, B, N1, N2, 3, recv, M).

% All three message structures match.

protocol_consistent(A, B, N1, N2) :-
    first_message_matches(A, B, N1),
    second_message_matches(A, B, N1, N2),
    third_message_matches(A, B, N1, N2).

% ------------------------------------------------------------
% Test scenario
% ------------------------------------------------------------

test_protocol :-
    protocol_consistent(alice, bob, na, nb).

?- test_protocol.