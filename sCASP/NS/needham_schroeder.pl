% ============================================================
% Needham-Schroeder Public-Key Protocol
% Reference: MITRE CPSA tst/ns.scm
%
% Original NS protocol (not Lowe-corrected)
% ============================================================

#include 'ns_roles.pl'.

% ------------------------------------------------------------
% Protocol consistency checks
% ------------------------------------------------------------

% The initiator's first message matches the responder's
% first message.

first_message_matches(A, B, N1) :-
    init_event(A, B, N1, _, 1, send, M),
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