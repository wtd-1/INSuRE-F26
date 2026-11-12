% ============================================================
% Needham-Schroeder Public-Key Protocol: role definitions
% Reference: MITRE CPSA tst/ns.scm
%
% Original NS protocol (not Lowe-corrected). Included by
% needham_schroeder.pl and lowe_attack.pl.
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
% (N2 is not yet bound; kept so every event has arity 7)

init_event(A, B, N1, _N2, 1, send,
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
