% ============================================================
% Needham-Schroeder Public-Key Protocol
% CPSA Assumptions
%
% Reference: MITRE CPSA tst/ns.scm
% ============================================================

% ------------------------------------------------------------
% Scenario 1: Initiator point of view
%
% CPSA:
% (non-orig (privk b) (privk a))
% (uniq-orig n1)
% ------------------------------------------------------------

non_orig(initiator_view, privk(alice)).
non_orig(initiator_view, privk(bob)).

uniq_orig(initiator_view, na).

% ------------------------------------------------------------
% Scenario 2: Responder point of view
%
% CPSA:
% (non-orig (privk a))
% (uniq-orig n2)
% ------------------------------------------------------------

non_orig(responder_view, privk(alice)).

uniq_orig(responder_view, nb).

% ------------------------------------------------------------
% Assumption interpretation
% ------------------------------------------------------------

% A non-originating value is protected from origination
% by the adversary.

protected_key(Scenario, Principal) :-
    non_orig(Scenario, privk(Principal)).

% A uniquely originating nonce is fresh within
% the corresponding protocol execution.

fresh_nonce(Scenario, Nonce) :-
    uniq_orig(Scenario, Nonce).

% ------------------------------------------------------------
% Initiator assumption checks
% ------------------------------------------------------------

initiator_assumptions :-
    protected_key(initiator_view, alice),
    protected_key(initiator_view, bob),
    fresh_nonce(initiator_view, na).

% ------------------------------------------------------------
% Responder assumption checks
% ------------------------------------------------------------

responder_assumptions :-
    protected_key(responder_view, alice),
    fresh_nonce(responder_view, nb).

% ------------------------------------------------------------
% Test queries
% ------------------------------------------------------------

?- responder_assumptions.