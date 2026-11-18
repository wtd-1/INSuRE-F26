% ============================================================
% Lowe's man-in-the-middle attack on Needham-Schroeder
% Reference: G. Lowe, "Breaking and fixing the
% Needham-Schroeder public-key protocol using FDR" (1996);
% CPSA tst/ns.scm, responder point of view.
%
% Alice starts an honest run with Mallory. Mallory reuses
% Alice's messages to run the protocol with Bob in Alice's
% name. Bob finishes believing he talked to Alice, but
% Alice never ran the protocol with Bob.
%
%   1.  alice   -> mallory : {na, alice}_Km
%   1'. mallory -> bob     : {na, alice}_Kb    (forged)
%   2'. bob     -> alice   : {na, nb}_Ka       (forwarded)
%   2.  (Alice accepts 2' as Mallory's reply)
%   3.  alice   -> mallory : {nb}_Km
%   3'. mallory -> bob     : {nb}_Kb           (forged)
% ============================================================

#include 'ns_roles.pl'.
#include 'intruder.pl'.

% ------------------------------------------------------------
% Messages Mallory sees on the network
% ------------------------------------------------------------

% Alice's message 1 in her run with Mallory.
intercepted(mallory, M) :-
    init_event(alice, mallory, na, _, 1, send, M).

% Bob's message 2 in his run with (he believes) Alice.
intercepted(mallory, M) :-
    resp_event(alice, bob, na, nb, 2, send, M).

% Alice's message 3 in her run with Mallory.
intercepted(mallory, M) :-
    init_event(alice, mallory, na, nb, 3, send, M).

% ------------------------------------------------------------
% Attack steps
% ------------------------------------------------------------

% 1'. Mallory can build the message 1 Bob expects from Alice:
% decrypt with privk(mallory), re-encrypt under pubk(bob).
forge_bob_msg1 :-
    resp_event(alice, bob, na, nb, 1, recv, M),
    knows(mallory, M, [step, step]).

% 2. Alice accepts Bob's message 2 as the reply in her run
% with Mallory: message 2 does not name the responder, so
% Alice cannot tell it came from Bob's run.
alice_accepts_bob_msg2 :-
    resp_event(alice, bob, na, nb, 2, send, M),
    init_event(alice, mallory, na, nb, 2, recv, M).

% 3'. Mallory can build the message 3 Bob expects from Alice.
forge_bob_msg3 :-
    resp_event(alice, bob, na, nb, 3, recv, M),
    knows(mallory, M, [step, step]).

% Bob's nonce, meant to be shared only with Alice, leaks.
nb_leaks :-
    knows(mallory, nb, [step]).

% Bob completes all three steps with "Alice" while Alice
% only ever ran with Mallory: responder authentication fails
% (the shape CPSA reports for the responder skeleton).
lowe_attack :-
    forge_bob_msg1,
    alice_accepts_bob_msg2,
    forge_bob_msg3,
    nb_leaks.

?- lowe_attack.
