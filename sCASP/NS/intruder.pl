% ============================================================
% Dolev-Yao Intruder Model
% Needham-Schroeder Public-Key Protocol
%
% Intruder: Mallory
% Bounded deduction model
% ============================================================

% ------------------------------------------------------------
% 1. Initial intruder knowledge
% ------------------------------------------------------------

intruder_initial(mallory, alice).
intruder_initial(mallory, bob).
intruder_initial(mallory, mallory).

% Public keys
intruder_initial(mallory, pubk(alice)).
intruder_initial(mallory, pubk(bob)).
intruder_initial(mallory, pubk(mallory)).

% Mallory's private key
intruder_initial(mallory, privk(mallory)).

% ------------------------------------------------------------
% 2. Initial knowledge
% ------------------------------------------------------------

knows(I, X, []) :-
    intruder_initial(I, X).

% Intercepted network messages become known to the intruder.

knows(I, Message, []) :-
    intercepted(I, Message).
    
% ------------------------------------------------------------
% 3. Public-key decryption
% ------------------------------------------------------------

knows(I, M, [step|D]) :-
    knows(I, enc(M, pubk(P)), D),
    knows(I, privk(P), D).

% ------------------------------------------------------------
% 4. Pair decomposition
% ------------------------------------------------------------

knows(I, X, [step|D]) :-
    knows(I, msg(X, Y), D).

knows(I, Y, [step|D]) :-
    knows(I, msg(X, Y), D).

% ------------------------------------------------------------
% 5. Pair construction
% ------------------------------------------------------------

knows(I, msg(X, Y), [step|D]) :-
    knows(I, X, D),
    knows(I, Y, D).

% ------------------------------------------------------------
% 6. Public-key encryption construction
% ------------------------------------------------------------

knows(I, enc(M, pubk(P)), [step|D]) :-
    knows(I, M, D),
    intruder_initial(I, pubk(P)).

% ------------------------------------------------------------
% 7. Interception
% ------------------------------------------------------------

intercept(I, Message, Depth) :-
    knows(I, Message, Depth).

% ------------------------------------------------------------
% 8. Replay
% ------------------------------------------------------------

replay(I, Message, Depth) :-
    knows(I, Message, Depth).