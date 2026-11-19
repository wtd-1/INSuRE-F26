% ==================================================
% TLS 1.3 Intruder Model - Analysis Candidate v3
% ==================================================
%
% Stage 1:
%   Initial knowledge
%   Network observation
%   Message decomposition
%   Decryption using initially known keys
%
% Hash and DH construction are intentionally excluded
% during this diagnostic stage.

% --------------------------------------------------
% 1. Initial intruder knowledge
% --------------------------------------------------

initial_knowledge(mallory, gen).
initial_knowledge(mallory, pubk(ca)).
initial_knowledge(mallory, pubk(server)).

initial_knowledge(mallory, mallory).
initial_knowledge(mallory, privk(mallory)).

initial_knowledge(mallory, client).
initial_knowledge(mallory, server).
initial_knowledge(mallory, ca).

initial_knowledge(mallory, derived).
initial_knowledge(mallory, 'c hs traffic').
initial_knowledge(mallory, 's hs traffic').
initial_knowledge(mallory, 'c ap traffic').
initial_knowledge(mallory, 's ap traffic').
initial_knowledge(mallory, finished).

% --------------------------------------------------
% 1.5. Network message interface
% --------------------------------------------------

% Default empty network.
% Individual tests can supply network_message/1 facts.
network_message(_) :-
    impossible_network_message = no_network_message.


% --------------------------------------------------
% 2. Intruder knowledge
% --------------------------------------------------

intruder_knows(Term) :-
    initial_knowledge(mallory, Term).

intruder_knows(Term) :-
    network_message(Message),
    extract(Message, Term).

% --------------------------------------------------
% 3. Message decomposition
% --------------------------------------------------

extract(Message, Message).

extract(cat(A, _), Part) :-
    extract(A, Part).

extract(cat(_, B), Part) :-
    extract(B, Part).

extract(cat(A, _, _), Part) :-
    extract(A, Part).

extract(cat(_, B, _), Part) :-
    extract(B, Part).

extract(cat(_, _, C), Part) :-
    extract(C, Part).

extract(transcript(A, _), Part) :-
    extract(A, Part).

extract(transcript(_, B), Part) :-
    extract(B, Part).

extract(transcript(A, _, _), Part) :-
    extract(A, Part).

extract(transcript(_, B, _), Part) :-
    extract(B, Part).

extract(transcript(_, _, C), Part) :-
    extract(C, Part).

extract(server_flight(A, _, _), Part) :-
    extract(A, Part).

extract(server_flight(_, B, _), Part) :-
    extract(B, Part).

extract(server_flight(_, _, C), Part) :-
    extract(C, Part).

% --------------------------------------------------
% 4. Keys directly available to Mallory
% --------------------------------------------------

known_decryption_key(Key) :-
    initial_knowledge(mallory, Key).

known_decryption_key(Key) :-
    network_message(Key).

% --------------------------------------------------
% 5. Decryption
% --------------------------------------------------

extract(enc(Plaintext, Key), Part) :-
    inverse_key(Key, DecryptionKey),
    known_decryption_key(DecryptionKey),
    extract(Plaintext, Part).

% --------------------------------------------------
% 6. Key inverses
% --------------------------------------------------

asymmetric_key(pubk(_)).
asymmetric_key(privk(_)).

inverse_key(pubk(A), privk(A)).
inverse_key(privk(A), pubk(A)).

inverse_key(Key, Key) :-
    not asymmetric_key(Key).

% --------------------------------------------------
% 7. Controlled hash construction
% --------------------------------------------------

% Mallory can compute a hash when its input is known.
intruder_knows(hash(A)) :-
    intruder_knows(A).

% Two-input hash construction.
intruder_knows(hash(A, B)) :-
    intruder_knows(A),
    intruder_knows(B).

% Four-input hash construction.
intruder_knows(hash(A, B, C, D)) :-
    intruder_knows(A),
    intruder_knows(B),
    intruder_knows(C),
    intruder_knows(D).