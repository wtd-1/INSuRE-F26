% ==================================================
% TLS 1.3 Dolev-Yao Intruder Model
% ==================================================
%
% Term conventions (shared with tls13_terms.pl and the
% CPSA reference, where `enc` covers every kind of
% encryption and the key decides who can decrypt):
%
%   enc(P, pubk(A))   public-key encryption to A
%   enc(H, privk(A))  A's signature over H
%   enc(P, K)         symmetric encryption under any
%                     other key K (e.g. a traffic key)
%   cat/2, cat/3, transcript/2, transcript/3 and
%   server_flight/3 are plain concatenations.
%
% Mallory can:
%   1. Know public information, the key-schedule labels
%      and her own private key.
%   2. Observe network messages.
%   3. Decompose concatenations, recursively.
%   4. Decrypt enc(P, K) whenever she knows the inverse
%      of K (K itself for symmetric keys, privk(A) for
%      pubk(A), pubk(A) for privk(A)). The decryption key
%      may itself be learned from other messages.
%   5. Build hashes of terms she knows, so she can rerun
%      the key schedule once she has the inputs.
%   6. Compute a DH secret when she knows one exponent
%      and the other party's public share.
%
% Mallory cannot:
%   1. Invert hashes.
%   2. Derive unknown private keys.
%   3. Derive a DH secret from the two public shares.
%
% Query knows/2 with a bound term. With an unbound term
% the hash-construction rules can generate infinitely
% many answers.

% --------------------------------------------------
% 1. Initial intruder knowledge
% --------------------------------------------------

% Public information
initial_knowledge(mallory, gen).
initial_knowledge(mallory, pubk(ca)).
initial_knowledge(mallory, pubk(server)).

% Mallory's identity and private key
initial_knowledge(mallory, mallory).
initial_knowledge(mallory, privk(mallory)).

% Public agent names
initial_knowledge(mallory, client).
initial_knowledge(mallory, server).
initial_knowledge(mallory, ca).

% Key-schedule labels are public constants
% (quoted strings in the CPSA macros).
initial_knowledge(mallory, derived).
initial_knowledge(mallory, client_hs_traffic).
initial_knowledge(mallory, server_hs_traffic).
initial_knowledge(mallory, client_ap_traffic).
initial_knowledge(mallory, server_ap_traffic).
initial_knowledge(mallory, finished).

% --------------------------------------------------
% 2. Initial knowledge and network observation
% --------------------------------------------------

knows(mallory, Term) :-
    initial_knowledge(mallory, Term).

knows(mallory, Term) :-
    network_message(Message),
    extract(Message, Term).

% --------------------------------------------------
% 3. Message analysis
% --------------------------------------------------

% extract(Message, Part): Mallory can read Part out of
% Message, given what she already knows.

extract(Message, Message).

extract(cat(A, _), Part) :- extract(A, Part).
extract(cat(_, B), Part) :- extract(B, Part).

extract(cat(A, _, _), Part) :- extract(A, Part).
extract(cat(_, B, _), Part) :- extract(B, Part).
extract(cat(_, _, C), Part) :- extract(C, Part).

extract(transcript(A, _), Part) :- extract(A, Part).
extract(transcript(_, B), Part) :- extract(B, Part).

extract(transcript(A, _, _), Part) :- extract(A, Part).
extract(transcript(_, B, _), Part) :- extract(B, Part).
extract(transcript(_, _, C), Part) :- extract(C, Part).

extract(server_flight(A, _, _), Part) :- extract(A, Part).
extract(server_flight(_, B, _), Part) :- extract(B, Part).
extract(server_flight(_, _, C), Part) :- extract(C, Part).

% Decryption needs the inverse of the encryption key.
extract(enc(Plaintext, Key), Part) :-
    inverse_key(Key, DecryptionKey),
    knows(mallory, DecryptionKey),
    extract(Plaintext, Part).

% --------------------------------------------------
% 4. Key inverses
% --------------------------------------------------

asymmetric_key(pubk(_)).
asymmetric_key(privk(_)).

inverse_key(pubk(A), privk(A)).
inverse_key(privk(A), pubk(A)).
inverse_key(Key, Key) :-
    not asymmetric_key(Key).

% --------------------------------------------------
% 5. Construction: hashing (one-way)
% --------------------------------------------------

% Arities used by tls13_terms.pl.

knows(mallory, hash(A)) :-
    knows(mallory, A).

knows(mallory, hash(A, B)) :-
    knows(mallory, A),
    knows(mallory, B).

knows(mallory, hash(A, B, C, D)) :-
    knows(mallory, A),
    knows(mallory, B),
    knows(mallory, C),
    knows(mallory, D).

% --------------------------------------------------
% 6. Construction: Diffie-Hellman
% --------------------------------------------------

% dh_secret(X, Y) is g^(XY). Mallory needs one exponent
% plus the other side's public share g^Y or g^X.

knows(mallory, dh_secret(X, Y)) :-
    knows(mallory, X),
    knows(mallory, exp(gen, Y)).

knows(mallory, dh_secret(X, Y)) :-
    knows(mallory, Y),
    knows(mallory, exp(gen, X)).

% --------------------------------------------------
% 7. Intruder knowledge query
% --------------------------------------------------

intruder_knows(Term) :-
    knows(mallory, Term).

% --------------------------------------------------
% 8. Decryption capability queries
% --------------------------------------------------

intruder_can_decrypt_symmetric(Ciphertext, Plaintext) :-
    network_message(Ciphertext),
    Ciphertext = enc(Plaintext, Key),
    not asymmetric_key(Key),
    knows(mallory, Key).

intruder_can_decrypt_public_key(Ciphertext, Plaintext) :-
    network_message(Ciphertext),
    Ciphertext = enc(Plaintext, pubk(Agent)),
    knows(mallory, privk(Agent)).

% --------------------------------------------------
% 9. Signature verification capability query
% --------------------------------------------------

intruder_can_verify_signature(Signature, Hash) :-
    network_message(Signature),
    Signature = enc(Hash, privk(Agent)),
    knows(mallory, pubk(Agent)).
