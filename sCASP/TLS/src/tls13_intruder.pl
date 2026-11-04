% ==================================================
% TLS 1.3 Dolev-Yao Intruder Model
% ==================================================
%
% Bounded initial implementation.
%
% Mallory can:
%   1. Know public information and her own private key.
%   2. Observe network messages.
%   3. Decompose directly observed concatenated messages.
%   4. Decrypt symmetric ciphertexts when she knows the key.
%   5. Decrypt public-key ciphertexts when she knows
%      the recipient's private key.
%   6. Recover a signed hash when she knows the
%      corresponding signer's public key.
%
% Mallory cannot:
%   1. Invert hashes.
%   2. Derive unknown private keys.
%   3. Automatically derive DH shared secrets.
%
% This is a bounded model. It does not implement
% unrestricted recursive Dolev-Yao closure.

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

% --------------------------------------------------
% 2. Network observation
% --------------------------------------------------

knows(mallory, Message) :-
    network_message(Message).

% --------------------------------------------------
% 3. Initial knowledge
% --------------------------------------------------

knows(mallory, Term) :-
    initial_knowledge(mallory, Term).

% --------------------------------------------------
% 4. Concatenated message decomposition
% --------------------------------------------------

knows(mallory, Part1) :-
    network_message(cat(Part1, _)).

knows(mallory, Part2) :-
    network_message(cat(_, Part2)).

% --------------------------------------------------
% 5. Symmetric decryption
% --------------------------------------------------

knows(mallory, Plaintext) :-
    network_message(senc(Plaintext, Key)),
    initial_knowledge(mallory, Key).

% --------------------------------------------------
% 6. Public-key decryption
% --------------------------------------------------

% Decryption requires the recipient's private key.

knows(mallory, Plaintext) :-
    network_message(enc(Plaintext, pubk(Agent))),
    initial_knowledge(mallory, privk(Agent)).

% --------------------------------------------------
% 7. Symbolic signature verification
% --------------------------------------------------

% A symbolic signature is represented as:
% enc(Hash, privk(Agent)).
%
% Mallory can recover the signed hash when she knows
% the corresponding public key.

knows(mallory, Hash) :-
    network_message(enc(Hash, privk(Agent))),
    initial_knowledge(mallory, pubk(Agent)).

% --------------------------------------------------
% 8. Intruder knowledge query
% --------------------------------------------------

intruder_knows(Term) :-
    knows(mallory, Term).

% --------------------------------------------------
% 9. Decryption capability queries
% --------------------------------------------------

intruder_can_decrypt_symmetric(Ciphertext, Plaintext) :-
    network_message(Ciphertext),
    Ciphertext = senc(Plaintext, Key),
    initial_knowledge(mallory, Key).

intruder_can_decrypt_public_key(Ciphertext, Plaintext) :-
    network_message(Ciphertext),
    Ciphertext = enc(Plaintext, pubk(Agent)),
    initial_knowledge(mallory, privk(Agent)).

% --------------------------------------------------
% 10. Signature verification capability query
% --------------------------------------------------

intruder_can_verify_signature(Signature, Hash) :-
    network_message(Signature),
    Signature = enc(Hash, privk(Agent)),
    initial_knowledge(mallory, pubk(Agent)).