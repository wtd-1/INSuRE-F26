
% TLS 1.3 analysis scenario: client DH exponent leaked.
%
% With client_x and the server's public share g^server_y
% from ServerHello, Mallory computes the handshake secret,
% reruns the key schedule and reads the whole session.

leaked(client_x).

?- session_exposed.
