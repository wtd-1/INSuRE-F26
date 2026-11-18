#include 'intruder.pl'.

% Mallory intercepts a message encrypted with
% her own public key.

intercepted(
    mallory,
    enc(msg(secret, alice), pubk(mallory))
).

% Mallory decrypts the message and extracts the secret.

?- knows(mallory, secret, [step,step]).