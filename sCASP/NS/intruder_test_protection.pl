#include 'intruder.pl'.

% Mallory intercepts a message encrypted with Alice's key.

intercepted(
    mallory,
    enc(msg(secret, alice), pubk(alice))
).

% Mallory should not be able to recover the secret.

?- not knows(mallory, secret, [step,step]).