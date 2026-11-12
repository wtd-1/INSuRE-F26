
% TLS 1.3 analysis scenario: server long-term key leaked.
%
% The server's signing key is not an input to the key
% schedule, so a passive eavesdropper who later obtains
% privk(server) still cannot read the recorded session
% (the passive counterpart of the client-side perfect
% forward secrecy goal in tls13_final.scm).

leaked(privk(server)).

?- all_secrecy.
