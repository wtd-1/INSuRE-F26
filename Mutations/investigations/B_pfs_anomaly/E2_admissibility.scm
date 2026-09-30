(herald "B/E2: can a client strand coexist with cert-gen for its own key?")
(include "TLS1.3_macros.lisp")
(include "pfs_protocol_v1.scminc")

(defskeleton tls13mtlspfs
  (vars (s ca c self name) (cr sr random32) (x rndx) (y expt) (spk cpk other akey) (priv-stor locn) (ignore mesg))
  (defstrand client 3 (s s) (ca ca) (c c) (cr cr) (sr sr) (x x) (y y) (spk spk) (cpk cpk))
  
  (uniq-gen x)
  (comment "E2a client strand alone"))
(defskeleton tls13mtlspfs
  (vars (s ca c self name) (cr sr random32) (x rndx) (y expt) (spk cpk other akey) (priv-stor locn) (ignore mesg))
  (defstrand client 3 (s s) (ca ca) (c c) (cr cr) (sr sr) (x x) (y y) (spk spk) (cpk cpk))
  (defstrand cert-gen 2 (self c) (pk cpk) (priv-stor priv-stor) (ignore ignore))
  (uniq-gen x)
  (comment "E2b client strand + cert-gen for the client key cpk"))
(defskeleton tls13mtlspfs
  (vars (s ca c self name) (cr sr random32) (x rndx) (y expt) (spk cpk other akey) (priv-stor locn) (ignore mesg))
  (defstrand client 3 (s s) (ca ca) (c c) (cr cr) (sr sr) (x x) (y y) (spk spk) (cpk cpk))
  (defstrand cert-gen 2 (self c) (pk other) (priv-stor priv-stor) (ignore ignore))
  (uniq-gen x)
  (comment "E2c control: client strand + cert-gen for an unrelated key"))
