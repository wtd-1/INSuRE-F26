# TLS Test Bed

Collection of TLS Stack Containers and TLS Tools.

> **Origin of this folder.** This is a copy of the GASP project's test bed,
> [gitlab.com/gaspians/tls-test-bed](https://gitlab.com/gaspians/tls-test-bed) at commit `8597e75` (GPLv3, see
> `COPYING.txt`), with additions for this project:
> - fixes so that the images build again (archived Debian package sources, LF line endings, version pins);
> - `tools/pylstar-tls-lsharp/`: pylstar-tls learning with AALpy's L# instead of L\*;
> - `tools/automaton2dot/` and `automaton2dot.sh`: graphs of the inferred state machines;
> - `run-experiments.sh`, `summarize-results.sh`, `experiments/` and `docs/reproducing-the-paper.md`: running and
>   analysing the experiments of the original paper with L\* and L#.

To rerun the experiments of the paper this test bed was built for (Rasoamanana, Levillain, Debar, ESORICS 2022), with
L\* or L#, see [docs/reproducing-the-paper.md](docs/reproducing-the-paper.md). It covers the batch runner
(`run-experiments.sh`), the experiment lists in `experiments/`, and result analysis (`summarize-results.sh`).

## Installation

You need to install Docker, make and openssl.


## Nano-tutorial

To infer an OpenSSL server, here are the steps required:

  * Generate some cryptographic material using `make crypto-material`
  * Find the tag you are interested in in the directories `stacks/openssl*/tags`; we will use `openssl-3.0.2`.
  * build the OpenSSL container using `make containers/openssl/openssl-3.0.2.docker`, which will produce the container named `tls-test-bed/openssl:openssl-3.0.2`, and put the image identifier in the file `containers/openssl/openssl-3.0.2.docker`.
  * build the `pylstar-tls` container, with `make containers/tools/pylstar-tls.docker`, which will produce the container named `tls-test-bed/pylstar-tls`.
  * run the inference using `./infer-server.sh tls-test-bed/openssl:openssl-3.0.2 1.3 tls13`, where `1.3` is the version used by the server and `tls13` corresponds to the scenario used by `pylstar-tls`.

The results will be in a new directory under `results/` (ignored by git), named after the run, e.g. `results/server--openssl_openssl-3.0.2--tls13--pylstar-tls--20261112-141500-XXXXXX`. You can choose another directory using the `RESULTS_DIR` environment variable.


Inferring a client can be done in a similar way.


### Learning with L# instead of L*

`pylstar-tls` learns with pylstar's L\*. The `pylstar-tls-lsharp` tool runs the same `pylstar-tls` code (TLS messages, scenarios, equivalence oracles, output files) but learns with [AALpy](https://github.com/DES-Lab/AALpy)'s L# algorithm:

    make containers/tools/pylstar-tls-lsharp.docker
    INFERER_IMAGE=tls-test-bed/pylstar-tls-lsharp ./infer-server.sh tls-test-bed/openssl:openssl-3.0.2 1.3 tls13

`INFERER_IMAGE` works the same way with `infer-srv-auth.sh` and `infer-client.sh`. The results directory name includes the inferer (`pylstar-tls` or `pylstar-tls-lsharp`), so runs of both learners can be compared side by side.


### Visualizing a state machine

`automaton2dot.sh` renders a result with `pylstar-tls`'s `automaton2dot.py`: messages get short names, similar transitions are merged, the expected handshake is drawn in green, error transitions in grey, and simple security checks (loops, authentication bypass) are run and reported.

    make containers/tools/automaton2dot.docker
    ./automaton2dot.sh results/server--openssl_openssl-3.0.2--tls13--pylstar-tls--20261112-141500-XXXXXX

This writes `final.dot` and `final.svg` into the results directory. A `.automaton` file can be given instead of a directory, and the scenario (e.g. `server.tls13`) can be passed as a second argument when it cannot be guessed from the directory name.


You can run `tlsprint` on the different stacks using the following commands:

    make containers/tools/tlsprint.docker
    make containers/openssl/OpenSSL_1_1_1k.docker
    /tlsprint.sh tls-test-bed/openssl:OpenSSL_1_1_1k 1.2


## Bugs and enhancements

Please, report any bug found by opening a ticket and/or by submiting a pull requests.


## Authors and acknowledgment

  * Aina Toky Rasoamanana
  * Olivier Levillain

This tool has been supported in part by the French ANR [GASP project](https://gasp.ebfe.fr) (ANR-19-CE39-0001).


## License

This software is licensed under the GPLv3 License. See the `COPYING.txt` file
in the top distribution directory for the full license text.
