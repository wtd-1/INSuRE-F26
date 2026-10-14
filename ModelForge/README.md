# ModelForge exploration (Prong 1: "ML-based tools to aid the process")

## What ModelForge is

ModelForge (Duclos, Fernandez, Moore, Mittal, Zieglar, *Foundations and
Practice of Security* 2025, `BIDS/bib.bib`) turns a natural-language protocol
specification into a CPSA protocol definition with a fine-tuned LLM. A domain
expert then reviews the output. Our mentor is a co-author.

- An earlier paper (arXiv 2402.00890) fine-tuned Code Llama 34B. It reported
  only a qualitative example (one role of a toy DH protocol).
- A 2026 MSU thesis by Duclos
  (https://scholarsjunction.msstate.edu/td/6890) evaluates 15 LLMs on 104
  protocols. It reports 71% syntactically valid outputs for a locally
  fine-tuned model and 97% for frontier models. Curated reference examples
  helped, and prescriptive instructions hurt. The abstract says the benchmark,
  evaluation framework and fine-tuned model are public.
- **We could not obtain the tool, model or benchmark.** The thesis PDF sits
  behind a bot check, and GitHub and Hugging Face searches found no release.
  The closest repository (`mariobx/RFC-LLM`) is an unrelated student project.
  **Action:** ask the mentor for access at the sync.

## What we did instead

We reproduced the ModelForge approach and scored it against our ground truth,
which is something the published evaluation does not do: it measures syntax,
not whether CPSA's verdicts are right.

**Inputs.**
- `spec/mtls13_spec.md`: mTLS 1.3, abstracted from RFC 8446 and written in
  RFC terms, not CPSA terms.
- Four versions: unmutated (m0); no server CertificateVerify (m1); no client
  CertificateVerify (m6); neither (m8). Each matches the mutant of the same
  name in `Mutations/`.
- `spec/interface_contract.md` fixes role names, variable names and sorts,
  and the event order, so that fixed goals can be appended automatically.
  This stands in for ModelForge's structured output.

**Translator.**
- Claude Sonnet 5.5 via the `claude` CLI, run in an empty temporary directory
  with every tool disabled. It sees only the prompt and never our models,
  goals or answers.
- Two conditions:
  - Zero-shot.
  - With two stock CPSA examples, Station-to-Station and plain DH from the
    MITRE repository (`reference_examples/`). Neither is TLS. This is the
    thesis's "static context augmentation".
- Three samples per cell.
- One self-repair round: if CPSA rejects a model, its error is sent back once.
  This plays the role of ModelForge's post-processor.

**Scoring.**
- *Accepted*: CPSA loads the model.
- *Executable*: each role can run to completion. Without this check, a
  broken model would satisfy every goal vacuously.
- *Goals matching truth*: four goals (client→server and server→client
  agreement, secrecy of the request, secrecy of the response), checked
  against the same goals on the mentor's validated model, with each mutant
  applied to it (`ground_truth.csv`).
- Goals are stated over application payloads, not key terms, so they do not
  depend on how a model derives its keys.

## Results

`results.csv` has one row per generated model and stage. Reproduce with
`python3 run_modelforge.py truth|generate|evaluate|report`.

| model | condition | accepted (first try) | accepted (after repair) | executable | goals matching truth | exact match |
|---|---|---|---|---|---|---|
| Sonnet 5.5 | zero-shot | 11/12 | 12/12 | 9/12 | 38/48 (79%) | 9/12 (75%) |
| Sonnet 5.5 | with examples | 12/12 | 12/12 | 12/12 | 48/48 (100%) | **12/12 (100%)** |

Cost: $2.25 for 25 LLM calls, about 31 s per generation.

**Findings**
1. **With two reference examples, every generated model matched the ground
   truth on every goal, for all four variants.** Translating "the server does
   not send CertificateVerify" into a model in which CPSA finds the right
   attack worked every time. This matches the thesis's finding that
   reference examples help.
2. **All three zero-shot failures have one cause.** They are exactly the
   three models (of 24) that put `non-orig` security assumptions inside the
   role definitions. That writes "my key is uncompromised" into the protocol
   itself, and CPSA did not finish within the time limit. No correct model
   does this, and the Station-to-Station example does not either.
   Re-run with a 15-minute limit (`long_timeout_rerun.log`), none of the three
   finished. The two m1 models covered only 19 search steps in that time,
   because each step is very expensive. The m6 model reached 582 steps
   with no counterexample. In practice these models cannot be analysed;
   they are not merely slow.
3. **Syntax errors are cheap; semantic slips are not.** The one rejected model
   (a name used where a key was required) was fixed by a single repair round.
   The role-level assumptions passed every syntax check and would mislead
   anyone who did not inspect the model. This is the expert review that
   ModelForge's authors say is required.
4. **Haiku 5.5 could not be evaluated through this CLI version** (1.0.100).
   Its answers exceeded the CLI's fixed 8,192-token output limit in all three
   attempts. Running `claude update`, or calling the API directly, would allow
   a multi-model comparison like the thesis's.

**Limits.**
- The interface contract gives more structure than ModelForge receives; it
  is what makes automatic scoring possible.
- The m8 match (all four goals violated) is weak evidence, since a crude
  model can fail every goal. m1 and m6 are the discriminating variants: each
  needs one direction to hold and the other to fail.
- The model may have seen CPSA and TLS material in training. Our models and
  goals are not public.
- 24 samples from one model. These are indications, not statistics.

## How this feeds the other prongs

The ground truth plus the four spec variants make a ready-made test for any
translator. That includes ModelForge itself, if the mentor grants access:
run its output through `evaluate` unchanged.
