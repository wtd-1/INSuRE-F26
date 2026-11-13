"""Drop-in replacement for pylstar's LSTAR class that learns with AALpy's L#.

pylstar-tls's infer_server.main() and infer_client.main() only do

    LSTAR(input_vocabulary, knowledge_base, max_states=..., eqtests=...).learn()

and use the returned pylstar Automata. LSharpLearner offers the same constructor
and learn(), so run_lsharp.py can substitute it without modifying pylstar-tls.

Everything around the learner is reused as is: the TLS knowledge bases (with their
cache, timeout shortcuts and statistics), the scenarios, and pylstar-tls's
equivalence oracles (BDist, HappyPathFirst, StoreHypotheses).
"""

from aalpy.base import SUL, Oracle
from aalpy.learning_algs import run_Lsharp
from pylstar.Letter import Letter
from pylstar.Word import Word
from pylstar.automata.Automata import Automata
from pylstar.automata.State import State
from pylstar.automata.Transition import Transition
from pylstar.eqtests.WpMethodEQ import WpMethodEQ


def _symbol(letter):
    """The symbol carried by a pylstar Letter (pylstar-tls letters carry exactly one)."""
    return next(iter(letter.symbols))


class KnowledgeBaseSUL(SUL):
    """AALpy system under learning backed by a pylstar knowledge base.

    Every query goes through knowledge_base._resolve_word(), i.e. pylstar's
    KnowledgeTree cache, pylstar-tls's TLS concretisation and kb.stats, exactly
    as with pylstar's L*. That keeps the statistics comparable between learners.
    """

    def __init__(self, knowledge_base):
        super().__init__()
        self.knowledge_base = knowledge_base
        self._prefix = []

    def _resolve(self, word):
        output = self.knowledge_base._resolve_word(Word([Letter(s) for s in word]))
        return [_symbol(letter) for letter in output.letters]

    def query(self, word):
        self.num_queries += 1
        self.num_steps += len(word)
        return self._resolve(word) if word else []

    # Stepwise interface, required by the SUL base class. pylstar-tls opens one
    # TLS session per word, so each step replays the prefix as a single word
    # (already-known prefixes are answered from pylstar's cache).
    def pre(self):
        self._prefix = []

    def post(self):
        self._prefix = []

    def step(self, letter):
        self._prefix.append(letter)
        return self._resolve(self._prefix)[-1]


def _states_in_bfs_order(mealy):
    """The Mealy machine's states, initial state first, in breadth-first order."""
    ordered = [mealy.initial_state]
    seen = {mealy.initial_state.state_id}
    for state in ordered:  # the list grows while we iterate over it
        for successor in state.transitions.values():
            if successor.state_id not in seen:
                seen.add(successor.state_id)
                ordered.append(successor)
    ordered += [s for s in mealy.states if s.state_id not in seen]
    return ordered


def mealy_to_pylstar(mealy):
    """Convert an AALpy MealyMachine into a pylstar Automata.

    States are named "0", "1", ... with the initial state as "0", which is what
    pylstar-tls's convert_from_pylstar() expects.
    """
    states = _states_in_bfs_order(mealy)
    pylstar_states = {s.state_id: State(str(i)) for i, s in enumerate(states)}
    n_transitions = 0
    for state in states:
        source = pylstar_states[state.state_id]
        for input_symbol, destination in state.transitions.items():
            output_symbol = state.output_fun[input_symbol]
            source.transitions.append(
                Transition(
                    f"t{n_transitions}",
                    pylstar_states[destination.state_id],
                    Letter(input_symbol),
                    Letter(output_symbol),
                )
            )
            n_transitions += 1
    return Automata(pylstar_states[states[0].state_id])


class PylstarEqOracle(Oracle):
    """AALpy equivalence oracle that delegates to a pylstar(-tls) eqtests object.

    This lets L# use pylstar-tls's own oracles (BDist, HappyPathFirst,
    StoreHypotheses, or pylstar's RandomWalk / WpMethod) unchanged.
    """

    def __init__(self, alphabet, sul, eqtests):
        super().__init__(alphabet, sul)
        self.eqtests = eqtests

    def find_cex(self, hypothesis):
        counterexample = self.eqtests.find_counterexample(mealy_to_pylstar(hypothesis))
        if counterexample is None:
            return None
        return tuple(_symbol(letter) for letter in counterexample.input_word.letters)


class LSharpLearner:
    """Same interface as pylstar.LSTAR.LSTAR, but learning is done by AALpy's L#."""

    # AALpy's statistics for the last learn() call (rounds, timings), for run_lsharp.py.
    last_info = None

    # pylint: disable=too-many-arguments,unused-argument
    def __init__(self, input_vocabulary, knowledge_base, max_states, tmp_dir=None, eqtests=None):
        self.input_vocabulary = list(input_vocabulary)
        self.knowledge_base = knowledge_base
        # L# has no state bound. max_states is only used, as in pylstar's LSTAR,
        # for the default equivalence test.
        if eqtests is None:
            letters = [Letter(s) for s in self.input_vocabulary]
            eqtests = WpMethodEQ(knowledge_base, max_states, letters)
        self.eqtests = eqtests

    def learn(self):
        sul = KnowledgeBaseSUL(self.knowledge_base)
        oracle = PylstarEqOracle(self.input_vocabulary, sul, self.eqtests)
        mealy, info = run_Lsharp(
            self.input_vocabulary,
            sul,
            oracle,
            automaton_type="mealy",
            # Separating sequences (not adaptive distinguishing sequences): ADS
            # drives the SUL step by step, which costs one TLS session per step.
            extension_rule="SepSeq",
            separation_rule="SepSeq",
            # pylstar's KnowledgeTree already caches queries and detects
            # non-determinism; a second cache would skew n_queries.
            cache_and_non_det_check=False,
            return_data=True,
            print_level=0,
        )
        LSharpLearner.last_info = info
        return mealy_to_pylstar(mealy)
