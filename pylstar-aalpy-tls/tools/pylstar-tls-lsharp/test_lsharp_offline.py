"""Offline check of LSharpLearner: no TLS, no network.

Each testdata/*.automaton (a state machine previously inferred by pylstar-tls)
is used as the system under learning through pylstar's FakeActiveKnowledgeBase.
L#, driven by pylstar-tls's own BDist oracle, must learn it back exactly.

Run inside the image:  cd /opt/lsharp && python -m pytest -q test_lsharp_offline.py
"""

import os
import sys

import pytest

sys.path.insert(0, os.environ.get("PYLSTAR_TLS_SRC", "/root/pylstar-tls/src"))

# pylint: disable=wrong-import-position
from pylstar.FakeActiveKnowledgeBase import FakeActiveKnowledgeBase
from pylstar.Letter import Letter
from pylstar.automata.Automata import Automata
from pylstar.automata.State import State
from pylstar.automata.Transition import Transition

from automata.automata import convert_from_pylstar, load_automaton_from_file
from BDistMethod import BDistMethod

from lsharp_learner import LSharpLearner

TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def to_pylstar(automaton):
    """pylstar-tls Automaton (as loaded from a .automaton file) -> pylstar Automata."""
    states = {s: State(str(s)) for s in automaton.states}
    n_transitions = 0
    for source, transitions in automaton.states.items():
        for input_word, (destination, output_words, _) in sorted(transitions.items()):
            states[source].transitions.append(
                Transition(
                    f"t{n_transitions}",
                    states[destination],
                    Letter(input_word),
                    Letter("+".join(output_words)),
                )
            )
            n_transitions += 1
    return Automata(states[0])


@pytest.mark.parametrize(
    "filename", sorted(f for f in os.listdir(TESTDATA) if f.endswith(".automaton"))
)
def test_lsharp_relearns_automaton(filename):
    reference = load_automaton_from_file(os.path.join(TESTDATA, filename))
    vocabulary = sorted(reference.input_vocabulary)
    knowledge_base = FakeActiveKnowledgeBase(to_pylstar(reference))
    eqtests = BDistMethod(knowledge_base, [Letter(s) for s in vocabulary], 3)

    learned = LSharpLearner(vocabulary, knowledge_base, 15, eqtests=eqtests).learn()

    assert convert_from_pylstar(vocabulary, learned) == reference
    assert LSharpLearner.last_info["automaton_size"] == len(reference.states)
