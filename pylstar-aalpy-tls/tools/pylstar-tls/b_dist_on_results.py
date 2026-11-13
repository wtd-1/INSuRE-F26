import os
import time

from pylstar.LSTAR import LSTAR
from pylstar.eqtests.RandomWalkMethod import RandomWalkMethod

from bdist_compute import  construct_automata
from BdistMethod import *
from pylstar.FakeActiveKnowledgeBase import FakeActiveKnowledgeBase
from prettytable import PrettyTable

from tests import automata_to_automaton

chemin_b_dist = {}
os.chdir("../../results")

# Génération de la table pour générer le fichier html
table = PrettyTable()
table.field_names = ["Automate", "Bdist", "Mot pour lequel Bdist est atteint", "Paires", "Random Walk Ex time", "Bdist Ex Time", "Ecart relatif"]

for filename in os.listdir("."):
    if filename[0] != ".":
        for file in os.listdir("./%s" % filename):
            print("%s/%s" % (filename, file))
            if file.endswith(".automaton"):  # on calcule pour chaque fichier .automaton
                automate, input_letters, nb_state = construct_automata("%s/%s" % (filename, file))
                b_dist, chemin_b_dist[0], chemin_b_dist[1], mot_b_dist, b_pairs = bdist_compute.bdist_compute(automate, input_letters, nb_state)

                # b_dist, chemin_b_dist[0], chemin_b_dist[1], mot_b_dist, b_pairs = bdist_compute.bdist_compute_from_file(z
                #     "%s/%s" % (filename, file))

                kb = FakeActiveKnowledgeBase(automate)

                bdEqTests = BdistMethod(kb, input_letters, max_steps=nb_state)
                bdist_lstar = LSTAR(input_letters, kb, max_states=nb_state, eqtests=bdEqTests)
                start_time = time.time()
                bdist_infered_automata = bdist_lstar.learn()
                bdist_execution_time = round(time.time() - start_time, 4)
                print("--- BdistMethod :  %s seconds ---" % bdist_execution_time)

                rwEqTests = RandomWalkMethod(kb, input_letters, max_steps=nb_state, restart_probability=0.75)
                rw_lstar = LSTAR(input_letters, kb, max_states=nb_state, eqtests=rwEqTests)
                start_time = time.time()
                rw_infered_automata = rw_lstar.learn()
                rw_execution_time = round(time.time() - start_time, 4)
                print("--- RandomWalk :  %s seconds ---" % rw_execution_time)
                if automata_to_automaton(bdist_infered_automata) == automata_to_automaton(rw_infered_automata):
                    execution_difference = str(round((bdist_execution_time - rw_execution_time) / rw_execution_time * 100,1)) + "%"
                    print(execution_difference)
                    if b_dist != 1:
                        table.add_row([file, b_dist, mot_b_dist, b_pairs, rw_execution_time, bdist_execution_time, execution_difference])
                    else:  # on n'ajoute pas les paires pour b_dist=1 pour plus de lisibilité
                        table.add_row([file, b_dist, mot_b_dist, "", rw_execution_time, bdist_execution_time, execution_difference])
                else:
                    print("Infered automatas not equal")
                continue

f = open("../tools/b_dist/result.html", "w")
f.write("<style>tr:hover {background-color: #D6EEEE;}</style>")  # Style du tableau HTML
f.write(table.get_html_string())
