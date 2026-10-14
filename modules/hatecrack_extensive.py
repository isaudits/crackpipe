'''
Extensive "Pure_Hate" methodology from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack

Runs the full ordered attack chain, recycling cracked passwords between every
stage. Each stage is a self-contained sub-attack run in turn; cracked passwords
propagate between stages through the shared hashcat potfile (keep
temporary_potfile=false), and the recycle steps re-attack everything cracked so
far. Remaining hashes and results are carried forward across stages.
'''

from modules import base
from modules import hatecrack_bruteforce
from modules import hatecrack_recycle
from modules import combo_rules
from modules import hatecrack_topmask
from modules import hatecrack_fingerprint
from modules import hatecrack_combinator
from modules import hatecrack_hybrid
from modules import hatecrack_good_measure

class Attack(base.Attack):
    def init(self):
        '''
        subclass specific initializations - use instead of `__init__`
        '''


    def build_commands(self):
        # This module orchestrates whole sub-attacks (see crack_passwords); it
        # has no hashcat commands of its own.
        self.commands = []

    def sequence(self):
        # (label, module) in hate_crack's extensive order, recycling between each
        return [
            ("Brute force", hatecrack_bruteforce),
            ("Recycle", hatecrack_recycle),
            ("Dictionary + rules", combo_rules),
            ("Recycle", hatecrack_recycle),
            ("Top mask", hatecrack_topmask),
            ("Recycle", hatecrack_recycle),
            ("Fingerprint", hatecrack_fingerprint),
            ("Recycle", hatecrack_recycle),
            ("Combinator", hatecrack_combinator),
            ("Recycle", hatecrack_recycle),
            ("Hybrid", hatecrack_hybrid),
            ("Recycle", hatecrack_recycle),
            ("Good measure", hatecrack_good_measure),
            ("Recycle", hatecrack_recycle),
        ]

    def crack_passwords(self):
        '''
        Drive each sub-attack in turn, carrying the remaining hash list and the
        collected results forward. Overrides the base single-CrackThread run.
        '''
        for label, module in self.sequence():
            if not self.hash_list:
                print("\n[*] Extensive methodology: all hashes cracked - stopping.")
                break

            print("\n[*] Extensive methodology: {0} ({1} hashes remaining)".format(label, len(self.hash_list)))

            attack = module.Attack(self.hash_list, self.hash_type)
            attack.crack_passwords()

            self.hash_list = attack.hash_list
            for result in attack.results:
                if result not in self.results:
                    self.results.append(result)

        return self.job_id, "Request accepted."
