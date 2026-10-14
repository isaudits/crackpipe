'''
Implementation of the Fingerprint attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack

Expands cracked passwords into fragments with hashcat-utils' expander, runs a
combinator attack over those fragments, and repeats until no new hashes crack.
This is the "Approach B" multi-pass attack: run_attack() loops CrackThread
passes (cleanup=False) and watches cracked_count() to decide when to stop.
'''

import os
from modules import base
from core import cracker

class Attack(base.Attack):
    def init(self):
        '''
        subclass specific initializations - use instead of `__init__`
        '''
        self.max_iterations = int(self.config.get("fingerprint", "max_iterations", fallback="10"))


    def build_commands(self):
        '''
        One expand+combinator iteration. run_attack() seeds [outfile], repeats
        these commands while new hashes keep cracking, then harvests results.
        [working] is rebuilt from [outfile] before the expander runs.
        '''
        expander = os.path.join(self.utils_path, "bin", "expander.bin")
        expanded = self.job_id + ".expanded"

        self.commands = [
            "{expander} < [working] | sort -u > {expanded}".format(expander=expander, expanded=expanded),
            "{hcat_base_cmd} -o [outfile] -a 1 {expanded} {expanded}".format(
                hcat_base_cmd=self.hcat_base_cmd, expanded=expanded),
        ]

    def run_pass(self, commands, cleanup):
        thread = cracker.CrackThread(self.job_id, self.hash_type, self.hash_list, commands, cleanup=cleanup)
        thread.start()
        thread.join()
        return thread

    def run_attack(self):
        # Seed the cracked-password dictionary from the potfile
        before = self.run_pass([self.hcat_base_cmd + " --show -o [outfile]"], cleanup=False).cracked_count()

        # Expand + combinator, repeating until a pass cracks nothing new
        for _ in range(self.max_iterations):
            after = self.run_pass(self.commands, cleanup=False).cracked_count()
            if after <= before:
                break
            before = after
        # Results are harvested (and temp files removed) by base.harvest().
