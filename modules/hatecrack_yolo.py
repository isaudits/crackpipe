'''
Implementation of the YOLO Combinator attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack

Repeatedly combinator-attacks two randomly chosen optimized wordlists. Runs
until interrupted (Ctrl-C) by default, or for a fixed number of rounds when
[yolo] iterations is set. A multi-pass (Approach B) attack: run_attack() drives
the rounds and harvests results at the end.
'''

import os
import random
from modules import base
from core import cracker

class Attack(base.Attack):
    def init(self):
        '''
        subclass specific initializations - use instead of `__init__`
        '''
        # 0 == run until Ctrl-C (hate_crack behavior); >0 caps the rounds
        self.iterations = int(self.config.get("yolo", "iterations", fallback="0"))


    def build_commands(self):
        # Wordlist pairs are chosen at random each round in run_attack().
        self.commands = []

    def run_attack(self):
        opt = os.path.expanduser(self.config.get("wordlist", "optimized_path", fallback=""))
        files = []
        if opt and os.path.isdir(opt):
            files = [f for f in os.listdir(opt) if os.path.isfile(os.path.join(opt, f))]

        if not files:
            print("YOLO: no wordlists found in optimized_path (" + str(opt) + "); nothing to do.")
            self.output = ""
            return

        print("YOLO combinator: combining random optimized wordlists " +
              ("for {0} rounds".format(self.iterations) if self.iterations else "until Ctrl-C") + "...")

        count = 0
        try:
            while self.iterations == 0 or count < self.iterations:
                left = os.path.join(opt, random.choice(files))
                right = os.path.join(opt, random.choice(files))
                command = "{hcat_base_cmd} -o [outfile] -a 1 {left} {right}".format(
                            hcat_base_cmd=self.hcat_base_cmd, left=left, right=right)
                thread = cracker.CrackThread(self.job_id, self.hash_type, self.hash_list, [command], cleanup=False)
                thread.start()
                thread.join()
                count += 1
        except KeyboardInterrupt:
            print("\nYOLO: stopped after {0} rounds.".format(count))
        # Results are harvested (and temp files removed) by base.harvest().
