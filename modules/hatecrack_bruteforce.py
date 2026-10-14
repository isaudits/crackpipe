'''
Implementation of brute force (mask increment) attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack
'''

import re
from modules import base

class Attack(base.Attack):
    def init(self):
        '''
        subclass specific initializations - use instead of `__init__`
        for example, use to override self.results_regex
        '''


    def build_commands(self):
        '''
        [hashfile] will be replaced with the actual temp hashfile location
        [potfile] will be replaced with the actual temp potfile location
        for hashcat, make sure to run again with --show parameter to show all cracked hashes, including those that were in potfile
        '''

        # Length bounds are optional; default to 1-7 (fast full-keyspace sweep).
        min_len = int(self.config.get("bruteforce", "min_length", fallback="1"))
        max_len = int(self.config.get("bruteforce", "max_length", fallback="7"))
        mask = "?a" * max_len

        commands=[]

        commands.append("{hcat_base_cmd} -a 3 --increment --increment-min={min_len} --increment-max={max_len} {mask}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            min_len=min_len,
                            max_len=max_len,
                            mask=mask,
                            )
                        )

        commands.append(self.hcat_base_cmd + " --show")


        self.commands = commands
