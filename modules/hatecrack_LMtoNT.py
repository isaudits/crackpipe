'''
Implementation of LanMan to NT attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack
'''

import re
import os
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
        
        cwd = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)

        # base.process_hash_list() writes the LM hashes to {job}.lm and the NT
        # hashes to {job}.hash ([hashfile]) when a PWDUMP file is loaded.
        lm_base_cmd = self.hcat_base_cmd.replace("-m 1000", "-m 3000").replace("[hashfile]", self.job_id + ".lm")

        commands=[]

        #Pull any already-cracked LM hashes out of the potfile
        commands.append(lm_base_cmd + " --show > {hash_file}.lm.cracked".format(hash_file=self.job_id))

        #Brute force LM hashes (max 7 chars per half); append results to the same file
        commands.append(lm_base_cmd + " -o {hash_file}.lm.cracked -1 ?u?d?s --increment -a 3 ?1?1?1?1?1?1?1".format(hash_file=self.job_id))

        #Create working file of cracked hash halves
        commands.append("cat {hash_file}.lm.cracked | cut -d : -f 2 > {hash_file}.working".format(
                            hash_file=self.job_id
                            )
                       )

        #Use combinator app to create a combined dictionary of cracked password halves
        commands.append("{utils_path}/bin/combinator.bin {hash_file}.working {hash_file}.working | sort -u > {hash_file}.combined".format(
                            utils_path=self.config.get("hashcat", "utils_path"),
                            hash_file=self.job_id,
                            )
                        )

        #Crack NT hashes ([hashfile]) using combined LM halves with case toggle rule
        commands.append("{hcat_base_cmd} -r {cwd}/rules/toggles-lm-ntlm.rule {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            cwd=cwd,
                            wordlist=self.job_id+".combined"
                            )
                       )

        commands.append(self.hcat_base_cmd + " --show")


        self.commands = commands