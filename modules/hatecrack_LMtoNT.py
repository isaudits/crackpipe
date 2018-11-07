#!/usr/bin/env python
'''
Implementation of LanMan to NT attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack
'''

import re
import os
import base

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
        
        commands=[]
        
        #Brute force LM hashes and output results to outfile.lm.cracked
        commands.append("{hcat_base_cmd} -o {out_file} -1 ?u?d?s --increment -a 3 ?1?1?1?1?1?1?1".format(
                            hcat_base_cmd=self.hcat_base_cmd.replace("-m 1000", "-m 3000"),
                            out_file=self.job_id+".lm.cracked",
                            cwd=os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir),
                            )
                        )
        
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
        
        #Crack NT hashes using dictionary of combined LM hash halves with case toggle rule
        commands.append("{hcat_base_cmd} -r {cwd}/rules/toggles-lm-ntlm.rule {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd.replace("-m 3000", "-m 1000"),
                            cwd=os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir),
                            wordlist=self.job_id+".combined"
                            )
                       )
        
        commands.append(self.hcat_base_cmd + " --show")
        
        
        self.commands = commands