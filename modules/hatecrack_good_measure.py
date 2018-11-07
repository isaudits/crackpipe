#!/usr/bin/env python
'''
Implementation of Extra Good Measure chained attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack

combinator -> PasswordsPro ruleset

'''


import re
import base
import json

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
        
        commands.append("{hcat_base_cmd} -r {hcat_path}/rules/combinator.rule -r {hcat_path}/rules/InsidePro-PasswordsPro.rule {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "good_measure_base_list"))
                        )
        
        commands.append(self.hcat_base_cmd + " --show")
        
        
        self.commands = commands