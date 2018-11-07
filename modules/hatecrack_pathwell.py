#!/usr/bin/env python
'''
Implementation of pathwell attack from TrustedSec hate_crack:
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
        
        commands.append("{hcat_base_cmd} -a 3 {cwd}/masks/pathwell.hcmask".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            cwd=os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir),
                            )
                        )
        
        commands.append(self.hcat_base_cmd + " --show")
        
        
        self.commands = commands