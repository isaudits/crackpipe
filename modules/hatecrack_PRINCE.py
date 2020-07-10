'''
Implementation of PRINCE attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack
'''

import re
import sys
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
        
        if sys.platform == 'darwin':
            prince_bin = "pp64.app"
        else:
            prince_bin = "pp64.bin"
        
        commands=[]
        
        commands.append("{cwd}/princeprocessor/{prince_bin} --case-permute --elem-cnt-min=1 --elem-cnt-max=16 -c < {wordlist} | {hcat_base_cmd} -r {cwd}/princeprocessor/rules/prince_optimized.rule".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "prince_base_list"),
                            cwd=os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir),
                            prince_bin=prince_bin,
                            )
                        )
        
        commands.append(self.hcat_base_cmd + " --show")
        
        
        self.commands = commands