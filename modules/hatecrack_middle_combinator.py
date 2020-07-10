'''
Implementation of middle fast combinator attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack
'''
import re
import json
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
        
        commands=[]
        
        # Use JSON to grab list from config file
        masks = json.loads(self.config.get("masks", "middle_combinator_masks"))
        
        for x in range(len(masks)):
        
        
        
            commands.append("{hcat_base_cmd} -a 1 -j '${middle_mask}' {left} {right}".format(
                                hcat_base_cmd=self.hcat_base_cmd,
                                left=self.config.get("wordlist", "path")+self.config.get("wordlist", "middle_base_list"),
                                right=self.config.get("wordlist", "path")+self.config.get("wordlist", "middle_base_list"),
                                middle_mask=masks[x]
                                )
                            )
            
        commands.append(self.hcat_base_cmd + " --show")
        
        
        self.commands = commands