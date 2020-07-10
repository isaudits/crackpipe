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
        
        commands=[]
        
        commands.append("{hcat_base_cmd} -r {cwd}/rules/d3adhob0.rule {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            cwd=os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "dictionary_wordlist"))
                        )
        
        commands.append(self.hcat_base_cmd + " --show")

                        
        self.commands = commands