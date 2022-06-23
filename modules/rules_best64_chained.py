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
        
        commands=[]
        
        commands.append("{hcat_base_cmd} -r {rules_path}/best64.rule -r {rules_path}/best64.rule {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            rules_path=self.rules_path,
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "dictionary_wordlist"))
                        )
        
        commands.append(self.hcat_base_cmd + " --show")
                        
        self.commands = commands