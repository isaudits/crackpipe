'''
Implementation of hybrid attack from TrustedSec hate_crack:
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
        
        commands=[]
        
        # append 2 digit / symbol
        commands.append("{hcat_base_cmd} -a 6 -1 ?s?d {wordlist} ?1?1".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "hybrid_list"))
                        )
        
        # append 3 digit / symbol
        commands.append("{hcat_base_cmd} -a 6 -1 ?s?d {wordlist} ?1?1?1".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "hybrid_list"))
                        )
        
        # append 4 digit / symbol
        commands.append("{hcat_base_cmd} -a 6 -1 ?s?d {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "hybrid_list"))
                        )
        
        # prepend 2 digit / symbol
        commands.append("{hcat_base_cmd} -a 7 -1 ?s?d ?1?1 {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "hybrid_list"))
                        )
        
        # prepend 3 digit / symbol
        commands.append("{hcat_base_cmd} -a 7 -1 ?s?d ?1?1 {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "hybrid_list"))
                        )
        
        # prepend 4 digit / symbol
        commands.append("{hcat_base_cmd} -a 7 -1 ?s?d ?1?1?1?1 {wordlist}".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            hcat_path=self.config.get("hashcat", "path"),
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "hybrid_list"))
                        )
        
        commands.append(self.hcat_base_cmd + " --show")
        
        
        self.commands = commands