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
        
        import simple_wordlist
        commands += simple_wordlist.Attack(self.hash_list, self.hash_type).commands
        
        import simple_passlist
        commands += simple_passlist.Attack(self.hash_list, self.hash_type).commands
        
        import combo_rules
        commands += combo_rules.Attack(self.hash_list, self.hash_type).commands
        
        import hatecrack_hybrid
        commands += hatecrack_hybrid.Attack(self.hash_list, self.hash_type).commands
        
        import hatecrack_middle_combinator
        commands += hatecrack_middle_combinator.Attack(self.hash_list, self.hash_type).commands
        
        
        self.commands = commands