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
        
        from modules import combo_mcjon3z
        commands += combo_mcjon3z.Attack(self.hash_list, self.hash_type).commands
        
        from modules import rules_pantagrule_hybrid
        commands += rules_pantagrule_hybrid.Attack(self.hash_list, self.hash_type).commands
        
        from modules import hatecrack_hybrid
        commands += hatecrack_hybrid.Attack(self.hash_list, self.hash_type).commands
        
        from modules import hatecrack_middle_combinator
        commands += hatecrack_middle_combinator.Attack(self.hash_list, self.hash_type).commands
        
        self.commands = commands