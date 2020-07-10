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
        
        import rules_best64
        commands += rules_best64.Attack(self.hash_list, self.hash_type).commands
        
        import rules_hob064
        commands += rules_hob064.Attack(self.hash_list, self.hash_type).commands
        
        import rules_passwordspro
        commands += rules_hob064.Attack(self.hash_list, self.hash_type).commands
        
        import rules_T0XlC
        commands += rules_T0XlC.Attack(self.hash_list, self.hash_type).commands
        
        import rules_d3ad0ne
        commands += rules_d3ad0ne.Attack(self.hash_list, self.hash_type).commands
        
        import rules_onerule
        commands += rules_onerule.Attack(self.hash_list, self.hash_type).commands
        
        import rules_d3adhob0
        commands += rules_d3adhob0.Attack(self.hash_list, self.hash_type).commands
        
        import rules_dive
        commands += rules_dive.Attack(self.hash_list, self.hash_type).commands
        
        
        
        self.commands = commands