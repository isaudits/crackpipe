'''
Implementation of the recycle (cracked-password re-attack) step from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack

Feeds already-cracked plaintext back through a set of rules to catch variants
(Password1 -> Password2 -> Password!). Uses the [outfile]/[working] feedback
placeholders resolved by core.cracker.CrackThread: each rule run appends newly
cracked hashes to [outfile], and [working] is rebuilt from it before the next run.
'''

import json
from modules import base

# Rules to recycle through when none are configured. OneRule ships in the repo;
# best66/dive come from the hashcat install (resolve_rule checks both).
DEFAULT_RULES = ["OneRuleToRuleThemAll.rule", "best66.rule", "dive.rule"]

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
        [outfile] collects cracked hash:plain; [working] is the recycled dictionary
        '''

        try:
            rules = json.loads(self.config.get("recycle", "rules", fallback=""))
        except ValueError:
            rules = []
        if not rules:
            rules = DEFAULT_RULES

        commands = []

        # Seed the cracked-password dictionary from the potfile
        commands.append(self.hcat_base_cmd + " --show -o [outfile]")

        # Re-attack with each rule; [working] rebuilds from [outfile] before each run
        for rule in rules:
            commands.append("{hcat_base_cmd} -o [outfile] -r {rule} [working]".format(
                                hcat_base_cmd=self.hcat_base_cmd,
                                rule=self.resolve_rule(rule),
                                )
                            )

        commands.append(self.hcat_base_cmd + " --show")


        self.commands = commands
