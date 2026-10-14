'''
Implementation of PRINCE attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack
'''

import re
import glob
import os
from modules import base

class Attack(base.Attack):
    def init(self):
        '''
        subclass specific initializations - use instead of `__init__`
        for example, use to override self.results_regex
        '''


    def prince_binary(self, prince_dir):
        '''
        Locate the princeprocessor binary. The submodule ships source only, so
        the binary is built locally (`make -C princeprocessor/src`) and its name
        is platform-specific (ppAppleArm64.bin on Apple Silicon, pp64.bin on
        Linux). Checks the built src/ location and legacy top-level names.
        '''
        candidates = [
            os.path.join(prince_dir, 'src', 'ppAppleArm64.bin'),
            os.path.join(prince_dir, 'src', 'pp64.bin'),
            os.path.join(prince_dir, 'src', 'pp64.app'),
            os.path.join(prince_dir, 'pp64.bin'),
            os.path.join(prince_dir, 'pp64.app'),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        built = sorted(glob.glob(os.path.join(prince_dir, 'src', 'pp*.bin')))
        if built:
            return built[0]
        return candidates[0]  # default; hashcat will error clearly if unbuilt

    def build_commands(self):
        '''
        [hashfile] will be replaced with the actual temp hashfile location
        [potfile] will be replaced with the actual temp potfile location
        for hashcat, make sure to run again with --show parameter to show all cracked hashes, including those that were in potfile
        '''

        cwd = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
        prince_dir = os.path.join(cwd, "tools", "princeprocessor")

        commands=[]

        commands.append("{prince_bin} --case-permute --elem-cnt-min=1 --elem-cnt-max=16 -c < {wordlist} | {hcat_base_cmd} -r {prince_dir}/rules/prince_optimized.rule".format(
                            hcat_base_cmd=self.hcat_base_cmd,
                            wordlist=self.config.get("wordlist", "path")+self.config.get("wordlist", "prince_base_list"),
                            prince_bin=self.prince_binary(prince_dir),
                            prince_dir=prince_dir,
                            )
                        )

        commands.append(self.hcat_base_cmd + " --show")


        self.commands = commands