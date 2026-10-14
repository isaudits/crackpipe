'''
Implementation of the Top Mask attack from TrustedSec hate_crack:
https://github.com/trustedsec/hate_crack

Analyzes already-cracked passwords with PACK (statsgen/maskgen) to build a
time-bounded hashcat mask set, then runs it as a mask attack. Uses the
[outfile]/[working] feedback placeholders resolved by core.cracker.CrackThread.
'''

import os
import sys
from modules import base

class Attack(base.Attack):
    def init(self):
        '''
        subclass specific initializations - use instead of `__init__`
        for example, use to override self.results_regex
        '''


    def pack_path(self):
        '''
        Directory containing PACK's statsgen.py/maskgen.py. Defaults to the
        bundled tools/PACK dir; override with [topmask] pack_path (absolute, or
        relative to the repo root).
        '''
        return self.resolve_vendored(self.config.get("topmask", "pack_path", fallback="auto"), "tools/PACK")

    def build_commands(self):
        '''
        [hashfile] / [potfile] / [outfile] / [working] are resolved per command
        by core.cracker.CrackThread.
        '''

        pack = self.pack_path()
        statsgen = os.path.join(pack, "statsgen.py")
        maskgen = os.path.join(pack, "maskgen.py")

        if not (os.path.isfile(statsgen) and os.path.isfile(maskgen)):
            print("PACK not found at " + pack + " - Top Mask needs statsgen.py/maskgen.py.")
            print("Vendor PACK there or set [topmask] pack_path in your config.")
            self.commands = []
            return

        target_time = self.config.get("topmask", "target_time", fallback="14400")
        pps = self.config.get("topmask", "pps", fallback="14000000000")
        min_length = self.config.get("topmask", "min_length", fallback="7")
        python = sys.executable or "python3"

        masks = self.job_id + ".masks"
        hcmask = self.job_id + ".hcmask"

        commands = []

        # Seed the cracked-password dictionary from the potfile
        commands.append(self.hcat_base_cmd + " --show -o [outfile]")

        # Analyze cracked passwords, then generate a time-boxed mask set
        commands.append("{python} {statsgen} [working] -o {masks}".format(
                            python=python, statsgen=statsgen, masks=masks))

        commands.append("{python} {maskgen} {masks} --targettime {target} --optindex -q --pps {pps} --minlength={minlen} -o {hcmask}".format(
                            python=python, maskgen=maskgen, masks=masks,
                            target=target_time, pps=pps, minlen=min_length, hcmask=hcmask))

        # Mask attack with the generated masks
        commands.append("{hcat_base_cmd} -o [outfile] -a 3 {hcmask}".format(
                            hcat_base_cmd=self.hcat_base_cmd, hcmask=hcmask))

        commands.append(self.hcat_base_cmd + " --show")


        self.commands = commands
