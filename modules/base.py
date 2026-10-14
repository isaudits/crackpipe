"""
The base module defines the `Attack` class.
This class has to be inherited to create a new cracking module.

Default methods can be overridden in the inheriting module
"""

from configparser import ConfigParser
import logging
import time
import re
import os
import shutil
from core import messages
from core import cracker
from core import util

class Attack:
    def __init__(self,hash_list, hash_type=1000):
        '''
        Attack object constructor. Defaults to hashcat NT hash (1000)
        
        Should not be be overridden. This calls overridable `init()` function which is
        used to perform module-specific initializations.
        '''
        
        self.config_file = 'config/config.cfg'
        self.job_id = str(int(time.time()))
        self.hash_list = hash_list
        self.hash_type = str(hash_type)
        self.commands = []
        self.processes = {}
        self.hashes = {}
        self.output = ''
        self.cracked_count = 0
        self.results = []
        self.hashcat_tuning = ''
        self.hashcat_path = ''
        self.rules_path = ''
        self.masks_path = ''
        self.utils_path = ''

        
        self.read_config()

        # Auto-detect the hashcat mode when the user left the type at the
        # default. Must happen before hcat_base_cmd / build_commands() below,
        # since those bake -m {hash_type} into every command.
        if self.hash_type == '1000':
            detected = self.detect_hash_type()
            if detected:
                print("Auto-detected hash type: -m " + detected)
                self.hash_type = detected

        # path/bin are optional: unset means "find hashcat on PATH". Set them
        # only for a non-standard install location.
        self.hashcat_path = self.config.get("hashcat", "path", fallback="")
        self.hashcat_bin = self.config.get("hashcat", "bin", fallback="hashcat")
        self.hashcat_tuning = self.config.get("hashcat", "tuning", fallback="")
        self.hashcat_binary = self.resolve_hashcat_binary()
        # rules_path/masks_path are optional and default to "auto" (detect from
        # the hashcat install). May also be absolute or relative to the repo.
        self.rules_path = self.resolve_data_path(self.config.get("hashcat", "rules_path", fallback="auto"), "rules")
        self.masks_path = self.resolve_data_path(self.config.get("hashcat", "masks_path", fallback="auto"), "masks")
        # utils_path: "auto"/unset -> the bundled hashcat-utils submodule
        self.utils_path = self.resolve_vendored(self.config.get("hashcat", "utils_path", fallback="auto"), "tools/hashcat-utils")

        
        # Name the hashcat session after the job so concurrent runs don't clash
        # and an interrupted attack can be resumed with --restore --session <id>.
        if self.config.getboolean("hashcat", "temporary_potfile", fallback=False):
            self.hcat_base_cmd = "{hcat_bin} -m {hash_type} --session {session} --potfile-path [potfile] {tuning} [hashfile]".format(
                                    hcat_bin=self.hashcat_binary,
                                    hash_type=self.hash_type,
                                    session=self.job_id,
                                    tuning=self.hashcat_tuning,
                                    )
        else:
            self.hcat_base_cmd = "{hcat_bin} -m {hash_type} --session {session} {tuning} [hashfile]".format(
                                    hcat_bin=self.hashcat_binary,
                                    hash_type=self.hash_type,
                                    session=self.job_id,
                                    tuning=self.hashcat_tuning,
                                    )
        
        ### Add --username flag for IPMI hashes - https://blog.rapid7.com/2013/07/02/a-penetration-testers-guide-to-ipmi/
        if self.hash_type == '7300':
            self.hcat_base_cmd += " --username"
        
        # Run module-specific initializations
        self.init()

        self.build_commands()
        
        logging.debug("Cracking module initialized...")
        logging.debug("commands: " + str(self.commands))
        logging.debug("hash type: " + self.hash_type)
        logging.debug("hash list: " +str(self.hash_list))
        
        
    def init(self):
        logging.debug("init run from parent class - does nothing; should be subclassed in module")
        
    def build_commands(self):
        logging.debug("build_commands run from parent class - does nothing; should be subclassed in module")
        
    def read_config(self):
        '''
        Gets info from config file
        '''
        self.config = ConfigParser()
        self.config.read(self.config_file)

    def resolve_hashcat_binary(self):
        '''
        Resolve the hashcat executable. Prefers the configured path/bin, then a
        PATH lookup, so an unset/stale config still works for a standard install.
        '''
        candidate = os.path.join(self.hashcat_path, self.hashcat_bin)
        if os.path.isfile(candidate):
            return candidate
        return shutil.which(self.hashcat_bin) or shutil.which('hashcat') or candidate

    def resolve_rule(self, name):
        '''
        Resolve a rule file name to a usable path. An absolute path or one with a
        directory component is used as-is; a bare name is looked up in rules_path
        (the hashcat install) first, then the repo's bundled rules/ dir.
        '''
        if os.path.isabs(name) or os.sep in name:
            return name
        candidate = os.path.join(self.rules_path, name)
        if os.path.isfile(candidate):
            return candidate
        repo_rules = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir, "rules")
        return os.path.normpath(os.path.join(repo_rules, name))

    def resolve_vendored(self, value, default_rel):
        '''
        Resolve a path to a vendored tool (hashcat-utils, PACK, ...). Accepts:
          - "auto" or unset: the bundled copy at default_rel (under the repo root)
          - an absolute path: used as-is
          - a relative path: resolved against the repo root
        '''
        repo_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
        value = (value or '').strip()
        if not value or value.lower() == 'auto':
            return os.path.normpath(os.path.join(repo_root, default_rel))
        if os.path.isabs(value):
            return value
        return os.path.normpath(os.path.join(repo_root, value))

    def resolve_data_path(self, value, subdir):
        '''
        Resolve a configured rules/masks path. Accepts:
          - "auto": detect the directory from the hashcat install
          - an absolute path: used as-is
          - a relative path: resolved against the repo root (bundled dirs)
        '''
        value = (value or '').strip()
        repo_root = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)

        if value.lower() == 'auto':
            detected = self.detect_hashcat_data_dir(subdir)
            if detected:
                return detected
            # fall back to the repo's bundled dir if detection fails
            return os.path.normpath(os.path.join(repo_root, subdir))

        if os.path.isabs(value):
            return value

        return os.path.normpath(os.path.join(repo_root, value))

    def detect_hashcat_data_dir(self, subdir):
        '''
        Locate hashcat's bundled data directory (e.g. "rules" or "masks") by
        resolving the hashcat binary to its real location and checking the
        share paths relative to the install prefix. Works regardless of the
        install method (Homebrew on Intel/ARM, Linux packages, manual builds).
        Returns the directory path, or None if it can't be found.
        '''
        binary = self.hashcat_binary

        candidates = []
        if binary and os.path.isfile(binary):
            # .../<prefix>/bin/hashcat -> <prefix>
            prefix = os.path.dirname(os.path.dirname(os.path.realpath(binary)))
            candidates.append(os.path.join(prefix, 'share', 'doc', 'hashcat', subdir))
            candidates.append(os.path.join(prefix, 'share', 'hashcat', subdir))

        # common system locations as a fallback
        candidates += [
            '/opt/homebrew/share/hashcat/' + subdir,
            '/usr/local/share/hashcat/' + subdir,
            '/usr/share/hashcat/' + subdir,
            '/usr/local/share/doc/hashcat/' + subdir,
        ]

        for candidate in candidates:
            if os.path.isdir(candidate):
                return candidate

        logging.warning("Could not auto-detect hashcat %s directory", subdir)
        return None

    def check_hashtype(self):
        '''
        Checks hashtype against accepted hash types from config file; returns
        True if it is of an accepted type
        
        TODO - Need to implement!
        '''
        return True
    
    def detect_hash_type(self):
        '''
        Inspect the first hash and return the matching hashcat mode as a string,
        or None if the format isn't recognized. Used to override the default
        mode when the user didn't explicitly specify one.

        Regex for various hash types: https://github.com/psypanda/hashID/blob/master/prototypes.json
        '''
        if not self.hash_list:
            return None

        sample = self.hash_list[0]

        ### NetNTLMv2 - user::domain:serverchallenge:ntproofstr:blob
        if re.search(r".*:.*:.*:[a-z0-9A-Z]{16}:[a-z0-9A-Z]{32}:[a-z0-9A-Z]*", sample):
            return '5600'

        ### PWDUMP / NTLM - user:uid:lm:ntlm:::
        if re.search(r"[a-z0-9A-Z]{32}:[a-z0-9A-Z]{32}:::", sample):
            return '1000'

        return None

    def process_hash_list(self):
        ### Note - Regex for various hash types: https://github.com/psypanda/hashID/blob/master/prototypes.json
        
        
        ### NTLM Hashes (PWDUMP: user:rid:lm:nt:::)
        nt_hashes = None
        if re.search(r"[a-z0-9A-Z]{32}:[a-z0-9A-Z]{32}:::", self.hash_list[0]):
            print("PWDUMP format detected...")

            empty_lm = "aad3b435b51404eeaad3b435b51404ee"
            nt_hashes = []
            nt_seen = set()
            lm_hashes = []
            lm_seen = set()
            for line in self.hash_list:
                fields = line.split(':')
                if len(fields) < 4:
                    continue
                user, lm, ntlm = fields[0], fields[2].lower(), fields[3].lower()
                self.hashes[user] = ntlm
                if ntlm not in nt_seen:
                    nt_seen.add(ntlm)
                    nt_hashes.append(ntlm)
                if lm and lm != empty_lm and lm not in lm_seen:
                    lm_seen.add(lm)
                    lm_hashes.append(lm)

            # Split the LM hashes out for the opt-in LM->NT module.
            # The standard -m 1000 modules crack the NT hashes written below.
            with open(self.job_id + '.lm', "w") as handle:
                if lm_hashes:
                    handle.write("\n".join(lm_hashes) + "\n")

        
        ### NetNTLMv2 Hashes
        if re.search(r".*:.*:.*:[a-z0-9A-Z]{16}:[a-z0-9A-Z]{32}:[a-z0-9A-Z]*", self.hash_list[0]):
            print("NetNTLMv2 format detected...")

            # Map each username to its NTproofstr so results can be attributed
            # back to the user (record_cracked substring-matches it in the
            # outfile hash).
            for line in self.hash_list:
                user, a, domain, salt, netntlmv2_hash, blob = line.split(':')
                key = user
                self.hashes[key] = netntlmv2_hash.lower()

        # Write the hashes the attack will run against. For PWDUMP this is the
        # deduped NT hashes (so -m 1000 can parse them); otherwise the raw list.
        hashfile_lines = nt_hashes if nt_hashes is not None else self.hash_list
        with open(self.job_id + '.hash', "wb") as handle:
            for item in hashfile_lines:
                handle.write(bytes(item+"\n", "UTF-8"))
    
    def crack_passwords(self):
        '''
        Creates a CrackThread object and passes the id, file, and hash type to it.
        Returns the id so that results can be obtained later.
        '''
        message = "Request rejected."
        if self.check_hashtype():
            message = "Request accepted."

            self.process_hash_list()
            self.run_attack()
            self.harvest()

        return self.job_id, message

    def run_attack(self):
        '''
        Run the module's command list in a single CrackThread pass (leaving the
        job's temp files in place for harvest()). Multi-pass attacks (e.g.
        fingerprint) override this to loop, using CrackThread(cleanup=False) and
        cracked_count() between passes.
        '''
        self.run_commands(self.commands)

    def run_commands(self, commands):
        '''Run one CrackThread pass over `commands` without cleanup; returns the thread.'''
        thread = cracker.CrackThread(self.job_id, self.hash_type, self.hash_list, commands, cleanup=False)
        thread.start()
        thread.join()
        self.output = thread.output
        return thread

    def harvest(self):
        '''
        Record results from the authoritative cracked file: dump everything the
        potfile holds for these hashes to {job}.out via --show, parse it, update
        results and the remaining hash list, then remove the job's temp files.
        Reading hashcat's outfile (rather than scraping stdout) keeps results
        clean and works for every hash type, including WPA/IKE.
        '''
        thread = self.run_commands([self.hcat_base_cmd + " --show -o [outfile]"])
        self.record_cracked(thread.read_cracked())
        thread.remove_temp_files()

    def decode_hex(self, value):
        '''
        Unwrap hashcat's $HEX[...] plaintext so results and recycled
        dictionaries hold the real password. See core.util.decode_hex.
        '''
        return util.decode_hex(value)

    def expand_mask(self, mask):
        '''
        Turn a combinator mask into a hashcat -j/-k rule: each character becomes
        a "$c" append, so "2" -> "$2" and "ab" -> "$a$b". Single-character masks
        are unchanged in effect; multi-character masks now work correctly.
        '''
        return "$" + "$".join(mask)

    def record_cracked(self, cracked):
        '''
        Turn (hash, plaintext) pairs from the cracked file into results and drop
        the cracked hashes from the remaining list. Maps a hash back to its
        username via self.hashes when known (exact, or substring for formats like
        NetNTLMv2 where the stored value is part of the outfile hash); otherwise
        the hash itself is used as the key.
        '''
        hash_to_users = {}
        for user, value in self.hashes.items():
            hash_to_users.setdefault(value.lower(), []).append(user)

        for hashfield, plain in cracked:
            key = hashfield.lower()
            users = hash_to_users.get(key)
            if not users:
                for value, value_users in hash_to_users.items():
                    if value and value in key:
                        users = value_users
                        break

            for name in (users if users else [hashfield]):
                entry = (name, plain)
                if entry not in self.results:
                    self.results.append(entry)

            # drop the cracked hash from the remaining list
            for line in list(self.hash_list):
                if key in line.lower():
                    self.hash_list.remove(line)

        self.cracked_count = len(cracked)

    def show_results(self):
        print("\nResults of cracking session " + self.job_id +":")
        print("-"*80)
        for result in self.results:
            #if there is a third value we know its a string, not a list
            if len(result)>2:
                print(result)
            else:
                print(result[0] + ":" + result[1])
        print("-"*80)
        print("Cracked {0} of {1} hashes.".format(self.cracked_count, self.cracked_count + len(self.hash_list)))
        print('\n')