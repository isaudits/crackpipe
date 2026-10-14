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
        self.results_regex = '([0-9a-f]{16,}):(.*)' #standard hashcat output of hash:password
        self.results = []
        self.hashcat_tuning = ''
        self.hashcat_path = ''
        self.rules_path = ''
        self.masks_path = ''
        
        
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

        
        if self.config.getboolean("hashcat", "temporary_potfile", fallback=False):
            self.hcat_base_cmd = "{hcat_bin} -m {hash_type} --potfile-path [potfile] {tuning} [hashfile]".format(
                                    hcat_bin=self.hashcat_binary,
                                    hash_type=self.hash_type,
                                    tuning=self.hashcat_tuning,
                                    )
        else:
            self.hcat_base_cmd = "{hcat_bin} -m {hash_type} {tuning} [hashfile]".format(
                                    hcat_bin=self.hashcat_binary,
                                    hash_type=self.hash_type,
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
            
            # hashcat returns entire input hash:password; adjust results regex accordingly
            self.results_regex = '.*:.*:.*:[a-z0-9A-Z]{16}:([a-z0-9A-Z]{32}):[a-z0-9A-Z]*:(.*)'
            
            for line in self.hash_list:
                user, a, domain, salt, netntlmv2_hash, blob = line.split(':')
                key = user
                self.hashes[key] = netntlmv2_hash.lower()
        
        ### WPA2 hashes - set results regex to none; we will pass all results straight through as plaintext
        if self.hash_type == '2500':
            # example output from WPA2
            # a895f7d62ccc3e892fa9e9f9146232c1:aef50f22801c:987bdcf9f950:8381533406003807685881523:hashcat!
            # ?????:mac-ap:mac-client:essid:password
            
            self.results_regex = None
            
        ### IKE-PSK hashes - set results regex to none; we will pass all results straight through as plaintext
        if self.hash_type == '5300' or self.hash_type == '5400':
            #example output:
            # g_xr_hex:g_xi_hex:cky_r_hex:cky_i_hex:sai_b_hex:idir_b_hex:ni_b_hex:nr_b_hex:hash:Password
            
            self.results_regex = None
        
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
        if self.check_hashtype():
            message = "Request accepted."
            
            self.process_hash_list()

            self.crack_thread = cracker.CrackThread(self.job_id, self.hash_type, self.hash_list, self.commands)
            self.crack_thread.start()
            
            # Join the thread so it does not terminate until this function does
            # otherwise, we can't get the output
            self.crack_thread.join()
            self.output = self.crack_thread.output
            
            self.process_output()

        return self.job_id, message
    
    def process_output(self):
        
        if self.results_regex:
            for r in re.finditer(self.results_regex, self.output, re.MULTILINE):
                #self.results.append((r.group(1), r.group(2)))
                self.process_hash(r.group(1), "", r.group(2))
        else:
            # no regex - process as plaintext
            self.process_hash("","","",self.output)
            
    def decode_hex(self, value):
        '''
        hashcat wraps a plaintext in $HEX[...] when it contains bytes it can't
        print (non-ASCII, or a literal colon). Decode it back to text so results
        and recycled dictionaries hold the real password, not the wrapper.
        '''
        match = re.fullmatch(r'\$HEX\[([0-9a-fA-F]*)\]', value or '')
        if not match:
            return value
        try:
            raw = bytes.fromhex(match.group(1))
        except ValueError:
            return value
        try:
            return raw.decode('utf-8')
        except UnicodeDecodeError:
            return raw.decode('latin-1')

    def process_hash(self, hash, user, password, plaintext=""):
        '''plaintext variable is for simple output where hashes are not stored in
        the hash table (such as wifi hashes); if this is the case, just append
        output in plaintext field to the results table and spit it out!
        '''

        password = self.decode_hex(password)
        plaintext = self.decode_hex(plaintext)

        if plaintext:
            if not plaintext in self.results:
                self.results.append(plaintext)
        
        key = user
        for k,v in self.hashes.items():
            if v == hash or k == key:
                hash = v
                self.results.append((k, password))
                #del self.hashes[k]

            #remove found hashes from hash list
            for line in list(self.hash_list):
                if re.search(hash, line):
                    self.hash_list.remove(line)
    
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
        print('\n')