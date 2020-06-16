#!/usr/bin/env python

"""
The base module defines the `Attack` class.
This class has to be inherited to create a new cracking module.

Default methods can be overridden in the inheriting module
"""

import ConfigParser
import logging
import time
import re
import os
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
        self.hash_type = hash_type
        self.commands = []
        self.processes = {}
        self.hashes = {}
        self.output = ''
        self.results_regex = '([0-9a-f]{16,}):(.*)' #standard hashcat output of hash:password
        self.results = []
        
        
        self.read_config()
        
        if self.config.getboolean("hashcat", "temporary_potfile"):
            self.hcat_base_cmd = "{hcat_bin} -m {hash_type} --potfile-path [potfile] {tuning} [hashfile]".format(
                                    hcat_bin=os.path.join(self.config.get("hashcat", "path"), self.config.get("hashcat", "bin")),
                                    hash_type=self.hash_type,
                                    tuning=self.config.get("hashcat", "tuning"),
                                    )
        else:
            self.hcat_base_cmd = "{hcat_bin} -m {hash_type} {tuning} [hashfile]".format(
                                    hcat_bin=os.path.join(self.config.get("hashcat", "path"), self.config.get("hashcat", "bin")),
                                    hash_type=self.hash_type,
                                    tuning=self.config.get("hashcat", "tuning"),
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
        self.config = ConfigParser.SafeConfigParser()
        self.config.read(self.config_file)
    
    def check_hashtype(self):
        '''
        Checks hashtype against accepted hash types from config file; returns
        True if it is of an accepted type
        
        TODO - Need to implement!
        '''
        return True
    
    def process_hash_list(self):
        ### Note - Regex for various hash types: https://github.com/psypanda/hashID/blob/master/prototypes.json
        
        
        ### NTLM Hashes
        if re.search(r"[a-z0-9A-Z]{32}:[a-z0-9A-Z]{32}:::", self.hash_list[0]):
            print("PWDUMP format detected...")
            
            for line in self.hash_list:
                user, uid, lm, ntlm, comment, homedir, endofline = line.split(':')
                key = user
                self.hashes[key] = ntlm.lower()
                #if self.hash_type.lower()[-2:] == 'nt':
                #    self.hashes[key] = ntlm.lower()
                #else:
                #    self.hashes[key] = lm.lower()
        
        
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
        
        #write hash data passed to file
        with open(self.job_id + '.hash', "wb") as handle:
            #handle.write(self.hash_list)
            for item in self.hash_list:
                handle.write(item+"\n")
    
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
            
    def process_hash(self, hash, user, password, plaintext=""):
        '''plaintext variable is for simple output where hashes are not stored in
        the hash table (such as wifi hashes); if this is the case, just append
        output in plaintext field to the results table and spit it out!
        '''
        
        if plaintext:
            if not plaintext in self.results:
                self.results.append(plaintext)
        
        key = user
        for k,v in self.hashes.items():
            if v == hash or k == key:
                hash = v
                self.results.append((k, password))
                del self.hashes[k]

            #remove found hashes from hash list
            for line in self.hash_list:
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