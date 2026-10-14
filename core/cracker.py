import subprocess
import shlex
import threading
import os
import sys
import logging

from core import util

class CrackThread(threading.Thread):
    '''
    Takes an id, hash type, a hash list, and a list of commands. The hash
    list should be in username:hash format except for special cases.
    The hash list is processed to extract usernames. After each command is run
    the results are processed, added to the results array, and the cracked hashes
    are removed from the hash file.

    Commands may contain these placeholders, substituted per command at run time:
        [hashfile] - the hashes being attacked
        [potfile]  - the session potfile
        [outfile]  - where cracked hash:plain is written (-o target); feedback attacks append here
        [working]  - a dictionary of cracked plaintext, rebuilt from [outfile] just before the
                     command runs (deduped, $HEX[...] decoded); lets a later stage recycle earlier cracks
    '''

    def __init__(self, job_id, hash_type, hash_list, commands, cleanup=True):
        threading.Thread.__init__(self)
        self.job_id = job_id
        self.hash_type = hash_type
        self.hash_list = hash_list
        self.commands = commands
        self.hash_file = job_id + '.hash'
        self.pot_file = job_id + '.pot'
        self.out_file = job_id + '.out'
        self.working_file = job_id + '.working'
        self.output = ''
        self.complete = False
        # Multi-pass attacks run several CrackThreads over the same job and keep
        # the temp files (.out/.hash/...) between passes; they pass cleanup=False
        # on all but the final pass.
        self.cleanup = cleanup
        
        logging.info("Processing request " + job_id + " with hash type " + hash_type)
        logging.debug("CrackThread is initialized - now we have to process hash list")


    def cracked_count(self):
        '''
        Number of cracked hashes recorded so far (non-blank lines in {job}.out).
        Used by multi-pass attacks to tell when a loop stops making progress.
        '''
        try:
            with open(os.path.join(os.getcwd(), self.out_file), "r", errors="replace") as handle:
                return sum(1 for line in handle if line.strip())
        except FileNotFoundError:
            return 0

    def build_working_file(self):
        '''
        (Re)build the recycle dictionary ({job}.working) from the cracked output
        file ({job}.out). Takes each cracked plaintext (the field after the final
        ':'), decodes any $HEX[...] wrapper, dedupes preserving order, and writes
        one candidate per line. Missing/empty .out yields an empty dictionary.
        '''
        out_path = os.path.join(os.getcwd(), self.out_file)
        working_path = os.path.join(os.getcwd(), self.working_file)

        plains = []
        seen = set()
        try:
            with open(out_path, "r", errors="replace") as handle:
                for line in handle:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    plain = util.decode_hex(line.rsplit(":", 1)[-1])
                    if plain and plain not in seen:
                        seen.add(plain)
                        plains.append(plain)
        except FileNotFoundError:
            pass

        with open(working_path, "w") as handle:
            if plains:
                handle.write("\n".join(plains) + "\n")

    def run(self):
        '''
        Overwrites default run method for Threading.Thread class.
        
        For each command, process the hash_list, modify the command to
        include the correct file name on disk, and run the command. Once the
        command is run, we process the output, which include updating the hash
        list to remove found hashes.
        '''
        
        for command in self.commands:
            command = command.replace('[hashfile]', os.path.join(os.getcwd(),self.hash_file))
            command = command.replace('[potfile]', os.path.join(os.getcwd(),self.pot_file))
            command = command.replace('[outfile]', os.path.join(os.getcwd(),self.out_file))

            # Rebuild the recycle dictionary from everything cracked so far,
            # right before any command that consumes it.
            if '[working]' in command:
                self.build_working_file()
                command = command.replace('[working]', os.path.join(os.getcwd(),self.working_file))

            print("\n"+command+"\n")
            
            output = ""
            
            try:
                    
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                
                while process.poll() is None:
                    nextline = process.stdout.readline()
                    output += nextline.decode('UTF-8')
                    sys.stdout.buffer.write(nextline)
                    sys.stdout.flush()
                    
                self.output = output
                
            #except KeyboardInterrupt:
            #    logging.error("Command killed via keyboard interrupt")
        
            except subprocess.CalledProcessError as e:
                logging.error(e.output)
        
            #except Exception as exception:
            #    logging.error(exception)
                
                        
            
        self.complete = True

        if self.cleanup:
            print("\n\nCracking session " + self.job_id + " is complete...")

            # remove temp files which start with the current job ID
            files = os.listdir(".")
            for file in files:
                if file.startswith(self.job_id+"."):
                    os.remove(file)
        

        
        
