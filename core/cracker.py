import subprocess
import shlex
import threading
import os
import sys
import logging

class CrackThread(threading.Thread):
    '''
    Takes an id, hash type, a hash list, and a list of commands. The hash
    list should be in username:hash format except for special cases. 
    The hash list is processed to extract usernames. After each command is run
    the results are processed, added to the results array, and the cracked hashes 
    are removed from the hash file.
    '''
    
    def __init__(self, job_id, hash_type, hash_list, commands):
        threading.Thread.__init__(self)
        self.job_id = job_id
        self.hash_type = hash_type
        self.hash_list = hash_list
        self.commands = commands
        self.hash_file = job_id + '.hash'
        self.pot_file = job_id + '.pot'
        self.output = ''
        self.complete = False
        
        logging.info("Processing request " + job_id + " with hash type " + hash_type)
        logging.debug("CrackThread is initialized - now we have to process hash list")


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
        print("\n\nCracking session " + self.job_id + " is complete...")
        
        # remove temp files which start with the current job ID
        files = os.listdir(".")
        for file in files:
            if file.startswith(self.job_id+"."):
                os.remove(file)
        

        
        
