#!/usr/bin/env python3

import logging
import os
import sys
import importlib

import modules      #import modules package so we can access list of modules with modules.__all__

from core.argparsers import CliParser

hash_list=[]
results = []

def main(args):
    global hash_list
    global results
    
    hash_file = open(args.file, "r")
    hash_type = args.type
    
    for line in hash_file.readlines():
        hash_list.append(line.rstrip())
    hash_file.close()
    
    index = 1
    selections = {}
    for m in modules.__all__:
        selections.update({index:m})
        index += 1
    
    if args.server:
        print("Running in server mode...")
        print('TODO\n')
        
    elif args.client:
        print("Running in client mode...")
        print('TODO\n')
    
    else:
        logging.debug("Running in standalone mode...\n")
        
        try:
            while 1:
        
                print("\nSelect from the following available modules:\n")
                for k,v in selections.items():
                    print("\t" + str(k) + " \t" + v)
                
                print("\n\t99\tShow Results\n")
                
                module = None # Ensure module is defined before try block
                
                try:
                    selection = int(input("Enter module selection: "))
                
                    if selection == 99:
                        show_results()
                    else:
                        try:
                            module_name = "modules." + selections.get(selection)
                            module = importlib.import_module(module_name)
                        except ModuleNotFoundError as e:
                            print(f"Module not found: {e}")
                        except ImportError as e:
                            print(f"Import error: {e}")
                        except Exception as e:
                            print(f"Unexpected error: {e}")
                    
                        if module:
                            attack = module.Attack(hash_list, hash_type)
                            
                            attack.crack_passwords()
                            attack.show_results()
                            hash_list=attack.hash_list
                            
                            for result in attack.results:
                                if not result in results:
                                    results.append(result)
                            
                            logging.debug(hash_list)
                            logging.debug(results)
                            
                except KeyboardInterrupt:
                    sys.exit()
            
                except KeyError:
                    print("Invalid key pressed...")
                
        except KeyboardInterrupt:
            sys.exit()
            

def show_results():
    global hash_list
    global results
    
    '''
    TODO / note:
        counts are wrong for WPA hashes because there isnt a good way to remove the hashfile
        from the hash list so it gets counted in count_fail even if successful. Also, what if more than
        1 hash in the file???
    '''
    count_success = len(results)
    count_fail = len(hash_list)
    count_all = count_success + count_fail
    
    print("\nStatistics:")
    print("-"*80)
    print("Total hashes analyzed: "+ str(count_all))
    print("Total hashes cracked: "+ str(count_success))
    print("Total hashes remaining: "+ str(count_fail))
    print("-"*80)
    
    if count_success:
        
        print("\nResults:")
        print("-"*80)
        for result in results:
            #if there is a third value we know its a string, not a list
            if len(result)>2:
                print(result)
            else:
                print(result[0] + ":" + result[1])
        print("-"*80)

    print("\n")

if __name__ == '__main__':
    program_name = 'crackpipe'
    program_descr = 'Hashcat password attack automation script'
    parser = CliParser(prog=program_name, description=program_descr)
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--client", help="client mode (TODO - not implemented)",
                    action="store_true")
    group.add_argument("--server", help="server mode (TODO - not implemented)",
                    action="store_true")
    
    parser.add_argument("file", nargs="?", action="store", default="hashes.txt",
                            help="specify a hash file (default: hashes.txt)"
    )
    parser.add_argument("type", nargs="?", action="store", default="1000",
                        help="specify the hash type (default: 1000 - NT)"
    )
    parser.add_argument('-d','--debug',
                        help='Print lots of debugging statements',
                        action="store_const",dest="loglevel",const=logging.DEBUG,
                        default=logging.WARNING
    )
    parser.add_argument('-v','--verbose',
                        help='Be verbose',
                        action="store_const",dest="loglevel",const=logging.INFO         
    )
    
    args = parser.parse_args()
    
    #TODO - customize logging to be prettier (see weevely!)
    logging.basicConfig(level=args.loglevel)

    try:
        main(args)
    except (KeyboardInterrupt, EOFError):
        logging.error('Exiting.')
