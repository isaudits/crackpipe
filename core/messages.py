#!/usr/bin/env python

version = '0.1'

class generic:
    file_s_not_found = "File '%s' not found"
    error_creating_file_s_s = "Error creating file '%s': %s"
    error_loading_file_s_s = 'Error loading file \'%s\': %s'
    error_file_s_already_exists = 'Error file \'%s\' already exists'
    error_parsing_command_s = 'Error parsing command: %s'
    crackpipe_s_error_s_usage = '''
[+] crackpipe %s
[!] Error: %s
[+] Usage: need to put usage here!!!
'''

class config:
    config_section_s_missing = 'Could not find config file section %s'