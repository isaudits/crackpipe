#!/usr/bin/env python
'''
Credit: Based on argparsers.py code from Weevely (https://github.com/epinna/weevely3/)

'''

from core import messages
import argparse
import sys

class CliParser(argparse.ArgumentParser):

    """
    Override `error` method of `argparse.ArgumentParser`
    in order to print the complete help on error.
    """

    def error(self, message):
        sys.stderr.write(messages.generic.crackpipe_s_error_s_usage % (messages.version, message))
        self.print_help
        sys.exit(2)
