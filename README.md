crackpipe
===========

Hashcat password attack automation script

Crackpipe automates chaining of multiple attacks against hashes using predefined
modules as well as dictionaries and other options specified in the config file.
Many of the attack variants were borrowed from the excellent
[hate_crack](https://github.com/trustedsec/hate_crack) tool from TrustedSec.
Basically, we wanted a tool that was more modular to provide for easier expansion
and future customization.

Hash files passed to Crackpipe are parsed and processed through modules specified
after runtime. After each module is executed, the results are parsed and aggregated
into a results variable. As additional modules are executed, only the uncracked
hashes are passed to Hashcat which reduces runtime if you decide to use temporary
potfiles for each session (specified in config file).

# Dependencies
* Hashcat
    - Installed by default in Kali Linux
    - Precompiled binaries: https://hashcat.net/hashcat/
    - Source: https://github.com/hashcat
    - Wiki with tutorials and instructions: https://hashcat.net/wiki/
* Python 2.7
    - Uses standard Python libraries and should not require additional packages

# Installation

Just clone from repo and set up your config file:

    git clone https://github.com/isaudits/crackpipe
    cd config
    cp config.example config.cfg
    
Edit config file to point to your wordlists and hashcat binaries; Note that bin
name may be different for Linux / OSX variants

    nano config.cfg
    
# Usage

Options and basic usage

    usage: crackpipe [-h] [--client | --server] [-d] [-v] [file] [type]
    
    Hashcat password attack automation script
    
    positional arguments:
      file           specify a hash file (default: hashes.txt)
      type           specify the hash type (default: 1000 - NT)
    
    optional arguments:
      -h, --help     show this help message and exit
      --client       client mode (TODO - not implemented)
      --server       server mode (TODO - not implemented)
      -d, --debug    Print lots of debugging statements
      -v, --verbose  Be verbose

Hash type parameter corresponds with Hashcat hash modes. For a list of accepted
codes see Hashcat help. Note that proper output parsing of all hash types has not
been implemented so some hash types may not be parsed into results properly.
Additional handling of hash types will be added as they are encountered - feel free
to send us a PR!

Hash types that have been confirmed as working include:
* NTLM - 1000 (default)
* NetNTLMv1 - 5500
* NetNTLMv2 - 5600
* WPA-EAPOL-PBKDF2 - 2500

Note that Hashcat requires conversion of standard .cap files to .hccapx format for
processing: https://hashcat.net/wiki/doku.php?id=hashcat_utils

# Modules
Modules are defined in the crackpipe/modules directory. All modules inherit the
base.py module which provides general methods available to all modules. Attack modules
generally will subclass the build_commands method which defines the hashcat commands
which will be the basis for the attack.

Please feel free to submit additional modules as pull requests.
--------------------------------------------------------------------------------

Copyright 2018

Matthew C. Jones, CPA, CISA, OSCP, CCFE

IS Audits & Consulting, LLC - <http://www.isaudits.com/>

TJS Deemer Dana LLP - <http://www.tjsdd.com/>

--------------------------------------------------------------------------------

Except as otherwise specified:

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
