# PACK (Password Analysis and Cracking Kit)

`statsgen.py` and `maskgen.py` vendored here are used by crackpipe's Top Mask attack to analyze cracked passwords and generate time-bounded hashcat masks.

- Original project: **PACK** by Peter Kacherginsky (iphelix) — <https://github.com/iphelix/pack>
- These Python 3 builds were taken from TrustedSec's **hate_crack** — <https://github.com/trustedsec/hate_crack>
- Licensed under the BSD license, Copyright (c) 2013 Peter Kacherginsky — see [LICENSE](LICENSE).

Only `statsgen.py` and `maskgen.py` are included (the two tools Top Mask uses). Both are standalone and require no other PACK modules. They are not part of crackpipe and retain their original license.
