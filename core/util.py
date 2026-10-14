import re

_HEX_WRAPPER = re.compile(r'\$HEX\[([0-9a-fA-F]*)\]')

def decode_hex(value):
    '''
    hashcat wraps a plaintext in $HEX[...] when it contains bytes it can't
    print (non-ASCII, or a literal colon). Decode it back to text; return the
    input unchanged if it isn't a $HEX[...] wrapper or the hex is invalid.
    '''
    match = _HEX_WRAPPER.fullmatch(value or '')
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
