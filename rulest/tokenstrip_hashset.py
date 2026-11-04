"""
Compact exact-membership structure for Stage 0 (--token-strip).

Replaces a Python set[str] over the base wordlist with a flat open-addressing
hash table of 64-bit FNV-1a hashes (masked to 63 bits). Membership is exact
in practice (64-bit collisions are negligible, and every hit is re-verified
by py_apply_chain anyway), while RAM drops from ~60-100 B/word to ~9-10 B/word.

Only __contains__ / __len__ are supported: Stage 0 never reads a word back
out of the base set, it only asks "is this stem in the base?".
"""
from array import array

_MASK63 = 0x7FFFFFFFFFFFFFFF
_FNV_OFFSET = 1469598103934665603
_FNV_PRIME = 1099511628211


def _fnv1a_63(s):
    h = _FNV_OFFSET
    for ch in s:
        h ^= ord(ch)
        h = (h * _FNV_PRIME) & _MASK63
    return h


class FlatHashSet64:
    __slots__ = ("table", "mask", "size")

    def __init__(self, words, load=0.7):
        n = len(words)
        cap = 16
        while cap < n / load:
            cap <<= 1
        self.table = array('Q', bytes(8 * cap))  # zero-filled slots
        self.mask = cap - 1
        self.size = 0
        insert = self._insert
        for w in words:
            insert(_fnv1a_63(w))

    def _insert(self, h):
        slot = h & self.mask
        t = self.table
        want = h + 1  # 0 marks an empty slot; h <= 2^63-1 so want > 0
        while True:
            v = t[slot]
            if v == 0:
                t[slot] = want
                self.size += 1
                return
            if v == want:
                return  # duplicate
            slot = (slot + 1) & self.mask

    def __contains__(self, s):
        h = _FNV_OFFSET
        for ch in s:
            h ^= ord(ch)
            h = (h * _FNV_PRIME) & _MASK63
        slot = h & self.mask
        t = self.table
        want = h + 1
        while True:
            v = t[slot]
            if v == 0:
                return False
            if v == want:
                return True
            slot = (slot + 1) & self.mask

    def __len__(self):
        return self.size
