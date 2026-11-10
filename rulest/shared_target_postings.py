"""Compact target-keyed inverted postings for Rulestripper.

Only BASE-derived keys that can occur in the current TARGET wordlist are
stored.  Posting values are BASE word indexes, not Python strings.  All large
arrays live in SharedMemory so multiprocessing with Windows ``spawn`` passes
only small descriptors to workers.
"""
from array import array
from multiprocessing.shared_memory import SharedMemory

from .tokenstrip_hashset import _fnv1a_63

_INDEX_KINDS = ("purge", "substr", "omit", "prefix")


def _power_of_two(value):
    result = 16
    while result < max(16, int(value)):
        result <<= 1
    return result


def _word_keys(word):
    """Yield unique (index-kind, key) pairs matching the former Python indexes."""
    wlen = len(word)

    purge = {word.replace(char, "") for char in set(word)}
    for key in purge:
        if key:
            yield "purge", key

    substrings = set()
    for start in range(min(wlen, 10)):
        for end in range(start + 1, min(wlen + 1, 11)):
            substrings.add(word[start:end])
    for key in substrings:
        yield "substr", key

    omitted = set()
    for start in range(min(wlen, 10)):
        for omit_n in range(1, min(10, wlen - start) + 1):
            if start + omit_n > 10:
                break
            result = word[:start] + word[start + omit_n:]
            if result:
                omitted.add(result)
    for key in omitted:
        yield "omit", key

    prefixes = {word[:end] for end in range(1, min(wlen, 10))}
    for key in prefixes:
        yield "prefix", key


class SharedTargetLookup:
    """Open-addressed TARGET string -> first word index lookup."""

    __slots__ = ("target_buffer", "capacity", "mask", "hashes_shm", "ids_shm",
                 "hashes", "ids", "_owner", "_closed")

    def __init__(self, target_buffer):
        self.target_buffer = target_buffer
        self.capacity = _power_of_two(int(len(target_buffer) / 0.65) + 1)
        self.mask = self.capacity - 1
        self._owner = True
        self._closed = False
        self.hashes_shm = SharedMemory(create=True, size=self.capacity * 8)
        self.ids_shm = None
        self.hashes = self.hashes_shm.buf.cast("Q")
        try:
            self.ids_shm = SharedMemory(create=True, size=self.capacity * 8)
            self.ids = self.ids_shm.buf.cast("Q")
            for index, word in enumerate(target_buffer):
                value = _fnv1a_63(word) + 1
                slot = value & self.mask
                while True:
                    current = self.hashes[slot]
                    if current == 0:
                        self.hashes[slot] = value
                        self.ids[slot] = index + 1
                        break
                    if current == value:
                        existing = self.ids[slot] - 1
                        if target_buffer[existing] == word:
                            break
                    slot = (slot + 1) & self.mask
        except Exception:
            self.close()
            raise

    @classmethod
    def attach(cls, descriptor, target_buffer):
        name_hashes, name_ids, capacity = descriptor
        obj = cls.__new__(cls)
        obj.target_buffer = target_buffer
        obj.capacity = int(capacity)
        obj.mask = obj.capacity - 1
        obj._owner = False
        obj._closed = False
        obj.hashes_shm = SharedMemory(name=name_hashes, create=False)
        obj.ids_shm = None
        try:
            obj.ids_shm = SharedMemory(name=name_ids, create=False)
            obj.hashes = obj.hashes_shm.buf.cast("Q")
            obj.ids = obj.ids_shm.buf.cast("Q")
        except Exception:
            obj.close()
            raise
        return obj

    def descriptor(self):
        return (self.hashes_shm.name, self.ids_shm.name, self.capacity)

    def find(self, word):
        value = _fnv1a_63(word) + 1
        slot = value & self.mask
        while True:
            current = self.hashes[slot]
            if current == 0:
                return -1
            if current == value:
                index = self.ids[slot] - 1
                if self.target_buffer[index] == word:
                    return int(index)
            slot = (slot + 1) & self.mask

    def close(self):
        if getattr(self, "_closed", True):
            return
        self._closed = True
        for attr in ("hashes", "ids"):
            view = getattr(self, attr, None)
            setattr(self, attr, None)
            if view is not None:
                try:
                    view.release()
                except Exception:
                    pass
        for shm in (getattr(self, "ids_shm", None), getattr(self, "hashes_shm", None)):
            if shm is None:
                continue
            try:
                shm.close()
            finally:
                if self._owner:
                    try:
                        shm.unlink()
                    except FileNotFoundError:
                        pass
        self.target_buffer = None


class _BaseWordPostingView:
    __slots__ = ("_base", "_values", "_start", "_stop")

    def __init__(self, base_buffer, values, start, stop):
        self._base = base_buffer
        self._values = values
        self._start = int(start)
        self._stop = int(stop)

    def __len__(self):
        return self._stop - self._start

    def __iter__(self):
        for pos in range(self._start, self._stop):
            yield self._base[int(self._values[pos])]


class SharedTargetPostings:
    """Four shared-memory postings indexes keyed only by TARGET words."""

    __slots__ = ("base_buffer", "target_lookup", "word_count", "_owner", "_closed",
                 "_resources", "_offsets", "_values", "_value_format")

    def __init__(self, base_buffer, target_lookup, enabled=True):
        self.base_buffer = base_buffer
        self.target_lookup = target_lookup
        self.word_count = len(target_lookup.target_buffer)
        self._owner = True
        self._closed = False
        self._resources = {}
        self._offsets = {}
        self._values = {}
        self._value_format = "I" if len(base_buffer) <= 0xFFFFFFFF else "Q"
        item_size = 4 if self._value_format == "I" else 8

        counts = {kind: array("Q", [0]) * self.word_count for kind in _INDEX_KINDS}
        if enabled:
            for word in base_buffer:
                for kind, key in _word_keys(word):
                    target_id = target_lookup.find(key)
                    if target_id >= 0:
                        counts[kind][target_id] += 1

        offsets_by_kind = {}
        totals = {}
        for kind in _INDEX_KINDS:
            offsets = array("Q", [0])
            total = 0
            for count in counts[kind]:
                total += count
                offsets.append(total)
            offsets_by_kind[kind] = offsets
            totals[kind] = total

        try:
            for kind in _INDEX_KINDS:
                offsets_shm = SharedMemory(create=True, size=max(8, len(offsets_by_kind[kind]) * 8))
                offsets_view = offsets_shm.buf.cast("Q")
                offsets_view[:len(offsets_by_kind[kind])] = offsets_by_kind[kind]
                values_shm = SharedMemory(create=True, size=max(item_size, totals[kind] * item_size))
                values_view = values_shm.buf.cast(self._value_format)
                self._resources[kind] = (offsets_shm, values_shm)
                self._offsets[kind] = offsets_view
                self._values[kind] = values_view

            cursors = {kind: array("Q", offsets_by_kind[kind][:-1]) for kind in _INDEX_KINDS}
            if enabled:
                for base_id, word in enumerate(base_buffer):
                    for kind, key in _word_keys(word):
                        target_id = target_lookup.find(key)
                        if target_id < 0:
                            continue
                        position = cursors[kind][target_id]
                        self._values[kind][position] = base_id
                        cursors[kind][target_id] = position + 1
        except Exception:
            self.close()
            raise

    @classmethod
    def attach(cls, descriptor, base_buffer, target_lookup):
        obj = cls.__new__(cls)
        obj.base_buffer = base_buffer
        obj.target_lookup = target_lookup
        obj.word_count = int(descriptor[0])
        obj._owner = False
        obj._closed = False
        obj._resources = {}
        obj._offsets = {}
        obj._values = {}
        obj._value_format = descriptor[1]
        try:
            for kind, offset_name, value_name in descriptor[2:]:
                offsets_shm = SharedMemory(name=offset_name, create=False)
                values_shm = SharedMemory(name=value_name, create=False)
                obj._resources[kind] = (offsets_shm, values_shm)
                obj._offsets[kind] = offsets_shm.buf.cast("Q")
                obj._values[kind] = values_shm.buf.cast(obj._value_format)
        except Exception:
            obj.close()
            raise
        return obj

    def descriptor(self):
        return (self.word_count, self._value_format) + tuple(
            (kind, self._resources[kind][0].name, self._resources[kind][1].name)
            for kind in _INDEX_KINDS
        )

    def get(self, kind, key, default=()):
        if kind not in self._offsets:
            return default
        target_id = self.target_lookup.find(key)
        if target_id < 0:
            return default
        offsets = self._offsets[kind]
        start = int(offsets[target_id])
        stop = int(offsets[target_id + 1])
        if stop <= start:
            return default
        return _BaseWordPostingView(self.base_buffer, self._values[kind], start, stop)

    def close(self):
        if getattr(self, "_closed", True):
            return
        self._closed = True
        for views in (self._offsets, self._values):
            for view in views.values():
                try:
                    view.release()
                except Exception:
                    pass
            views.clear()
        for resources in getattr(self, "_resources", {}).values():
            for shm in resources:
                try:
                    shm.close()
                finally:
                    if self._owner:
                        try:
                            shm.unlink()
                        except FileNotFoundError:
                            pass
        self._resources.clear()
        # Do not retain references to BASE/TARGET owners after the views are released.
        self.base_buffer = None
        self.target_lookup = None
