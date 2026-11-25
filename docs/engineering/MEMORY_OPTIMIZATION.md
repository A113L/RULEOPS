# RULEST wordlist RAM and Stage-0 multiprocessing

> [← Documentation index](../README.md)


**Scope:** `rulest.io_utils.load_wordlist()`, Stage 0 and RULEST GPU preparation.
This does not describe the separate Rule Ranker wordlist reader.

The RULEST wordlist path is RAM-resident. It does **not** use temporary
wordlist files, `mmap`, or disk-backed random access.

## Loading model

`rulest.io_utils.load_wordlist()` builds a `SharedWordList`:

- every valid normalized entry is stored in a named
  `multiprocessing.shared_memory` byte segment, preserving input order and
  repeated entries;
- a `uint64` offset segment provides O(1) access to each entry;
- invalid / empty lines are filtered during normalization, but duplicate
  entries are **not** removed;
- the original file is read in two sequential passes (one pass to size the
  offset and optional membership structures, one pass to populate shared RAM);
  phases after loading do not read the wordlist file again.

The loader reports the reserved shared-memory sizes for data, offsets, and
(optional) membership index. The data segment is reserved to the source file
size; the offset table is reserved to the number of valid source lines, so
files with many duplicate rows can have some unused offset capacity.

## Stage 0

For exact base-word membership, RULEST chooses between two representations.
On POSIX systems using `fork`, it prefers CPython's native `set[str]` when the
estimated memory requirement (including a 512 MiB reserve) fits available RAM.
Workers inherit that set copy-on-write, avoiding per-worker serialization and
the Python-level fingerprint loop used by the compact table. If memory headroom
is insufficient, the platform uses `spawn`, or the native-set path cannot be
built, RULEST uses a compact shared `FlatHashSet64` table. Large Windows
`spawn` jobs therefore attach to shared-memory descriptors rather than
receiving a serialized multi-million-entry Python set. Small pre-existing sets
may also be reused directly.

The TARGET list is not packed a second time for Stage 0: workers attach to the
loader's existing shared byte and offset segments. Pool tasks contain only
`(start, stop)` word-index pairs. The optional base membership index is
released after Stage 0 completes, before later GPU stages need the RAM.

The compact membership table stores 63-bit FNV fingerprints (the project's
existing exact-in-practice hash-index representation); as with any finite
fingerprint table, a hash collision is theoretically possible. The POSIX
native-set path uses Python's normal exact string equality checks. When a Bloom
filter is explicitly selected instead, false positives can add CPU work, but
rule-chain verification still checks actual transformations.

## GPU host buffers

`GPUEngine._flatten()` now uses a view over shared word bytes when the source
is a `SharedWordList` or a contiguous lazy slice. It allocates only the GPU
`int32` offsets and lengths arrays. For ordinary Python sequences, it fills
one exact-sized bytearray instead of creating a list of encoded words and a
second joined copy.

The OpenCL word-offset ABI remains `int32`, so a single flattened word byte
buffer is limited to less than 2 GiB, consistent with the existing GPU path.

## Stage 3 genetic search on large targets

Large target wordlists use bounded samples during GA generations. Generation 0
is sampled too, so the first progress update does not wait for a full-target
scan. Periodic full sweeps remain enabled only below the configured size
threshold; very large targets use bounded samples throughout evolution.

Stage 3 retains each chromosome's covered-word signature as a dense `uint8`
bitmap (one bit per sampled word), not a Python `set[int]`. The cross-generation
cache is capped by both entry count and an estimated 256 MiB of retained hit
maps. GPU scans report chain-word-pair progress while a generation is running.

After the GA generation budget ends, candidate hit counts are corrected against
the full target in bounded candidate batches. This exact-verification phase is
separate from the GA budget and has its own progress bar. It uses count-only
aggregation: no per-candidate full-word bitmap or Python hit set is allocated.
