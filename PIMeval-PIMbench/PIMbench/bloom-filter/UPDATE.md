# Update Notes

## Overview

Two major additions built on top of the existing PIMeval Bloom filter benchmark:

1. **Streaming APT detection layer** — wires the three Bloom filter variants into a real detection use case driven by a process event log
2. **Cuckoo filter** — parallel implementation of the same detection interface using a cuckoo filter instead of a Bloom filter, with CPU and PIM variants

---

## 1. APT Detection Integration

### What was added

`detect.cpp` builds a streaming APT (Advanced Persistent Threat) detection system on top of the existing `BloomFilter` interface. It reads a process event log and propagates a reachable-PID frontier outward from one or more seed PIDs, firing alerts when a target-type node is reached via a suspicious parent.

### Detection algorithm

```
startup:   batchInsert(seed_pids)

per event (pid, ppid, is_target):
    result = batchQuery({ppid})
    if result[0]:
        batchInsert({pid})
        if is_target:
            emit ALERT pid ppid
```

The filter accumulates all PIDs reachable from the seed via parent-child spawn edges. An alert fires when such a reachable PID is also flagged as a target node type (e.g. a shell process). False positives from the filter may produce spurious alerts — this is expected and acceptable.

### Input log format

`process_stream.log` — CSV with three columns:

| Column | Type | Meaning |
|---|---|---|
| `pid` | uint64 | process ID of the spawned child |
| `ppid` | uint64 | parent process ID that spawned it |
| `is_target` | 0 or 1 | whether this process is a node type of interest |

Example log (15 events, 5 attack path + 10 benign noise):

```
100,1,1    ← root process spawned by init, attack path
101,100,1  ← shell spawned by root
102,101,1  ← curl spawned by shell
103,102,1  ← payload.sh spawned by curl
104,103,1  ← exfil_data spawned by payload.sh
105,100,0  ← benign: ls spawned by root (noise)
106,1,0    ← benign: chrome spawned by init
...
```

### Detection output (all variants, seed=1)

```
ALERT 100 1
ALERT 101 100
ALERT 102 101
ALERT 103 102
ALERT 104 103

events processed: 15
alerts fired:     5
pids inserted:    16
```

All five attack-path nodes correctly detected. All ten benign noise events suppressed.

### External log output

Pass `--log <filepath>` to mirror all output (alerts + summary) to a file:

```bash
./detect.out --log alerts.txt process_stream.log cpu 1024 3 1
```

### Supported variants

| Variant | Description |
|---|---|
| `cpu` | Standard bit-array Bloom filter |
| `cpu-counting` | Counting Bloom filter, 4-bit saturating counters, supports deletion |
| `pim-v2` | Bloom filter — CPU hashing, PIM bitwise OR |
| `pim-v3` | Bloom filter — PIM hashing and bitwise OR |
| `cuckoo-cpu` | Cuckoo filter — CPU only |
| `cuckoo-pim-v2` | Cuckoo filter — CPU hashing, PIM bucket table storage |
| `cuckoo-pim-v3` | Cuckoo filter — PIM hashing, PIM bucket table storage |

---

## 2. Cuckoo Filter

### Design

| Property | Value |
|---|---|
| Bucket slots | `uint32_t`, 0 = empty |
| Fingerprint | 16-bit, derived via `(key * CK_A_FP) >> 48`, forced non-zero (`\| 1`) |
| Primary index | `(key * CK_A_PRIMARY) >> shift` |
| Alternate index | `(i1 XOR (fp * CK_A_ALT) >> shift) & mask` — symmetric |
| Max kicks | 500 before dropping insert with stderr warning |
| Deletion | supported on all three variants via `batchRemove` |

The alternate index formula is symmetric: `alt(alt(i, fp), fp) == i`. This is required for correct deletion and relocation during cuckoo kicks.

Hash constants are from the golden-ratio PHI64 family, distinct from the Bloom filter constants:

```cpp
CK_A_PRIMARY = 11400714819323198485ULL   // phi64
CK_A_FP      = 14181476777654086739ULL   // 5/4 * phi64 | 1
CK_A_ALT     = 17280765499989070263ULL   // 3/2 * phi64 | 1
```

### PIM variants

**cuckoo-pim-v2**
- Bucket table allocated in PIM as `PIM_UINT32`
- All cuckoo logic (hash, kick loop) runs on a host mirror (`hostBuckets_`)
- `batchInsert`: pull table from PIM → mutate host mirror → push back
- `batchQuery`: pull table from PIM → check on host
- PIM is used as near-memory storage; data transfer is one bulk copy per batch op

**cuckoo-pim-v3**
- Extends V2 with PIM-side hash computation for `i1`, `fp`, and `altHash`
- PIM operations per batch:
  - `pimMulScalar(keysObj, i1Obj, CK_A_PRIMARY)` + `pimShiftBitsRight` → primary indices
  - `pimMulScalar(keysObj, fpObj, CK_A_FP)` + `pimShiftBitsRight(48)` → fingerprints
  - `pimMulScalar(fpObj, altHashObj, CK_A_ALT)` + `pimShiftBitsRight` → alt hashes
  - XOR to form `i2` done on CPU after download (trivial integer op)
- Kick loop and table mutations still run on host mirror
- 5 PIM objects: `bucketsObj_`, `keysObj_`, `i1Obj_`, `fpObj_`, `altHashObj_`

### Cuckoo vs Bloom: key differences

| Property | Bloom | Cuckoo |
|---|---|---|
| False negatives | never | never (unless insert dropped at saturation) |
| False positive rate | tunable via k | lower at equivalent space |
| Deletion | counting variant only | all variants |
| Insert failure | impossible | possible at high load (>~90%) |
| Lookup cost | k hash probes | exactly 2 bucket checks |
| PIM insert model | mask OR into bit array | full table copy (scatter not native to PIM) |

---

## 3. Benchmark Results (Bloom Filter, from results.txt)

Results at k=5, load=0.125 across all three bit-array sizes. Throughput in billions of elements per second. Energy in millijoules per batch operation.

### Insert throughput (B eps)

| Variant | m = 2²⁰ | m = 2²³ | m = 2²⁶ |
|---|---|---|---|
| cpu | 0.096 | 0.032 | 0.010 |
| pim-v2 | 9.540 | 9.540 | 9.540 |
| pim-v3 | 1.321 | 1.324 | 1.324 |

### Query throughput (B eps)

| Variant | m = 2²⁰ | m = 2²³ | m = 2²⁶ |
|---|---|---|---|
| cpu | 0.080 | 0.031 | 0.015 |
| pim-v2 | 13.744 | 13.744 | 13.744 |
| pim-v3 | 1.379 | 1.382 | 1.383 |

### Insert energy (mJ)

| Variant | m = 2²⁰ | m = 2²³ | m = 2²⁶ |
|---|---|---|---|
| cpu | 0.000 | 0.000 | 0.000 |
| pim-v2 | 0.056 | 0.452 | 3.612 |
| pim-v3 | 0.424 | 3.382 | 27.047 |

### Key observations

- **pim-v2 throughput is constant across m** because the workload is a single fixed-cost `pimOr` over m bits — it does not vary with k or n at fixed load
- **CPU throughput drops sharply with m** due to cache pressure: m=2²⁰ fits in L3, m=2²⁶ causes near-certain DRAM misses on every hash probe
- **pim-v3 energy scales with k and n** because it runs k `pimMulScalar` passes over n keys; pim-v2 energy is independent of both
- **FPR is identical across all three variants** for the same (m, k, n) — all implement the same logical filter

---

## Build & Run

```bash
cd PIM
module load gcc/14.2.0
make clean && make perf

# bloom filter benchmark sweep
./bloom.out > results.txt

# apt detection — all variant examples
./detect.out process_stream.log cpu          1024 3 1
./detect.out process_stream.log cpu-counting 1024 3 1
./detect.out process_stream.log cuckoo-cpu   1024 3 1
./detect.out process_stream.log pim-v2       1024 3 1
./detect.out process_stream.log pim-v3       1024 3 1
./detect.out process_stream.log cuckoo-pim-v2 1024 3 1
./detect.out process_stream.log cuckoo-pim-v3 1024 3 1

# with external log file
./detect.out --log alerts.txt process_stream.log cuckoo-cpu 1024 3 1
```
