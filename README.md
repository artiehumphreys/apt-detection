# apt-detection

APT detection experiments using Bloom filters, counting Bloom filters, cuckoo filters, and PIM variants.

## Layout

- `src/python/`: Python reference implementations and attack-log generation.
- `src/software/`: C++ software Bloom/counting Bloom headers.
- `src/common/`: Shared C++ hash helpers.
- `PIMeval-PIMbench/PIMbench/bloom-filter/`: PIMeval benchmark code for Bloom/counting/cuckoo filters and detection.

## Python setup

```bash
cd apt-detection/src/python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the local reference implementations:

```bash
python3 bloom_filter.py
python3 counting_bloom_filter.py
python3 cuckoo_filter.py
```

Generate the sample attack graph, attack tree, and process stream:

```bash
python3 generate_data.py
python3 generate_larger_data.py
```

Outputs are written under `src/python/data/`.

## PIM Bloom filter setup

The only PIMeval benchmark folder used by this project is:

```bash
cd apt-detection/PIMeval-PIMbench/PIMbench/bloom-filter
```

Build from the Bloom filter folder:

```bash
module load gcc/14.2.0 # if on rivanna or CS server
make clean
make perf
```

This builds the executables in `PIM/`:

- `PIM/bloom.out`: benchmark runner.
- `PIM/detect.out`: process-stream detector.

Run the benchmark:

```bash
cd PIM
./bloom.out > outs/results.txt
```

Run detection on a process log:

```bash
cd PIM
./detect.out logs/process_stream.log cpu 1048576 3 100
```

General detection form:

```bash
./detect.out [--log <file>] [--hash xor-shift|murmur3|jenkins] <logfile> <variant> <m> <k> [seed_pid...]
```

Supported variants:

```text
cpu
pim-v2 # these are the default bloom filters
pim-v3 # these are the default bloom filters
pim-v4 # these are the default bloom filters
cpu-counting
pim-counting-v2
pim-counting-v3
pim-counting-v4
cuckoo-cpu
cuckoo-pim-v2
cuckoo-pim-v3
cuckoo-pim-v4
```

Notes:

- `m` must be a power of two.
- `k` is used for Bloom/counting Bloom filters and ignored for cuckoo filters.
- PIM-native variants support `xor-shift` and `jenkins`; CPU variants also support `murmur3`.

Clean builds:

```bash
cd apt-detection/PIMeval-PIMbench/PIMbench/bloom-filter
make clean
```
