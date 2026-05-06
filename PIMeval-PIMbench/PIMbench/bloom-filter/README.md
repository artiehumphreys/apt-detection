# bloom filter (pimeval)

## build & run

```bash
cd PIM
module load gcc/14.2.0
make clean
make perf
./bloom.out > results.txt
```

## visuals

```bash
module load gcc/14.2.0 python/3.12.3
pip install --user matplotlib numpy pandas
cd visuals
python3 plot.py
```

output pngs are written to `visuals/`