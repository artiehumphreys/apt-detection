# currently not working, next look at: https://github.com/huydhn/cuckoo-filter

import random
import time
from hash_implementation import Hash

class CuckooFilter:
    def __init__(self, size: int, max_kicks: int = 500):
        if (size & (size - 1)) != 0:
            raise ValueError("size must be a power of two")
        self.size = size
        self.mask = size - 1
        self.max_kicks = max_kicks
        self.buckets = [None] * size

    def get_hashes(self, x: str):
        h = Hash.murmur3_32(x, seed=0)
        i1 = h & self.mask
        fp = (Hash.murmur3_32(x, seed=1) & 0xFFFF) or 1
        return i1, fp

    def get_alt_index(self, i, fp):
        # The XOR trick depends on this hash being stable
        # Using a fixed seed (42) for fingerprint randomization
        return (i ^ Hash.murmur3_32(str(fp), seed=42)) & self.mask

    def insert(self, x: str) -> bool:
        i1, fp = self.get_hashes(x)
        
        if self.buckets[i1] is None:
            self.buckets[i1] = fp
            return True
        
        i2 = self.get_alt_index(i1, fp)
        if self.buckets[i2] is None:
            self.buckets[i2] = fp
            return True

        curr_i = random.choice([i1, i2])
        for _ in range(self.max_kicks):
            fp, self.buckets[curr_i] = self.buckets[curr_i], fp
            curr_i = self.get_alt_index(curr_i, fp)
            
            if self.buckets[curr_i] is None:
                self.buckets[curr_i] = fp
                return True
        return False

    def query(self, x: str) -> bool:
        i1, fp = self.get_hashes(x)
        if self.buckets[i1] == fp: return True
        
        i2 = self.get_alt_index(i1, fp)
        if self.buckets[i2] == fp: return True
        return False

def test_cuckoo():
    size = 2**10
    cf = CuckooFilter(size=size)
    inserted_items = []
    
    count = 0
    for i in range(int(size * 0.95)):
        item = f"flow_key_{i}"
        if cf.insert(item):
            inserted_items.append(item)
            count += 1
        else:
            print(f"Saturated at {i} items.")
            break
            
    load_factor = (count / size) * 100
    print(f"Load Factor: {load_factor:.2f}%")
    
    # Verify No False Negatives
    fns = sum(1 for item in inserted_items if not cf.query(item))
    print(f"False Negatives: {fns}")
    
if __name__ == "__main__":
    test_cuckoo()