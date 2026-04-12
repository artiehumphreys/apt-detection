from hash_implementation import Hash

class BloomFilter:
    def __init__(self, size: int, num_hashes: int):
        if (size & (size - 1)) != 0:
            raise ValueError("size must be a power of two")
        
        self.size = size
        self.mask = size - 1
        self.num_hashes = num_hashes
        # Using a Python large integer as a bitset
        self.bitset = 0 

    def get_hashes(self, x: str):
        h1 = Hash.murmur3_32(x, seed=0)
        h2 = Hash.murmur3_32(x, seed=1)
            
        # h1 = Hash.fnv1a(x, seed=0)
        # h2 = Hash.fnv1a(x, seed=1)
        
        # h1 = Hash.sha256(x, seed=0)
        # h2 = Hash.sha256(x, seed=1)
        
        for i in range(self.num_hashes):
            yield (h1 + i * h2) & self.mask

    def insert(self, x: str):
        for i in self.get_hashes(x):
            # Set the bit at index i
            self.bitset |= (1 << i)

    def query(self, x: str) -> bool:
        for i in self.get_hashes(x):
            # Check if the bit at index i is NOT set
            if not (self.bitset & (1 << i)):
                return False
        return True
    
def test_standard_bloom():
    size = 2**10
    bf = BloomFilter(size, num_hashes=3)
    
    bf.insert("192.168.1.1")
    assert bf.query("192.168.1.1") == True
    assert bf.query("10.0.0.5") == False
    print("Basic Insert: PASS")

    test_set = [f"malware_{i}" for i in range(200)]
    for m in test_set:
        bf.insert(m)
        
    false_positives = 0
    for i in range(1000):
        if bf.query(f"clean_file_{i}"):
            false_positives += 1
            
    print(f"Standard Bloom FPR: {false_positives/1000:.2%}")

if __name__ == "__main__":
    test_standard_bloom()