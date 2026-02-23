
from hash_implementation import Hash

class CountingBloomFilter:
    def __init__(self, size: int, num_hashes: int):
        if (size & (size - 1)) != 0:
            raise ValueError("size must be a power of two")
        
        self.size = size
        self.mask = size - 1
        self.num_hashes = num_hashes
        self.buckets = [0] * size

    def get_hashes(self, x: str):
        h1 = Hash.murmur3_32(x, seed=0)
        h2 = Hash.murmur3_32(x, seed=1)
            
        # h1 = Hash.fnv1a(x, seed=0)
        # h2 = Hash.fnv1a(x, seed=1)
        
        # h1 = Hash.sha256(x, seed=0)
        # h2 = Hash.sha256(x, seed=1)
        
        for i in range(self.num_hashes):
            # Kirsch-Mitzenmacher: g_i(x) = h_1(x) + i*h_2(x)
            # https://stackoverflow.com/questions/70963247/bloom-filters-with-the-kirsch-mitzenmacher-optimization
            
            yield (h1 + i * h2) & self.mask

    def insert(self, x: str):
        for i in self.get_hashes(x):
            self.buckets[i] += 1

    def remove(self, x: str):
        for i in self.get_hashes(x):
            if self.buckets[i] > 0:
                self.buckets[i] -= 1

    def query(self, x: str) -> bool:
        for i in self.get_hashes(x):
            if self.buckets[i] <= 0:
                return False
            
        return True
    
    
def test_counting_bloom():
    size = 2**10
    bf = CountingBloomFilter(size, num_hashes=3)
    
    items = ["192.168.1.1", "10.0.0.5", "172.16.0.20"]
    for item in items:
        bf.insert(item)
    
    assert bf.query("192.168.1.1") == True, "Failed to find inserted item"
    
    bf.remove("10.0.0.5")
    assert bf.query("10.0.0.5") == False, "Delete failed or item still present"
    print("Basic Insert/Delete: PASS")

    # Test False Positive Rate
    test_set = [f"malware_{i}" for i in range(200)]
    for m in test_set:
        bf.insert(m)
        
    false_positives = 0
    for i in range(1000):
        if bf.query(f"clean_file_{i}"):
            false_positives += 1
            
    print(f"False Positive Rate: {false_positives/1000:.2%}")

if __name__ == "__main__":
    test_counting_bloom()