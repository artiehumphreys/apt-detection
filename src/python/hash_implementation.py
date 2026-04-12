import hashlib

class Hash:
    @staticmethod
    def fnv1a(data: str, seed: int = 0) -> int:
        """Extremely fast, hardware-friendly XOR/MUL hash."""
        h = 0x811c9dc5 + seed
        for char in data:
            h ^= ord(char)
            h = (h * 0x01000193) & 0xFFFFFFFF
        return h

    @staticmethod
    def sha256(data: str, seed: int = 0) -> int:
        """High-entropy cryptographic hash (Slower)."""
        # We include the seed in the string to get different results
        h_obj = hashlib.sha256(f"{seed}{data}".encode())
        return int(h_obj.hexdigest(), 16) & 0xFFFFFFFF

    @staticmethod
    def murmur3_32(key: str, seed: int = 0) -> int:
        """Industry standard: Excellent balance of speed and distribution."""
        data = key.encode()
        length = len(data)
        h1 = seed
        c1, c2 = 0xcc9e2d51, 0x1b873593

        # Body
        for i in range(0, (length // 4) * 4, 4):
            k1 = data[i] | (data[i+1] << 8) | (data[i+2] << 16) | (data[i+3] << 24)
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
            h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

        # Tail
        tail_idx = (length // 4) * 4
        k1 = 0
        remaining = length % 4
        if remaining >= 3: k1 ^= data[tail_idx + 2] << 16
        if remaining >= 2: k1 ^= data[tail_idx + 1] << 8
        if remaining >= 1:
            k1 ^= data[tail_idx]
            k1 = (k1 * c1) & 0xFFFFFFFF
            k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1 = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        # Finalization
        h1 ^= length
        h1 ^= h1 >> 16
        h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
        h1 ^= h1 >> 13
        h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
        h1 ^= h1 >> 16
        return h1 & 0xFFFFFFFF

    @classmethod
    def generate_indices(cls, key: str, size: int, num_hashes: int, mode='murmur'):
        """
        Universal wrapper for Kirsch-Mitzenmacher optimization.
        Returns a generator of indices within the range [0, size-1].
        """
        mask = size - 1
        
        # Select base hashing function
        if mode == 'murmur':
            h1, h2 = cls.murmur3_32(key, 0), cls.murmur3_32(key, 1)
        elif mode == 'fnv1a':
            h1, h2 = cls.fnv1a(key, 0), cls.fnv1a(key, 1)
        else: # sha256
            h1, h2 = cls.sha256(key, 0), cls.sha256(key, 1)

        for i in range(num_hashes):
            yield (h1 + i * h2) & mask