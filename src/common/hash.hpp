#pragma once

#include <cstddef>
#include <cstdint>

// PIM-friendly hash: xor-shift-multiply finalizer (murmur3 fmix32 variant).
// Decomposes into operations that map directly to PIMeval element-wise ops
// (pimXorScalar, pimShiftBitsRight, pimMulScalar).
inline uint32_t pim_hash(uint32_t key, uint32_t seed) {
  uint32_t h = key ^ seed;
  h ^= h >> 16;
  h *= 0x45d9f3b;
  h ^= h >> 16;
  return h;
}

// Murmur3 hash, a faster version of Murmur2, cited here:
// https://docs.amd.com/r/en-US/Vitis-Tutorials-Vitis-Hardware-Acceleration/Determine-the-Maximum-Achievable-Throughput
// Pure integer arithmetic and no dynamic allocation

// https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
namespace murmur3 {

inline uint32_t fmix32(uint32_t h) {
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

inline uint32_t hash(const uint8_t *data, std::size_t len, uint32_t seed) {
  const uint32_t c1 = 0xcc9e2d51;
  const uint32_t c2 = 0x1b873593;

  uint32_t h = seed;
  const std::size_t nblocks = len / 4;

  for (std::size_t i = 0; i < nblocks; ++i) {
    uint32_t k = static_cast<uint32_t>(data[i * 4 + 0]) |
                 (static_cast<uint32_t>(data[i * 4 + 1]) << 8) |
                 (static_cast<uint32_t>(data[i * 4 + 2]) << 16) |
                 (static_cast<uint32_t>(data[i * 4 + 3]) << 24);
    k *= c1;
    k = (k << 15) | (k >> 17);
    k *= c2;
    h ^= k;
    h = (h << 13) | (h >> 19);
    h = h * 5 + 0xe6546b64;
  }

  const uint8_t *tail = data + nblocks * 4;
  uint32_t k = 0;
  switch (len & 3) {
  case 3:
    k ^= static_cast<uint32_t>(tail[2]) << 16;
    [[fallthrough]];
  case 2:
    k ^= static_cast<uint32_t>(tail[1]) << 8;
    [[fallthrough]];
  case 1:
    k ^= static_cast<uint32_t>(tail[0]);
    k *= c1;
    k = (k << 15) | (k >> 17);
    k *= c2;
    h ^= k;
  }

  h ^= static_cast<uint32_t>(len);
  return fmix32(h);
}

} // namespace murmur3
