#pragma once

#include <cstdint>

// HLS-synthesizable hash: same xor-shift-multiply as pim_hash
// but with HLS INLINE pragma so it gets folded into the caller's pipeline.
inline uint32_t hls_hash(uint32_t key, uint32_t seed) {
#pragma HLS INLINE
  uint32_t h = key ^ seed;
  h ^= h >> 16;
  h *= 0x45d9f3b;
  h ^= h >> 16;
  return h;
}
