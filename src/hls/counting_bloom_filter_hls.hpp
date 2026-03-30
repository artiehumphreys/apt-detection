#pragma once

#include "hls_hash.hpp"
#include <cstdint>

// HLS-friendly Counting Bloom filter helpers.
// One uint8_t counter per slot, saturating at 0/255.
// Same double-hashing as the software version with HLS pragmas.

template <uint32_t SIZE, int NUM_HASHES>
void hls_cbf_insert(uint8_t counters[SIZE], uint32_t key) {
#pragma HLS INLINE
  const uint32_t MASK = SIZE - 1;
  uint32_t h1 = hls_hash(key, 0);
  uint32_t h2 = hls_hash(key, h1);
  for (int i = 0; i < NUM_HASHES; i++) {
#pragma HLS UNROLL
    uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
    if (counters[idx] < 255)
      counters[idx]++;
  }
}

template <uint32_t SIZE, int NUM_HASHES>
void hls_cbf_remove(uint8_t counters[SIZE], uint32_t key) {
#pragma HLS INLINE
  const uint32_t MASK = SIZE - 1;
  uint32_t h1 = hls_hash(key, 0);
  uint32_t h2 = hls_hash(key, h1);
  for (int i = 0; i < NUM_HASHES; i++) {
#pragma HLS UNROLL
    uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
    if (counters[idx] > 0)
      counters[idx]--;
  }
}

template <uint32_t SIZE, int NUM_HASHES>
bool hls_cbf_query(const uint8_t counters[SIZE], uint32_t key) {
#pragma HLS INLINE
  const uint32_t MASK = SIZE - 1;
  uint32_t h1 = hls_hash(key, 0);
  uint32_t h2 = hls_hash(key, h1);
  bool found = true;
  for (int i = 0; i < NUM_HASHES; i++) {
#pragma HLS UNROLL
    uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
    if (counters[idx] == 0)
      found = false;
  }
  return found;
}
