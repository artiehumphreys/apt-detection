#pragma once

#include "hls_hash.hpp"
#include <cstdint>

// HLS-friendly Bloom filter helpers.
// UNROLL on the hash loop for parallel BRAM access
// INLINE so the caller's PIPELINE pragma governs scheduling

template <uint32_t SIZE, int NUM_HASHES>
void hls_bloom_insert(uint8_t bits[SIZE / 8], uint32_t key) {
#pragma HLS INLINE
  const uint32_t MASK = SIZE - 1;
  uint32_t h1 = hls_hash(key, 0);
  uint32_t h2 = hls_hash(key, h1);
  for (int i = 0; i < NUM_HASHES; i++) {
#pragma HLS UNROLL
    uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
    bits[idx >> 3] |= static_cast<uint8_t>(1u << (idx & 7));
  }
}

template <uint32_t SIZE, int NUM_HASHES>
bool hls_bloom_query(const uint8_t bits[SIZE / 8], uint32_t key) {
#pragma HLS INLINE
  const uint32_t MASK = SIZE - 1;
  uint32_t h1 = hls_hash(key, 0);
  uint32_t h2 = hls_hash(key, h1);
  bool found = true;
  for (int i = 0; i < NUM_HASHES; i++) {
#pragma HLS UNROLL
    uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
    if (!(bits[idx >> 3] & (1u << (idx & 7)))) {
      found = false;
    }
  }
  return found;
}
