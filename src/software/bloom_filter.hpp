#pragma once

#include "hash.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>

// HLS-friendly Bloom filter.  Uses double hashing as cited here:
// https://www.eecs.harvard.edu/~michaelm/postscripts/tr-02-05.pdf

// Fixed-size uint8_t bit-array. No STL, no dynamic alloc.
template <std::size_t SIZE, std::size_t NUM_HASHES> struct BloomFilter {
  // efficient modulo via power of 2 size
  static_assert((SIZE & (SIZE - 1)) == 0, "SIZE must be a power of two");
  static_assert(SIZE >= 8, "SIZE must be at least 8");

  static constexpr std::size_t NUM_BYTES = SIZE / 8;
  static constexpr uint32_t MASK = SIZE - 1;

  uint8_t bits[NUM_BYTES];

  void clear() { std::memset(bits, 0, NUM_BYTES); }

  void insert(uint32_t key) {
    uint32_t h1 = pim_hash(key, 0);
    uint32_t h2 = pim_hash(key, h1);
    for (std::size_t i = 0; i < NUM_HASHES; ++i) {
      uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
      bits[idx >> 3] |= static_cast<uint8_t>(1u << (idx & 7));
    }
  }

  bool query(uint32_t key) const {
    uint32_t h1 = pim_hash(key, 0);
    uint32_t h2 = pim_hash(key, h1);
    for (std::size_t i = 0; i < NUM_HASHES; ++i) {
      uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
      if (!(bits[idx >> 3] & (1u << (idx & 7))))
        return false;
    }
    return true;
  }
};
