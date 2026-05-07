#pragma once

#include "hash.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>

// HLS-friendly Counting Bloom filter.  Same double-hashing scheme as
// BloomFilter, but each slot is a uint8_t counter instead of a single bit.
template <std::size_t SIZE, std::size_t NUM_HASHES> struct CountingBloomFilter {
  static_assert((SIZE & (SIZE - 1)) == 0, "SIZE must be a power of two");

  static constexpr uint32_t MASK = SIZE - 1;

  uint8_t counters[SIZE];

  void clear() { std::memset(counters, 0, SIZE); }

  void insert(uint32_t key) {
    uint32_t h1 = pim_hash(key, 0);
    uint32_t h2 = pim_hash(key, h1);
    for (std::size_t i = 0; i < NUM_HASHES; ++i) {
      uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
      if (counters[idx] < 255)
        ++counters[idx];
    }
  }

  void remove(uint32_t key) {
    uint32_t h1 = pim_hash(key, 0);
    uint32_t h2 = pim_hash(key, h1);
    for (std::size_t i = 0; i < NUM_HASHES; ++i) {
      uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
      if (counters[idx] > 0)
        --counters[idx];
    }
  }

  bool query(uint32_t key) const {
    uint32_t h1 = pim_hash(key, 0);
    uint32_t h2 = pim_hash(key, h1);
    for (std::size_t i = 0; i < NUM_HASHES; ++i) {
      uint32_t idx = (h1 + static_cast<uint32_t>(i) * h2) & MASK;
      if (counters[idx] == 0)
        return false;
    }
    return true;
  }
};
