#pragma once

#include "hash.hpp"
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

template <std::size_t size, std::size_t num_hashes> struct CountingBloomFilter {
  std::vector<uint8_t> filter = std::vector<uint8_t>(size, 0);
  static constexpr uint8_t max_value = std::numeric_limits<uint8_t>::max();

  static constexpr std::size_t mask = size - 1;
  static_assert((size & (size - 1)) == 0, "size must be a power of two");

  void insert(const std::string &key) noexcept {
    for (std::size_t i = 0; i < num_hashes; ++i) {
      std::size_t index = hash(key, i) & mask;
      if (filter[index] < max_value)
        ++filter[index];
    }
  }

  void remove(const std::string &key) noexcept {
    for (std::size_t i = 0; i < num_hashes; ++i) {
      std::size_t index = hash(key, i) & mask;
      if (filter[index] > 0)
        --filter[index];
    }
  }

  bool query(const std::string &key) const noexcept {
    for (std::size_t i = 0; i < num_hashes; ++i) {
      std::size_t index = hash(key, i) & mask;
      if (filter[index] == 0)
        return false;
    }
    return true;
  }
};
