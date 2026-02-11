#pragma once

#include <bitset>
#include <cstddef>
#include <string>

template <std::size_t size, std::size_t num_hashes> struct BloomFilter {
  std::bitset<size> filter;

  // power of two size for efficient modulo
  std::size_t mask = size - 1;
  static_assert((size & (size - 1)) == 0, "size must be a power of two");

  void insert(const std::string &key) {
    for (std::size_t i = 0; i < num_hashes; ++i) {
      std::size_t index = 0 & mask; /* TODO: hash */
      filter.set(index);
    }
  }

  bool query(const std::string &key) {
    for (std::size_t i = 0; i < num_hashes; ++i) {
      std::size_t index = 0 & mask; /* TODO: hash */
      if (!filter.test(index))
        return false;
    }
    return true;
  }
};
