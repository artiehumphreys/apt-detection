#pragma once

#include <cstdint>

// Configuration — SIZE must be a power of two
static constexpr uint32_t BF_SIZE = 1024;
static constexpr int BF_NUM_HASHES = 3;
static constexpr uint32_t BF_NUM_BYTES = BF_SIZE / 8;

enum BFMode { BF_CLEAR = 0, BF_INSERT = 1, BF_QUERY = 2 };

void bloom_filter_top(uint32_t *keys, uint8_t *results, uint32_t num_keys,
                      uint8_t mode);
