#pragma once

#include <cstdint>

// Configuration — SIZE must be a power of two
static constexpr uint32_t CBF_SIZE = 1024;
static constexpr int CBF_NUM_HASHES = 3;

enum CBFMode { CBF_CLEAR = 0, CBF_INSERT = 1, CBF_REMOVE = 2, CBF_QUERY = 3 };

void counting_bloom_filter_top(uint32_t *keys, uint8_t *results,
                               uint32_t num_keys, uint8_t mode);
