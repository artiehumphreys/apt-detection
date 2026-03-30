#include "bloom_filter_top.hpp"
#include "bloom_filter_hls.hpp"

// BF entry point

void bloom_filter_top(uint32_t *keys, uint8_t *results, uint32_t num_keys,
                      uint8_t mode) {
#pragma HLS INTERFACE m_axi port = keys offset = slave bundle = gmem0 depth =  \
    4096
#pragma HLS INTERFACE m_axi port = results offset = slave bundle =             \
    gmem1 depth = 4096
#pragma HLS INTERFACE s_axilite port = num_keys
#pragma HLS INTERFACE s_axilite port = mode
#pragma HLS INTERFACE s_axilite port = return

  static uint8_t bits[BF_NUM_BYTES];
#pragma HLS BIND_STORAGE variable = bits type = ram_2p impl = bram

  if (mode == BF_CLEAR) {
    for (uint32_t i = 0; i < BF_NUM_BYTES; i++) {
#pragma HLS PIPELINE II = 1
      bits[i] = 0;
    }
  } else if (mode == BF_INSERT) {
    for (uint32_t k = 0; k < num_keys; k++) {
#pragma HLS PIPELINE
      hls_bloom_insert<BF_SIZE, BF_NUM_HASHES>(bits, keys[k]);
    }
  } else if (mode == BF_QUERY) {
    for (uint32_t k = 0; k < num_keys; k++) {
#pragma HLS PIPELINE
      bool found = hls_bloom_query<BF_SIZE, BF_NUM_HASHES>(bits, keys[k]);
      results[k] = found ? 1 : 0;
    }
  }
}
