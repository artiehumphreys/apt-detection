#include "counting_bloom_filter_top.hpp"
#include "counting_bloom_filter_hls.hpp"

// CBF entry point

void counting_bloom_filter_top(uint32_t *keys, uint8_t *results,
                               uint32_t num_keys, uint8_t mode) {
#pragma HLS INTERFACE m_axi port = keys offset = slave bundle = gmem0 depth =  \
    4096
#pragma HLS INTERFACE m_axi port = results offset = slave bundle =             \
    gmem1 depth = 4096
#pragma HLS INTERFACE s_axilite port = num_keys
#pragma HLS INTERFACE s_axilite port = mode
#pragma HLS INTERFACE s_axilite port = return

  static uint8_t counters[CBF_SIZE];
#pragma HLS BIND_STORAGE variable = counters type = ram_2p impl = bram

  if (mode == CBF_CLEAR) {
    for (uint32_t i = 0; i < CBF_SIZE; i++) {
#pragma HLS PIPELINE II = 1
      counters[i] = 0;
    }
  } else if (mode == CBF_INSERT) {
    for (uint32_t k = 0; k < num_keys; k++) {
#pragma HLS PIPELINE
      hls_cbf_insert<CBF_SIZE, CBF_NUM_HASHES>(counters, keys[k]);
    }
  } else if (mode == CBF_REMOVE) {
    for (uint32_t k = 0; k < num_keys; k++) {
#pragma HLS PIPELINE
      hls_cbf_remove<CBF_SIZE, CBF_NUM_HASHES>(counters, keys[k]);
    }
  } else if (mode == CBF_QUERY) {
    for (uint32_t k = 0; k < num_keys; k++) {
#pragma HLS PIPELINE
      bool found = hls_cbf_query<CBF_SIZE, CBF_NUM_HASHES>(counters, keys[k]);
      results[k] = found ? 1 : 0;
    }
  }
}
