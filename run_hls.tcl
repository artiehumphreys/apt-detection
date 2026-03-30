# Vitis HLS build script for Bloom filter / Counting Bloom filter kernels.

set top_func "bloom_filter_top"
set proj_name "bloom_hls"

if { $argc > 0 && [lindex $argv 0] eq "cbf" } {
    set top_func "counting_bloom_filter_top"
    set proj_name "cbf_hls"
}

open_project $proj_name
set_top $top_func

add_files src/hls/bloom_filter_top.cpp -cflags "-Isrc/hls"
add_files src/hls/counting_bloom_filter_top.cpp -cflags "-Isrc/hls"

open_solution "solution1"
# TODO: configure this with target FPGA
# set_part {}
create_clock -period 5 -name default

csynth_design

export_design -format ip_catalog

exit
