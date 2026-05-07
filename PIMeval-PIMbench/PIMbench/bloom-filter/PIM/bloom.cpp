#include "bloom_filter.hpp"

int main() {
    initHashConsts();

    // static const uint64_t m_vals[] = {1ULL << 19};
    // static const uint64_t m_vals[] = {1ULL << 20};
    // static const uint64_t m_vals[] = {1ULL << 22};
    static const uint64_t m_vals[] = {1ULL << 21}; // keep this one for now
    // static const int k_vals[] = {4};
    // static const int k_vals[] = {5};
    static const int k_vals[] = {3};
    // static const double load_vals[] = {0.0625, 0.125};
    // static const double load_vals[] = {0.125, 0.25, 0.5};
    static const double load_vals[] = {0.125, 0.25};


    static const HashScheme hs_cpu_vals[] = {
        HashScheme::XOR_SHIFT,
        HashScheme::MURMUR3,
        HashScheme::JENKINS,
    };

    static const HashScheme hs_pim_vals[] = {
        HashScheme::XOR_SHIFT,
        HashScheme::JENKINS,
    };

    uint64_t max_n = (uint64_t)std::round(0.25 * (double)(1ULL << 26));
    std::vector<uint64_t> allKeys(2 * max_n);
    LCG lcg(0xDEADBEEFCAFEBABEULL);
    for (auto& key : allKeys) key = lcg.next(); // fill this once, dont redo it

    auto printRow = [](const std::string& hs, const std::string& variant, uint64_t m, int k, double load, uint64_t n, const BenchMetrics& bm) {
        std::cout << std::fixed << hs << "," << variant << "," << m << "," << k << "," << std::setprecision(4) << load << "," << n << "," << std::setprecision(2) << bm.insertThroughput() << "," << bm.queryThroughput() << "," << std::setprecision(6) << bm.fpr << "," << std::setprecision(4) << bm.insertMj << "," << bm.queryMj << "\n";
        std::cout.flush();
    };

    auto printCountingRow = [](const std::string& hs, const std::string& variant, uint64_t m, int k, double load, uint64_t n, const CountingBenchMetrics& bm) {
        std::cout << std::fixed << hs << "," << variant << "," << m << "," << k << "," << std::setprecision(4) << load << "," << n << "," << std::setprecision(2) << bm.insertThroughput() << "," << bm.deleteThroughput() << "," << bm.queryThroughput() << "," << std::setprecision(6) << bm.fpr << "," << bm.fnr_kept << "," << bm.fpr_del << "," << std::setprecision(4) << bm.insertMj << "," << bm.deleteMj << "," << bm.queryMj << "\n";
        std::cout.flush();
    };


    auto runCuckooDeleteExperiments = [&]() {
        std::cout << "hash_scheme,variant,m,k,load_factor,n,"
                     "insert_throughput_eps,delete_throughput_eps,query_throughput_eps,"
                     "fpr,fnr_kept,fpr_deleted,"
                     "insert_energy_mj,delete_energy_mj,query_energy_mj\n";
        std::cout.flush();

        for (HashScheme hs : hs_cpu_vals) {
            for (uint64_t m : m_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    uint64_t n_del = n / 2;
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> del_keys(ins_keys.begin(), ins_keys.begin() + (ptrdiff_t)n_del); // chop the front half
                    std::vector<uint64_t> kept_keys(ins_keys.begin() + (ptrdiff_t)n_del, ins_keys.end());
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                    // CpuBloomFilter bf(m, 3, hs);
                    // CpuCountingBloomFilter bf(m, 3, hs);
                    CpuCuckooFilter bf(m, hs);
                    printCountingRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runCpuCountingBench(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                }
            }
        }

        for (HashScheme hs : hs_cpu_vals) {
            for (uint64_t m : m_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    uint64_t n_del = n / 2;
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> del_keys(ins_keys.begin(), ins_keys.begin() + (ptrdiff_t)n_del);
                    std::vector<uint64_t> kept_keys(ins_keys.begin() + (ptrdiff_t)n_del, ins_keys.end()); // keep the back half
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                    // PimBloomFilterV2 bf(m, 3, hs);
                    PimCuckooFilterV2 bf(m, hs);
                    printCountingRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runPimCountingBench(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                }
            }
        }

        for (HashScheme hs : hs_pim_vals) {
            for (uint64_t m : m_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    uint64_t n_del = n / 2;
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> del_keys(ins_keys.begin(), ins_keys.begin() + (ptrdiff_t)n_del);
                    std::vector<uint64_t> kept_keys(ins_keys.begin() + (ptrdiff_t)n_del, ins_keys.end());
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                    {
                        PimCuckooFilterV3 bf(m, n, hs, false);
                        printCountingRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runPimCountingBench(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                    }

                    {
                        PimCuckooFilterV3 bf(m, n, hs, true);
                        printCountingRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runPimCountingBenchV4(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                    }
                }
            }
        }
    };


    std::cout << "hash_scheme,variant,m,k,load_factor,n,"
                 "insert_throughput_eps,query_throughput_eps,"
                 "fpr,insert_energy_mj,query_energy_mj\n";
    std::cout.flush();

    for (HashScheme hs : hs_cpu_vals) {
        for (uint64_t m : m_vals) {
            for (int k : k_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                    CpuBloomFilter bf(m, k, hs);
                    printRow(hashSchemeName(hs), "cpu", m, k, load, n, runCpuBench(&bf, ins_keys, fp_keys));
                }
            }
        }
    }



    assert(pimCreateDevice(PIM_DEVICE_BANK_LEVEL, 4, 128, 32, 1024, 8192) == PIM_OK); // start pim before its stuff

    for (HashScheme hs : hs_cpu_vals) {
        for (uint64_t m : m_vals) {
            for (int k : k_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m); // same n math every time
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                    PimBloomFilterV2 bf(m, k, hs);
                    printRow(hashSchemeName(hs), bf.name(), m, k, load, n, runPimBench(&bf, ins_keys, fp_keys));
                }
            }
        }
    }

    for (HashScheme hs : hs_pim_vals) {
        for (int v = 3; v <= 4; v++) {
            for (uint64_t m : m_vals) {
                for (int k : k_vals) {
                    for (double load : load_vals) {
                        uint64_t n = (uint64_t)std::round(load * (double)m);
                        std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                        std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                        BloomFilter* bf = (v == 3) ? new PimBloomFilterV3(m, k, n, hs, false) : new PimBloomFilterV3(m, k, n, hs, true);
                        BenchMetrics bm = (v == 4) ? runPimBenchV4(bf, ins_keys, fp_keys) : runPimBench(bf, ins_keys, fp_keys);
                        printRow(hashSchemeName(hs), bf->name(), m, k, load, n, bm);
                        delete bf;
                    }
                }
            }
        }
    }


    std::cout << "\nhash_scheme,variant,m,k,load_factor,n,"
                 "insert_throughput_eps,delete_throughput_eps,query_throughput_eps,"
                 "fpr,fnr_kept,fpr_deleted,"
                 "insert_energy_mj,delete_energy_mj,query_energy_mj\n";
    std::cout.flush();

    for (HashScheme hs : hs_cpu_vals) {
        for (uint64_t m : m_vals) {
            for (int k : k_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    uint64_t n_del = n / 2;
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> del_keys(ins_keys.begin(), ins_keys.begin() + (ptrdiff_t)n_del);
                    std::vector<uint64_t> kept_keys(ins_keys.begin() + (ptrdiff_t)n_del, ins_keys.end());
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                    CpuCountingBloomFilter bf(m, k, hs);
                    printCountingRow(hashSchemeName(hs), bf.name(), m, k, load, n, runCpuCountingBench(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                }
            }
        }
    }

    for (HashScheme hs : hs_cpu_vals) {
        for (uint64_t m : m_vals) {
            for (int k : k_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    uint64_t n_del = n / 2;
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> del_keys(ins_keys.begin(), ins_keys.begin() + (ptrdiff_t)n_del);
                    std::vector<uint64_t> kept_keys(ins_keys.begin() + (ptrdiff_t)n_del, ins_keys.end());
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                    PimCountingBloomFilterV2 bf(m, k, hs);
                    printCountingRow(hashSchemeName(hs), bf.name(), m, k, load, n, runPimCountingBench(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                }
            }
        }
    }

    for (HashScheme hs : hs_pim_vals) {
        for (uint64_t m : m_vals) {
            for (int k : k_vals) {
                for (double load : load_vals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);
                    uint64_t n_del = n / 2;
                    std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> del_keys(ins_keys.begin(), ins_keys.begin() + (ptrdiff_t)n_del);
                    std::vector<uint64_t> kept_keys(ins_keys.begin() + (ptrdiff_t)n_del, ins_keys.end());
                    std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                    {
                        PimCountingBloomFilterV3 bf(m, k, n, hs, false);
                        printCountingRow(hashSchemeName(hs), bf.name(), m, k, load, n, runPimCountingBench(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                    }

                    {
                        PimCountingBloomFilterV3 bf(m, k, n, hs, true);
                        printCountingRow(hashSchemeName(hs), bf.name(), m, k, load, n, runPimCountingBenchV4(&bf, ins_keys, del_keys, kept_keys, fp_keys));
                    }
                }
            }
        }
    }


    std::cout << "\nhash_scheme,variant,m,k,load_factor,n,"
                 "insert_throughput_eps,query_throughput_eps,"
                 "fpr,insert_energy_mj,query_energy_mj\n";
    std::cout.flush();

    for (HashScheme hs : hs_cpu_vals) {
        for (uint64_t m : m_vals) {
            for (double load : load_vals) {
                uint64_t n = (uint64_t)std::round(load * (double)m);
                std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                CpuCuckooFilter bf(m, hs);
                printRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runCpuBench(&bf, ins_keys, fp_keys));
            }
        }
    }

    for (HashScheme hs : hs_cpu_vals) {
        for (uint64_t m : m_vals) {
            for (double load : load_vals) {
                uint64_t n = (uint64_t)std::round(load * (double)m);
                std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                PimCuckooFilterV2 bf(m, hs);
                printRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runPimBench(&bf, ins_keys, fp_keys));
            }
        }
    }

    for (HashScheme hs : hs_pim_vals) {
        for (uint64_t m : m_vals) {
            for (double load : load_vals) {
                uint64_t n = (uint64_t)std::round(load * (double)m);
                std::vector<uint64_t> ins_keys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                std::vector<uint64_t> fp_keys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));
                {
                    PimCuckooFilterV3 bf(m, n, hs, false);
                    printRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runPimBench(&bf, ins_keys, fp_keys));
                }

                {
                    PimCuckooFilterV3 bf(m, n, hs, true);
                    printRow(hashSchemeName(hs), bf.name(), m, 0, load, n, runPimBenchV4(&bf, ins_keys, fp_keys));
                }
            }
        }
    }


    std::cout << "\n";
    runCuckooDeleteExperiments();

    pimDeleteDevice();
    return 0;
}
