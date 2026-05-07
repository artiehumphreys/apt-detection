#include "bloom_filter.hpp"
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

static std::ofstream gLogFile;

static void sayLine(const std::string& msg) {
    std::cout << msg;
    if (gLogFile.is_open()) gLogFile << msg; // mirror it if asked
}

static void showUsage(const char* prog) {
    std::cerr << "usage: " << prog << " [--log <file>] [--hash <hash>] <logfile> <variant> <m> <k> [seed_pid...]\n";
    std::cerr << "hash: xor-shift | murmur3 | jenkins (default: xor-shift)\n";
    std::cerr << "variant: cpu | pim-v2 | pim-v3 | pim-v4\n";
    std::cerr << "variant: cpu-counting | pim-counting-v2 | pim-counting-v3 | pim-counting-v4\n";
    std::cerr << "variant: cuckoo-cpu | cuckoo-pim-v2 | cuckoo-pim-v3 | cuckoo-pim-v4\n";
    std::cerr << "m: table size (must be power of 2)\n";
    std::cerr << "k: hash functions (bloom/counting only; ignored for cuckoo)\n";
    std::cerr << "seed_pid: optional starting roots\n";
}

static bool isPimVariant(const std::string& variant) {
    return variant == "pim-v2" || variant == "pim-v3" || variant == "pim-v4" || variant == "pim-counting-v2" || variant == "pim-counting-v3" || variant == "pim-counting-v4" || variant == "cuckoo-pim-v2" || variant == "cuckoo-pim-v3" || variant == "cuckoo-pim-v4";
}

static bool usesPimNativeHash(const std::string& variant) {
    return variant == "pim-v3" || variant == "pim-v4" || variant == "pim-counting-v3" || variant == "pim-counting-v4" || variant == "cuckoo-pim-v3" || variant == "cuckoo-pim-v4";
}

static std::unique_ptr<BloomFilter> makeFilter(const std::string& variant, uint64_t m, int k, HashScheme hs) {
    if (variant == "cpu") return std::unique_ptr<BloomFilter>(new CpuBloomFilter(m, k, hs));
    if (variant == "pim-v2") return std::unique_ptr<BloomFilter>(new PimBloomFilterV2(m, k, hs));
    if (variant == "pim-v3") return std::unique_ptr<BloomFilter>(new PimBloomFilterV3(m, k, 1, hs, false));
    if (variant == "pim-v4") return std::unique_ptr<BloomFilter>(new PimBloomFilterV3(m, k, 1, hs, true));
    if (variant == "cpu-counting") return std::unique_ptr<BloomFilter>(new CpuCountingBloomFilter(m, k, hs));
    if (variant == "pim-counting-v2") return std::unique_ptr<BloomFilter>(new PimCountingBloomFilterV2(m, k, hs));
    if (variant == "pim-counting-v3") return std::unique_ptr<BloomFilter>(new PimCountingBloomFilterV3(m, k, 1, hs, false));
    if (variant == "pim-counting-v4") return std::unique_ptr<BloomFilter>(new PimCountingBloomFilterV3(m, k, 1, hs, true));
    if (variant == "cuckoo-cpu") return std::unique_ptr<BloomFilter>(new CpuCuckooFilter(m, hs));
    if (variant == "cuckoo-pim-v2") return std::unique_ptr<BloomFilter>(new PimCuckooFilterV2(m, hs));
    if (variant == "cuckoo-pim-v3") return std::unique_ptr<BloomFilter>(new PimCuckooFilterV3(m, 1, hs, false));
    if (variant == "cuckoo-pim-v4") return std::unique_ptr<BloomFilter>(new PimCuckooFilterV3(m, 1, hs, true));
    return nullptr;
}

struct RootFilter {
    std::unique_ptr<BloomFilter> bf;
    std::unordered_set<uint64_t> seen;
};

int main(int argc, char* argv[]) {
    std::string logOutPath;
    // HashScheme hs = HashScheme::XOR_SHIFT;
    // HashScheme hs = HashScheme::JENKINS;
    // HashScheme hs = HashScheme::MURMUR3;
    HashScheme hs = HashScheme::XOR_SHIFT;
    std::vector<char*> args;

    for (int i = 0; i < argc; i++) { // walk args by hand, its fine
        std::string arg = argv[i];
        if (arg == "--log" && i + 1 < argc) {
            logOutPath = argv[++i];
        } else if (arg == "--hash" && i + 1 < argc) {
            try {
                hs = parseHashSchemeName(argv[++i]);
            } catch (const std::invalid_argument& e) {
                std::cerr << "error: " << e.what() << "\n";
                showUsage(argv[0]);
                return 1;
            }
        } else {
            args.push_back(argv[i]);
        }
    }

    if ((int)args.size() < 5) {
        showUsage(args[0]);
        return 1;
    }

    if (!logOutPath.empty()) {
        gLogFile.open(logOutPath);
        if (!gLogFile.is_open()) {
            std::cerr << "error: cannot open log output file '" << logOutPath << "'\n";
            return 1;
        }
    }

    const std::string eventFile = args[1];
    const std::string variant = args[2];
    uint64_t m = (uint64_t)std::stoull(args[3]);
    int k = std::stoi(args[4]);

    std::vector<uint64_t> seeds;
    for (int i = 5; i < (int)args.size(); i++)
        seeds.push_back((uint64_t)std::stoull(args[i])); // turn roots into nums

    if (m == 0 || (m & (m - 1)) != 0) {
        std::cerr << "error: m must be a power of 2\n";
        return 1;
    }
    if (k < 1 || k > MAX_K) {
        std::cerr << "error: k must be in [1, " << MAX_K << "]\n";
        return 1;
    }
    if (!isSupportedCpuHashScheme(hs)) {
        std::cerr << "error: supported cpu hashes are xor-shift, murmur3, jenkins\n";
        return 1;
    }
    if (usesPimNativeHash(variant) && !isSupportedPimHashScheme(hs)) {
        std::cerr << "error: pim-native hash variants support xor-shift and jenkins only\n";
        return 1;
    }

    initHashConsts();

    bool usePim = isPimVariant(variant);
    if (usePim)
        assert(pimCreateDevice(PIM_DEVICE_BANK_LEVEL, 4, 128, 32, 1024, 8192) == PIM_OK);

    std::unique_ptr<BloomFilter> trial = makeFilter(variant, m, k, hs);
    if (!trial) {
        std::cerr << "error: unknown variant '" << variant << "'\n";
        showUsage(args[0]);
        if (usePim) pimDeleteDevice();
        return 1;
    }

    std::vector<RootFilter> filters;
    // filters.reserve(seeds.size() + 2);
    // filters.reserve(seeds.size() + 32);
    filters.reserve(seeds.size() + 8);

    auto startFilter = [&](uint64_t root_pid) {
        RootFilter st;
        st.bf = makeFilter(variant, m, k, hs);
        assert(st.bf);
        st.bf->batchInsert({root_pid});
        st.seen.insert(root_pid);
        filters.push_back(std::move(st));
    };

    for (uint64_t seed : seeds) startFilter(seed); // seed the first batch
    trial.reset();

    std::ifstream log(eventFile);
    if (!log.is_open()) {
        std::cerr << "error: cannot open '" << eventFile << "'\n";
        filters.clear();
        if (usePim) pimDeleteDevice();
        return 1;
    }

    uint64_t totalEvents = 0;
    uint64_t totalAlerts = 0;
    uint64_t totalInserted = (uint64_t)seeds.size();
    uint64_t filtersStarted = (uint64_t)filters.size();

    std::string line;
    while (std::getline(log, line)) {
        if (line.empty()) continue; // skip blank lines quick

        for (char& ch : line)
            if (ch == ',') ch = ' '; // commas just get in the way here

        uint64_t pid, ppid, isTarget;
        std::istringstream row(line);
        if (!(row >> pid >> ppid >> isTarget)) continue;

        totalEvents++;

        if (ppid == 0) {
            startFilter(pid);
            totalInserted++;
            filtersStarted++;
            continue;
        }

        std::vector<size_t> exactHits;
        std::vector<size_t> bloomHits;
        for (size_t i = 0; i < filters.size(); i++) {
            std::vector<bool> result;
            filters[i].bf->batchQuery({ppid}, result);
            if (result[0]) bloomHits.push_back(i);
            if (filters[i].seen.find(ppid) != filters[i].seen.end()) exactHits.push_back(i);
        }

        if (!bloomHits.empty()) {
            // pass it forward, dont overthink it
            // const std::vector<size_t>& destinations = bloomHits;
            const std::vector<size_t>& destinations = exactHits.empty() ? bloomHits : exactHits;
            for (size_t idx : destinations) {
                filters[idx].bf->batchInsert({pid});
                filters[idx].seen.insert(pid);
                totalInserted++;
            }

            if (isTarget) {
                sayLine("ALERT " + std::to_string(pid) + " " + std::to_string(ppid) + "\n");
                totalAlerts++;
            }
        }
    }

    sayLine("\n");
    sayLine("variant: " + std::string(filters.empty() ? variant : filters[0].bf->name()) + "\n");
    sayLine("hash_scheme: " + std::string(hashSchemeName(hs)) + "\n");
    sayLine("events processed: " + std::to_string(totalEvents) + "\n");
    sayLine("alerts fired: " + std::to_string(totalAlerts) + "\n");
    sayLine("pids inserted: " + std::to_string(totalInserted) + "\n");
    sayLine("filters spawned: " + std::to_string(filtersStarted) + "\n");

    filters.clear();
    if (usePim) pimDeleteDevice();
    return 0;
}
