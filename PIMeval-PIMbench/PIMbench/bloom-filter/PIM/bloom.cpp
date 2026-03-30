#include "util.h"
#include "libpimeval.h"
#include <vector>
#include <cstdint>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>

using Clock = std::chrono::high_resolution_clock;

struct PimOpStats {
    double copyMs = 0.0;
    double copyMj = 0.0;
    double cmdMs = 0.0;
    double cmdMj = 0.0;

    double totalMs() const { return copyMs + cmdMs; }
    double totalMj() const { return copyMj + cmdMj; }

    PimOpStats operator-(const PimOpStats& o) const {
        return { copyMs - o.copyMs, copyMj - o.copyMj, cmdMs, cmdMj };
    }
};

static PimOpStats parsePimStats(const std::string& s) {
    PimOpStats r;
    std::istringstream ss(s);
    std::string line;

    while (std::getline(ss, line)) {
        if (line.find("TOTAL ---------") == std::string::npos) continue;

        if (line.find("Estimated Runtime") != std::string::npos) {
            unsigned long long bytes;
            double rt, en;
            if (sscanf(line.c_str(),
                       " TOTAL --------- : %llu bytes %lf ms Estimated Runtime %lf mj Estimated Energy",
                       &bytes, &rt, &en) == 3) {
                r.copyMs = rt;
                r.copyMj = en;
            }
        } else if (line.find("PIM-CMD") == std::string::npos) {
            int cnt;
            double rt, en;
            if (sscanf(line.c_str(), " TOTAL --------- : %d %lf %lf", &cnt, &rt, &en) == 3) {
                r.cmdMs = rt;
                r.cmdMj = en;
            }
        }
    }
    return r;
}

static PimOpStats capturePimStats() {
    int pipefd[2];
    if (pipe(pipefd) != 0) return {};

    int saved = dup(STDOUT_FILENO);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    pimShowStats();
    fflush(stdout);

    dup2(saved, STDOUT_FILENO);
    close(saved);

    std::string out;
    char buf[8192];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        out += buf;
    }

    close(pipefd[0]);
    return parsePimStats(out);
}


struct LCG {
    uint64_t s;
    explicit LCG(uint64_t seed) : s(seed) {}

    uint64_t next() {
        // s = s * 7364136243846793005ULL + 1042695340884963407ULL;
        // s = s * 2862933555777941757ULL + 3037000493ULL;
        // s = s * 6364136223846793005ULL + 1ULL;
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s;
    }
};


static constexpr int MAX_K = 10;

// golden ratio constant - its the closest odd integer to 2^64 / phi
// s = s * 9803400178671478987ULL | 1ULL;  // alt phi approximation
// static constexpr uint64_t PHI64 = 11400714819323198486ULL;  // even variant (wrong)
static constexpr uint64_t PHI64 = 11400714819323198485ULL;

static uint64_t kHashConst[MAX_K];

static void initHashConsts() {
    for (int i = 0; i < MAX_K; i++)
        kHashConst[i] = ((uint64_t)(i + 1) * PHI64) | 1ULL;
}


class BloomFilter {
public:
    virtual ~BloomFilter() = default;
    virtual void batchInsert(const std::vector<uint64_t>& keys) = 0;
    virtual void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) = 0;
    virtual const char* name() const = 0;
};


class CpuBloomFilter : public BloomFilter {
public:
    CpuBloomFilter(uint64_t m, int k) : m_(m), k_(k), shift_((unsigned)(64 - __builtin_ctzll(m))), bits_(m, 0) {}

    void batchInsert(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++)
                bits_[(key * kHashConst[i]) >> shift_] = 1;
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        out.resize(keys.size());

        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = bits_[(keys[j] * kHashConst[i]) >> shift_] != 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "cpu"; }

private:
    uint64_t m_;
    int k_;
    unsigned shift_;
    std::vector<uint8_t> bits_;
};


class PimBloomFilterV2 : public BloomFilter {
public:
    PimBloomFilterV2(uint64_t m, int k) : m_(m), k_(k), shift_((unsigned)(64 - __builtin_ctzll(m))), mask_(m, 0), hostBits_(m, 0) {
        bitsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT8);
        assert(bitsObj_ != -1);
        maskObj_ = pimAllocAssociated(bitsObj_, PIM_UINT8);
        assert(maskObj_ != -1);

        std::vector<uint8_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bitsObj_) == PIM_OK);
    }

    ~PimBloomFilterV2() {
        pimFree(bitsObj_);
        pimFree(maskObj_);
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        std::fill(mask_.begin(), mask_.end(), 0);

        // hash all keys into the mask on cpu, then send to pim as one block
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++)
                mask_[(key * kHashConst[i]) >> shift_] = 1;

        assert(pimCopyHostToDevice((void*)mask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyDeviceToHost(bitsObj_, (void*)hostBits_.data()) == PIM_OK);
        out.resize(keys.size());

        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = hostBits_[(keys[j] * kHashConst[i]) >> shift_] != 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "pim-v2"; }

private:
    uint64_t m_;
    int k_;
    unsigned shift_;
    PimObjId bitsObj_, maskObj_;
    std::vector<uint8_t> mask_, hostBits_;
};


class PimBloomFilterV3 : public BloomFilter {
public:
    PimBloomFilterV3(uint64_t m, int k, uint64_t n)
        : m_(m), n_(n), k_(k), shift_((unsigned)(64 - __builtin_ctzll(m))),
          mask_(m, 0), hostBits_(m, 0), hostIdx_(n) {
        bitsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT8);
        assert(bitsObj_ != -1);
        maskObj_ = pimAllocAssociated(bitsObj_, PIM_UINT8);
        assert(maskObj_ != -1);

        keysObj_ = pimAlloc(PIM_ALLOC_AUTO, n, PIM_UINT64);
        assert(keysObj_ != -1);
        tempObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(tempObj_ != -1);

        std::vector<uint8_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bitsObj_) == PIM_OK);
    }

    ~PimBloomFilterV3() {
        pimFree(bitsObj_);
        pimFree(maskObj_);
        pimFree(keysObj_);
        pimFree(tempObj_);
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);
        std::fill(mask_.begin(), mask_.end(), 0);

        // run each hash function in pim: multiply then shift to get indices
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data()) == PIM_OK);

            for (uint64_t idx : hostIdx_)
                mask_[idx] = 1;
        }

        assert(pimCopyHostToDevice((void*)mask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);
        assert(pimCopyDeviceToHost(bitsObj_, (void*)hostBits_.data()) == PIM_OK);

        // collect all k index arrays before checking membership
        std::vector<std::vector<uint64_t>> allIdx(k_, std::vector<uint64_t>(n_));
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data()) == PIM_OK);
        }

        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = hostBits_[allIdx[i][j]] != 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "pim-v3"; }

private:
    uint64_t m_, n_;
    int k_;
    unsigned shift_;
    PimObjId bitsObj_, maskObj_, keysObj_, tempObj_;
    std::vector<uint8_t> mask_, hostBits_;
    std::vector<uint64_t> hostIdx_;
};


struct BenchMetrics {
    double insertMs;
    double queryMs;
    double insertMj;
    double queryMj;
    double fpr;

    double insertThroughput() const { return insertMs > 0 ? (1000.0 / insertMs) : 0; }
    double queryThroughput() const { return queryMs > 0 ? (1000.0 / queryMs) : 0; }
};


static BenchMetrics runCpuBench(BloomFilter* bf, const std::vector<uint64_t>& insertKeys, const std::vector<uint64_t>& fpKeys) {
    auto t0 = Clock::now();
    bf->batchInsert(insertKeys);
    auto t1 = Clock::now();

    std::vector<bool> q1;
    auto t2 = Clock::now();
    bf->batchQuery(insertKeys, q1);
    auto t3 = Clock::now();

    for (bool b : q1) assert(b);

    std::vector<bool> Q2;
    bf->batchQuery(fpKeys, Q2);
    uint64_t fp = 0;
    for (bool b : Q2) fp += b ? 1 : 0;

    double n = (double)insertKeys.size();
    double insertMs = std::chrono::duration<double>(t1 - t0).count() * 1000.0;
    double QueryMs = std::chrono::duration<double>(t3 - t2).count() * 1000.0;

    return { insertMs / n, QueryMs / n, 0.0, 0.0, (double)fp / (double)fpKeys.size() };
}

static BenchMetrics runPimBench(BloomFilter* bf, const std::vector<uint64_t>& insertKeys, const std::vector<uint64_t>& fpKeys) {
    double n = (double)insertKeys.size();

    // snapshot stats before insert, reset, run, snapshot again
    PimOpStats s0 = capturePimStats();
    pimResetStats();
    bf->batchInsert(insertKeys);
    PimOpStats s1 = capturePimStats();

    std::vector<bool> q1;
    pimResetStats();
    bf->batchQuery(insertKeys, q1);
    PimOpStats S2 = capturePimStats();

    for (bool b : q1) 
        assert(b);

    std::vector<bool> q2;
    bf->batchQuery(fpKeys, q2);
    uint64_t Fp = 0;
    for (bool b : q2) Fp += b ? 1 : 0;

    PimOpStats ins = s1 - s0;
    PimOpStats qry = S2 - s1;

    return { ins.totalMs() / n, qry.totalMs() / n,
             ins.totalMj(), qry.totalMj(),
             (double)Fp / (double)fpKeys.size() };
}


int main() {
    initHashConsts();

    // sweep params
    // static const uint64_t mVals[] = {1ULL << 20, 1ULL << 23};  // smaller sweep for testing
    static const uint64_t mVals[] = {1ULL << 20, 1ULL << 23, 1ULL << 26};
    static const int kVals[] = {3, 5, 7};
    // static const double loadVals[] = {0.125, 0.25};  // reduced load sweep
    static const double loadVals[] = {0.0625, 0.125, 0.25};

    uint64_t maxN = (uint64_t)std::round(0.25 * (double)(1ULL << 26));
    std::vector<uint64_t> allKeys(2 * maxN);

    LCG lcg(0xDEADBEEFCAFEBABEULL);
    for (auto& key : allKeys) key = lcg.next();

    auto printRow = [](const std::string& variant, uint64_t m, int k, double load, uint64_t n, const BenchMetrics& bm) {
        std::cout << std::fixed
                  << variant << ","
                  << m << ","
                  << k << ","
                  << std::setprecision(4) << load << ","
                  << n << ","
                  << std::setprecision(2) << bm.insertThroughput() << ","
                  << bm.queryThroughput() << ","
                  << std::setprecision(6) << bm.fpr << ","
                  << std::setprecision(4) << bm.insertMj << ","
                  << bm.queryMj << "\n";
        std::cout.flush();
    };

    std::cout << "variant,m,k,load_factor,n,"
                 "insert_throughput_eps,query_throughput_eps,"
                 "fpr,insert_energy_mj,query_energy_mj\n";
    std::cout.flush();

    for (uint64_t m : mVals) {
        for (int k : kVals) {
            for (double load : loadVals) {
                uint64_t n = (uint64_t)std::round(load * (double)m);

                std::vector<uint64_t> insKeys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                std::vector<uint64_t> fpKeys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                CpuBloomFilter bf(m, k);
                printRow("cpu", m, k, load, n, runCpuBench(&bf, insKeys, fpKeys));
            }
        }
    }

    assert(pimCreateDevice(PIM_DEVICE_BANK_LEVEL, 4, 128, 32, 1024, 8192) == PIM_OK);

    for (int v = 2; v <= 3; v++) {
        for (uint64_t m : mVals) {
            for (int k : kVals) {
                for (double load : loadVals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);

                    std::vector<uint64_t> insKeys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> fpKeys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                    BloomFilter* bf = (v == 2)
                        ? (BloomFilter*)new PimBloomFilterV2(m, k)
                        : (BloomFilter*)new PimBloomFilterV3(m, k, n);

                    printRow((v == 2) ? "pim-v2" : "pim-v3", m, k, load, n, runPimBench(bf, insKeys, fpKeys));

                    delete bf;
                }
            }
        }
    }

    pimDeleteDevice();
    return 0;
}
