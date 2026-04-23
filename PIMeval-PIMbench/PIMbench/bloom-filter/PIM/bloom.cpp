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


// ---- hash schemes ----
// swap out ACTIVE_HS below to change the hash function for all three variants

enum class HashScheme {
    MULTIPLICATIVE,       // current baseline: (key * A_i) >> shift
    KIRSCH_MITZENMACHER,  // double hashing: h1 + i*h2, only two base hashes needed
    MURMUR3,              // 32-bit murmur3 finalizer, cpu-only (pim falls back to v2 style)
    XOR_SHIFT,            // pure xor/shift, no multiplication, pim-native
    H3,                   // universal hashing via lookup table, cpu-only
    FIVE_CYCLE            // 5-step: xor, shift, mul, shift, mul — pim-native
};

static const char* hashSchemeName(HashScheme hs) {
    switch (hs) {
        case HashScheme::MULTIPLICATIVE:      return "multiplicative";
        case HashScheme::KIRSCH_MITZENMACHER: return "kirsch-mitz";
        case HashScheme::MURMUR3:             return "murmur3";
        case HashScheme::XOR_SHIFT:           return "xor-shift";
        case HashScheme::H3:                  return "h3";
        case HashScheme::FIVE_CYCLE:          return "five-cycle";
    }
    return "?";
}

// murmur3 and h3 hash on cpu — pim variants fall back to v2-style mask
static bool isCpuHashScheme(HashScheme hs) {
    return hs == HashScheme::MURMUR3 || hs == HashScheme::H3;
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

// golden ratio constant - closest odd integer to 2^64 / phi
// s = s * 9803400178671478987ULL | 1ULL;  // alt phi approximation
// static constexpr uint64_t PHI64 = 11400714819323198486ULL;  // even variant (wrong)
static constexpr uint64_t PHI64 = 11400714819323198485ULL;

static uint64_t kHashConst[MAX_K];
static uint64_t XS_SALT[MAX_K];        // per-function salts for xor-shift scheme
static uint64_t h3Tab[MAX_K][8][256];  // h3 table: [hash_fn][byte_position][byte_value]

static void initHashConsts() {
    for (int i = 0; i < MAX_K; i++)
        kHashConst[i] = ((uint64_t)(i + 1) * PHI64) | 1ULL;

    // xor-shift salts — distinct odd values derived from a separate lcg
    LCG saltLcg(0xABCDEF1234567890ULL);
    for (int i = 0; i < MAX_K; i++)
        XS_SALT[i] = saltLcg.next() | 1ULL;

    // h3 table — random 64-bit values, one per (hash_fn, byte_pos, byte_val) triple
    LCG h3Lcg(0xFEEDFACEDEADBABEULL);
    for (int i = 0; i < MAX_K; i++)
        for (int b = 0; b < 8; b++)
            for (int v = 0; v < 256; v++)
                h3Tab[i][b][v] = h3Lcg.next();
}

// cpu dispatch: returns index in [0, m) for key under hash function i
static inline uint64_t computeCpuIndex(uint64_t key, int i, unsigned shift, uint64_t mask, HashScheme hs) {
    switch (hs) {
        case HashScheme::MULTIPLICATIVE:
            return (key * kHashConst[i]) >> shift;

        case HashScheme::KIRSCH_MITZENMACHER: {
            uint64_t h1 = (key * kHashConst[0]) >> shift;
            uint64_t h2 = ((key * kHashConst[1]) >> shift) | 1;  // force non-zero step
            return (h1 + (uint64_t)i * h2) & mask;
        }

        case HashScheme::MURMUR3: {
            // 32-bit murmur3 finalizer seeded per hash function i
            uint32_t h = (uint32_t)((key >> 32) ^ (uint32_t)key) + (uint32_t)i * 2654435761u;
            h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13;
            h *= 0xc2b2ae35u; h ^= h >> 16;
            return ((uint64_t)h * (mask + 1)) >> 32;
        }

        case HashScheme::XOR_SHIFT: {
            // pure xor/shift — no multiplication at all
            uint64_t h = key ^ XS_SALT[i];
            h ^= h >> 33;
            h ^= h << 21;
            h ^= h >> 43;
            return h >> shift;
        }

        case HashScheme::H3: {
            // byte-at-a-time universal hash: xor table entries for each input byte
            uint64_t h = 0;
            for (int b = 0; b < 8; b++)
                h ^= h3Tab[i][b][(uint8_t)(key >> (8 * b))];
            return h >> shift;
        }

        case HashScheme::FIVE_CYCLE: {
            // 5-step pipeline: xor, fold, mul, fold, mul
            uint64_t h = key ^ kHashConst[i];
            h ^= h >> 33;
            h *= 0xff51afd7ed558ccdULL;
            h ^= h >> 33;
            h *= 0xc4ceb9fe1a85ec53ULL;
            return h >> shift;
        }
    }
    return 0;
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
    CpuBloomFilter(uint64_t m, int k, HashScheme hs) : m_(m), k_(k), hs_(hs), shift_((unsigned)(64 - __builtin_ctzll(m))), mask_(m - 1), bits_(m, 0) {}

    void batchInsert(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++)
                bits_[computeCpuIndex(key, i, shift_, mask_, hs_)] = 1;
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        out.resize(keys.size());

        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = bits_[computeCpuIndex(keys[j], i, shift_, mask_, hs_)] != 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "cpu"; }

private:
    uint64_t m_;
    int k_;
    HashScheme hs_;
    unsigned shift_;
    uint64_t mask_;
    std::vector<uint8_t> bits_;
};


class PimBloomFilterV2 : public BloomFilter {
public:
    PimBloomFilterV2(uint64_t m, int k, HashScheme hs) : m_(m), k_(k), hs_(hs), shift_((unsigned)(64 - __builtin_ctzll(m))), mask_(m - 1), cpuMask_(m, 0), hostBits_(m, 0) {
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
        std::fill(cpuMask_.begin(), cpuMask_.end(), 0);

        // hash all keys into the mask on cpu, then send to pim as one block
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++)
                cpuMask_[computeCpuIndex(key, i, shift_, mask_, hs_)] = 1;

        assert(pimCopyHostToDevice((void*)cpuMask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyDeviceToHost(bitsObj_, (void*)hostBits_.data()) == PIM_OK);
        out.resize(keys.size());

        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = hostBits_[computeCpuIndex(keys[j], i, shift_, mask_, hs_)] != 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "pim-v2"; }

private:
    uint64_t m_;
    int k_;
    HashScheme hs_;
    unsigned shift_;
    uint64_t mask_;
    PimObjId bitsObj_, maskObj_;
    std::vector<uint8_t> cpuMask_, hostBits_;
};


class PimBloomFilterV3 : public BloomFilter {
public:
    PimBloomFilterV3(uint64_t m, int k, uint64_t n, HashScheme hs)
        : m_(m), n_(n), k_(k), hs_(hs), shift_((unsigned)(64 - __builtin_ctzll(m))),
          mask_(m - 1), cpuMask_(m, 0), hostBits_(m, 0), hostIdx_(n) {

        bitsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT8);
        assert(bitsObj_ != -1);
        maskObj_ = pimAllocAssociated(bitsObj_, PIM_UINT8);
        assert(maskObj_ != -1);

        keysObj_ = pimAlloc(PIM_ALLOC_AUTO, n, PIM_UINT64);
        assert(keysObj_ != -1);
        tempObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(tempObj_ != -1);
        workObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(workObj_ != -1);

        // kirsch-mitzenmacher precomputes h1 and h2 — needs two extra pim arrays
        if (hs_ == HashScheme::KIRSCH_MITZENMACHER) {
            h1Obj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
            assert(h1Obj_ != -1);
            h2Obj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
            assert(h2Obj_ != -1);
        } else {
            h1Obj_ = h2Obj_ = -1;
        }

        std::vector<uint8_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bitsObj_) == PIM_OK);
    }

    ~PimBloomFilterV3() {
        pimFree(bitsObj_); pimFree(maskObj_);
        pimFree(keysObj_); pimFree(tempObj_); pimFree(workObj_);
        if (h1Obj_ != -1) pimFree(h1Obj_);
        if (h2Obj_ != -1) pimFree(h2Obj_);
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        std::fill(cpuMask_.begin(), cpuMask_.end(), 0);

        if (isCpuHashScheme(hs_)) {
            // cpu-only schemes: build mask on host, bulk push to pim (same as v2)
            for (uint64_t key : keys)
                for (int i = 0; i < k_; i++)
                    cpuMask_[computeCpuIndex(key, i, shift_, mask_, hs_)] = 1;
            assert(pimCopyHostToDevice((void*)cpuMask_.data(), maskObj_) == PIM_OK);
            assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
            return;
        }

        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);

        switch (hs_) {
            case HashScheme::MULTIPLICATIVE:      pimInsertMultiplicative(); break;
            case HashScheme::KIRSCH_MITZENMACHER: pimInsertKirschMitz();     break;
            case HashScheme::XOR_SHIFT:           pimInsertXorShift();       break;
            case HashScheme::FIVE_CYCLE:          pimInsertFiveCycle();      break;
            default: break;
        }
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyDeviceToHost(bitsObj_, (void*)hostBits_.data()) == PIM_OK);

        if (isCpuHashScheme(hs_)) {
            out.resize(keys.size());
            for (size_t j = 0; j < keys.size(); j++) {
                bool ok = true;
                for (int i = 0; i < k_ && ok; i++)
                    ok = hostBits_[computeCpuIndex(keys[j], i, shift_, mask_, hs_)] != 0;
                out[j] = ok;
            }
            return;
        }

        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);

        // collect all k index arrays in pim, then check membership on host
        std::vector<std::vector<uint64_t>> allIdx(k_, std::vector<uint64_t>(n_));
        switch (hs_) {
            case HashScheme::MULTIPLICATIVE:      pimQueryMultiplicative(allIdx); break;
            case HashScheme::KIRSCH_MITZENMACHER: pimQueryKirschMitz(allIdx);     break;
            case HashScheme::XOR_SHIFT:           pimQueryXorShift(allIdx);       break;
            case HashScheme::FIVE_CYCLE:          pimQueryFiveCycle(allIdx);      break;
            default: break;
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
    HashScheme hs_;
    unsigned shift_;
    uint64_t mask_;
    PimObjId bitsObj_, maskObj_, keysObj_, tempObj_, workObj_, h1Obj_, h2Obj_;
    std::vector<uint8_t> cpuMask_, hostBits_;
    std::vector<uint64_t> hostIdx_;

    void flushMaskToPim() {
        assert(pimCopyHostToDevice((void*)cpuMask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
    }

    // -- multiplicative: run each hash function in pim via multiply then shift --
    void pimInsertMultiplicative() {
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data()) == PIM_OK);
            for (uint64_t idx : hostIdx_) cpuMask_[idx] = 1;
        }
        flushMaskToPim();
    }

    void pimQueryMultiplicative(std::vector<std::vector<uint64_t>>& allIdx) {
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data()) == PIM_OK);
        }
    }

    // -- kirsch-mitzenmacher: precompute h1 and h2, then combine per-i --
    void pimComputeKM() {
        // h1 = (key * A0) >> shift
        assert(pimMulScalar(keysObj_, h1Obj_, kHashConst[0]) == PIM_OK);
        assert(pimShiftBitsRight(h1Obj_, h1Obj_, shift_) == PIM_OK);
        // h2 = ((key * A1) >> shift) | 1  (step must be non-zero)
        assert(pimMulScalar(keysObj_, h2Obj_, kHashConst[1]) == PIM_OK);
        assert(pimShiftBitsRight(h2Obj_, h2Obj_, shift_) == PIM_OK);
        assert(pimOrScalar(h2Obj_, h2Obj_, 1) == PIM_OK);
    }

    void pimInsertKirschMitz() {
        pimComputeKM();
        for (int i = 0; i < k_; i++) {
            if (i == 0) {
                assert(pimCopyDeviceToHost(h1Obj_, (void*)hostIdx_.data()) == PIM_OK);
            } else {
                // workObj = h1 + i * h2
                assert(pimCopyObjectToObject(h2Obj_, workObj_) == PIM_OK);
                assert(pimMulScalar(workObj_, workObj_, (uint64_t)i) == PIM_OK);
                assert(pimAdd(h1Obj_, workObj_, workObj_) == PIM_OK);
                assert(pimAndScalar(workObj_, workObj_, mask_) == PIM_OK);
                assert(pimCopyDeviceToHost(workObj_, (void*)hostIdx_.data()) == PIM_OK);
            }
            for (uint64_t idx : hostIdx_) cpuMask_[idx] = 1;
        }
        flushMaskToPim();
    }

    void pimQueryKirschMitz(std::vector<std::vector<uint64_t>>& allIdx) {
        pimComputeKM();
        for (int i = 0; i < k_; i++) {
            if (i == 0) {
                assert(pimCopyDeviceToHost(h1Obj_, (void*)allIdx[0].data()) == PIM_OK);
            } else {
                assert(pimCopyObjectToObject(h2Obj_, workObj_) == PIM_OK);
                assert(pimMulScalar(workObj_, workObj_, (uint64_t)i) == PIM_OK);
                assert(pimAdd(h1Obj_, workObj_, workObj_) == PIM_OK);
                assert(pimAndScalar(workObj_, workObj_, mask_) == PIM_OK);
                assert(pimCopyDeviceToHost(workObj_, (void*)allIdx[i].data()) == PIM_OK);
            }
        }
    }

    // -- xor-shift: key ^ salt, then three xor-shift steps, no multiplication --
    void pimComputeXS(int i) {
        assert(pimXorScalar(keysObj_, workObj_, XS_SALT[i]) == PIM_OK);        // h = key ^ salt
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);                // h ^= h >> 33
        assert(pimShiftBitsLeft(workObj_, tempObj_, 21) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);                // h ^= h << 21
        assert(pimShiftBitsRight(workObj_, tempObj_, 43) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);                // h ^= h >> 43
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);       // index = h >> shift
    }

    void pimInsertXorShift() {
        for (int i = 0; i < k_; i++) {
            pimComputeXS(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data()) == PIM_OK);
            for (uint64_t idx : hostIdx_) cpuMask_[idx] = 1;
        }
        flushMaskToPim();
    }

    void pimQueryXorShift(std::vector<std::vector<uint64_t>>& allIdx) {
        for (int i = 0; i < k_; i++) {
            pimComputeXS(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data()) == PIM_OK);
        }
    }

    // -- five-cycle: xor seed, fold, mul, fold, mul (5 steps total, pim-native) --
    void pimComputeFC(int i) {
        assert(pimXorScalar(keysObj_, workObj_, kHashConst[i]) == PIM_OK);     // h = key ^ A_i
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);                // h ^= h >> 33
        assert(pimMulScalar(workObj_, workObj_, 0xff51afd7ed558ccdULL) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);                // h ^= h >> 33
        assert(pimMulScalar(workObj_, workObj_, 0xc4ceb9fe1a85ec53ULL) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);       // index = h >> shift
    }

    void pimInsertFiveCycle() {
        for (int i = 0; i < k_; i++) {
            pimComputeFC(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data()) == PIM_OK);
            for (uint64_t idx : hostIdx_) cpuMask_[idx] = 1;
        }
        flushMaskToPim();
    }

    void pimQueryFiveCycle(std::vector<std::vector<uint64_t>>& allIdx) {
        for (int i = 0; i < k_; i++) {
            pimComputeFC(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data()) == PIM_OK);
        }
    }
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

    // hash schemes to sweep — comment out entries to skip
    static const HashScheme hsVals[] = {
        HashScheme::MULTIPLICATIVE,
        HashScheme::KIRSCH_MITZENMACHER,
        HashScheme::MURMUR3,
        HashScheme::XOR_SHIFT,
        HashScheme::H3,
        HashScheme::FIVE_CYCLE,
    };

    uint64_t maxN = (uint64_t)std::round(0.25 * (double)(1ULL << 26));
    std::vector<uint64_t> allKeys(2 * maxN);

    LCG lcg(0xDEADBEEFCAFEBABEULL);
    for (auto& key : allKeys) key = lcg.next();

    auto printRow = [](const std::string& hs, const std::string& variant, uint64_t m, int k, double load, uint64_t n, const BenchMetrics& bm) {
        std::cout << std::fixed
                  << hs << ","
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

    std::cout << "hash_scheme,variant,m,k,load_factor,n,"
                 "insert_throughput_eps,query_throughput_eps,"
                 "fpr,insert_energy_mj,query_energy_mj\n";
    std::cout.flush();

    // cpu variants — no pim device needed
    for (HashScheme hs : hsVals) {
        for (uint64_t m : mVals) {
            for (int k : kVals) {
                for (double load : loadVals) {
                    uint64_t n = (uint64_t)std::round(load * (double)m);

                    std::vector<uint64_t> insKeys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                    std::vector<uint64_t> fpKeys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                    CpuBloomFilter bf(m, k, hs);
                    printRow(hashSchemeName(hs), "cpu", m, k, load, n, runCpuBench(&bf, insKeys, fpKeys));
                }
            }
        }
    }

    assert(pimCreateDevice(PIM_DEVICE_BANK_LEVEL, 4, 128, 32, 1024, 8192) == PIM_OK);

    for (HashScheme hs : hsVals) {
        for (int v = 2; v <= 3; v++) {
            for (uint64_t m : mVals) {
                for (int k : kVals) {
                    for (double load : loadVals) {
                        uint64_t n = (uint64_t)std::round(load * (double)m);

                        std::vector<uint64_t> insKeys(allKeys.begin(), allKeys.begin() + (ptrdiff_t)n);
                        std::vector<uint64_t> fpKeys(allKeys.begin() + (ptrdiff_t)n, allKeys.begin() + (ptrdiff_t)(2 * n));

                        BloomFilter* bf = (v == 2)
                            ? (BloomFilter*)new PimBloomFilterV2(m, k, hs)
                            : (BloomFilter*)new PimBloomFilterV3(m, k, n, hs);

                        printRow(hashSchemeName(hs), (v == 2) ? "pim-v2" : "pim-v3", m, k, load, n, runPimBench(bf, insKeys, fpKeys));

                        delete bf;
                    }
                }
            }
        }
    }

    pimDeleteDevice();
    return 0;
}
