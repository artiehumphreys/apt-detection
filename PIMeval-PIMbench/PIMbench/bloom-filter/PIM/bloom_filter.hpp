#pragma once

#include "util.h"
#include "libpimeval.h"
#include <vector>
#include <cstdint>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <stdexcept>
#include <unordered_set>
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

inline PimOpStats parsePimStats(const std::string& s) {
    PimOpStats r;
    std::istringstream ss(s);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.find("TOTAL ---------") == std::string::npos) continue;
        if (line.find("Estimated Runtime") != std::string::npos) {
            unsigned long long bytes; double rt, en;
            if (sscanf(line.c_str(),
                       " TOTAL --------- : %llu bytes %lf ms Estimated Runtime %lf mj Estimated Energy",
                       &bytes, &rt, &en) == 3) { r.copyMs = rt; r.copyMj = en; }
        } else if (line.find("PIM-CMD") == std::string::npos) {
            int cnt; double rt, en;
            if (sscanf(line.c_str(), " TOTAL --------- : %d %lf %lf", &cnt, &rt, &en) == 3) {
                r.cmdMs = rt; r.cmdMj = en;
            }
        }
    }
    return r;
}

inline PimOpStats capturePimStats() {
    std::cout.flush();
    fflush(stdout);

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
    while ((n = read(pipefd[0], buf, sizeof(buf) - 1)) > 0) { buf[n] = '\0'; out += buf; }
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


enum class HashScheme {
    MULTIPLICATIVE,
    KIRSCH_MITZENMACHER,
    MURMUR3,
    XOR_SHIFT,
    H3,
    FIVE_CYCLE,
    JENKINS
};

inline const char* hashSchemeName(HashScheme hs) {
    switch (hs) {
        case HashScheme::MULTIPLICATIVE: return "multiplicative";
        case HashScheme::KIRSCH_MITZENMACHER: return "kirsch-mitz";
        case HashScheme::MURMUR3: return "murmur3";
        case HashScheme::XOR_SHIFT: return "xor-shift";
        case HashScheme::H3: return "h3";
        case HashScheme::FIVE_CYCLE: return "five-cycle";
        case HashScheme::JENKINS: return "jenkins";
    }
    return "?";
}

inline bool isCpuHashScheme(HashScheme hs) {
    return hs == HashScheme::MURMUR3 || hs == HashScheme::H3;
}

inline bool isSupportedCpuHashScheme(HashScheme hs) {
    return hs == HashScheme::XOR_SHIFT || hs == HashScheme::MURMUR3 || hs == HashScheme::JENKINS;
}

inline bool isSupportedPimHashScheme(HashScheme hs) {
    return hs == HashScheme::XOR_SHIFT || hs == HashScheme::JENKINS;
}

inline HashScheme parseHashSchemeName(const std::string& s) {
    if (s == "xor-shift" || s == "xorshift") return HashScheme::XOR_SHIFT; // let both spellings work
    if (s == "murmur3") return HashScheme::MURMUR3;
    if (s == "jenkins") return HashScheme::JENKINS;
    throw std::invalid_argument("unsupported hash scheme: " + s);
}


// static constexpr int MAX_K = 6;
// static constexpr int MAX_K = 8;
static constexpr int MAX_K = 10; // dont crowd this one

// static constexpr uint64_t PHI64 = 9803400178671478987ULL;
// static constexpr uint64_t PHI64 = 11400714819323198486ULL;
static constexpr uint64_t PHI64 = 11400714819323198485ULL;

static uint64_t kHashConst[MAX_K];
static uint64_t XS_SALT[MAX_K];
static uint64_t h3Tab[MAX_K][8][256];

inline void initHashConsts() {
    for (int i = 0; i < MAX_K; i++)
        kHashConst[i] = ((uint64_t)(i + 1) * PHI64) | 1ULL;

    LCG saltLcg(0xABCDEF1234567890ULL);
    for (int i = 0; i < MAX_K; i++)
        XS_SALT[i] = saltLcg.next() | 1ULL;

    LCG h3Lcg(0xFEEDFACEDEADBABEULL);
    for (int i = 0; i < MAX_K; i++)
        for (int b = 0; b < 8; b++)
            for (int v = 0; v < 256; v++)
                h3Tab[i][b][v] = h3Lcg.next();
}

inline uint64_t computeCpuIndex(uint64_t key, int i, unsigned shift, uint64_t mask, HashScheme hs) {
    switch (hs) {
        case HashScheme::MULTIPLICATIVE:
            return (key * kHashConst[i]) >> shift;

        case HashScheme::KIRSCH_MITZENMACHER: {
            uint64_t h1 = (key * kHashConst[0]) >> shift;
            uint64_t h2 = ((key * kHashConst[1]) >> shift) | 1;
            return (h1 + (uint64_t)i * h2) & mask;
        }

        case HashScheme::MURMUR3: {
            uint32_t h = (uint32_t)((key >> 32) ^ (uint32_t)key) + (uint32_t)i * 2654435761u;
            h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13;
            h *= 0xc2b2ae35u; h ^= h >> 16;
            return ((uint64_t)h * (mask + 1)) >> 32;
        }

        case HashScheme::XOR_SHIFT: {
            uint64_t h = key ^ XS_SALT[i];
            h ^= h >> 33;
            h ^= h << 21;
            h ^= h >> 43;
            return h >> shift;
        }

        case HashScheme::H3: {
            uint64_t h = 0;
            for (int b = 0; b < 8; b++)
                h ^= h3Tab[i][b][(uint8_t)(key >> (8 * b))];
            return h >> shift;
        }

        case HashScheme::FIVE_CYCLE: {
            uint64_t h = key ^ kHashConst[i];
            h ^= h >> 33;
            h *= 0xff51afd7ed558ccdULL;
            h ^= h >> 33;
            h *= 0xc4ceb9fe1a85ec53ULL;
            return h >> shift;
        }

        case HashScheme::JENKINS: {
            uint64_t h = key ^ kHashConst[i];
            h += h << 10;
            h ^= h >> 6;
            h += h << 3;
            h ^= h >> 11;
            h += h << 15;
            h ^= h >> 16;
            h += h << 5;
            h ^= h >> 12;
            return h >> shift;
        }
    }
    return 0;
}

inline uint64_t computeCpuHashValue(uint64_t key, int i, HashScheme hs) {
    switch (hs) {
        case HashScheme::MURMUR3: {
            uint32_t h = (uint32_t)((key >> 32) ^ (uint32_t)key) + (uint32_t)i * 2654435761u;
            h ^= h >> 16; h *= 0x85ebca6bu; h ^= h >> 13;
            h *= 0xc2b2ae35u; h ^= h >> 16;
            return ((uint64_t)h << 32) | h;
        }

        case HashScheme::XOR_SHIFT: {
            uint64_t h = key ^ XS_SALT[i];
            h ^= h >> 33;
            h ^= h << 21;
            h ^= h >> 43;
            return h;
        }

        case HashScheme::JENKINS: {
            uint64_t h = key ^ kHashConst[i];
            h += h << 10;
            h ^= h >> 6;
            h += h << 3;
            h ^= h >> 11;
            h += h << 15;
            h ^= h >> 16;
            h += h << 5;
            h ^= h >> 12;
            return h;
        }

        default:
            return key * kHashConst[i];
    }
}


class BloomFilter {
public:
    virtual ~BloomFilter() = default;
    virtual void batchInsert(const std::vector<uint64_t>& keys) = 0;
    virtual void batchDelete(const std::vector<uint64_t>&) {}
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

    ~PimBloomFilterV2() { pimFree(bitsObj_); pimFree(maskObj_); }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        std::fill(cpuMask_.begin(), cpuMask_.end(), 0);
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++)
                cpuMask_[computeCpuIndex(key, i, shift_, mask_, hs_)] = 1;
        assert(pimCopyHostToDevice((void*)cpuMask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK); // do this last, ez to miss
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyDeviceToHost(bitsObj_, (void*)hostBits_.data()) == PIM_OK);
        out.resize(keys.size()); // make room first, alwyas
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
    PimBloomFilterV3(uint64_t m, int k, uint64_t n, HashScheme hs, bool preloadMode = false)
        : m_(m), n_(n), k_(k), hs_(hs), preloadMode_(preloadMode), shift_((unsigned)(64 - __builtin_ctzll(m))),
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
        if (h1Obj_ != -1) { pimFree(h1Obj_); pimFree(h2Obj_); }
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        std::fill(cpuMask_.begin(), cpuMask_.end(), 0);

        if (isCpuHashScheme(hs_)) {
            for (uint64_t key : keys)
                for (int i = 0; i < k_; i++)
                    cpuMask_[computeCpuIndex(key, i, shift_, mask_, hs_)] = 1;
            assert(pimCopyHostToDevice((void*)cpuMask_.data(), maskObj_) == PIM_OK);
            assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
            return;
        }

        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);
        if (preloadMode_) pimResetStats();

        switch (hs_) {
            // case HashScheme::MULTIPLICATIVE: pimInsertXorShift(); break;
            // case HashScheme::JENKINS: pimInsertFiveCycle(); break;
            case HashScheme::MULTIPLICATIVE: pimInsertMultiplicative(); break;
            case HashScheme::KIRSCH_MITZENMACHER: pimInsertKirschMitz(); break;
            case HashScheme::XOR_SHIFT: pimInsertXorShift(); break;
            case HashScheme::FIVE_CYCLE: pimInsertFiveCycle(); break;
            case HashScheme::JENKINS: pimInsertJenkins(); break;
            default: break;
        }
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        if (!isCpuHashScheme(hs_)) {
            assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);
            if (preloadMode_) pimResetStats();
        }

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

        std::vector<std::vector<uint64_t>> allIdx(k_, std::vector<uint64_t>(n_));
        switch (hs_) {
            // case HashScheme::XOR_SHIFT: pimQueryJenkins(allIdx); break;
            case HashScheme::MULTIPLICATIVE: pimQueryMultiplicative(allIdx); break;
            case HashScheme::KIRSCH_MITZENMACHER: pimQueryKirschMitz(allIdx); break;
            case HashScheme::XOR_SHIFT: pimQueryXorShift(allIdx); break;
            case HashScheme::FIVE_CYCLE: pimQueryFiveCycle(allIdx); break;
            case HashScheme::JENKINS: pimQueryJenkins(allIdx); break;
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

    const char* name() const override { return preloadMode_ ? "pim-v4" : "pim-v3"; }

private:
    uint64_t m_, n_;
    int k_;
    HashScheme hs_;
    bool preloadMode_;
    unsigned shift_;
    uint64_t mask_;
    PimObjId bitsObj_, maskObj_, keysObj_, tempObj_, workObj_, h1Obj_, h2Obj_;
    std::vector<uint8_t> cpuMask_, hostBits_;
    std::vector<uint64_t> hostIdx_;

    void flushMaskToPim() {
        assert(pimCopyHostToDevice((void*)cpuMask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK); // same finish, dont skip
    }

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

    void pimComputeKM() {
        assert(pimMulScalar(keysObj_, h1Obj_, kHashConst[0]) == PIM_OK);
        assert(pimShiftBitsRight(h1Obj_, h1Obj_, shift_) == PIM_OK);
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

    void pimComputeXS(int i) {
        assert(pimXorScalar(keysObj_, workObj_, XS_SALT[i]) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 21) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 43) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);
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

    void pimComputeFC(int i) {
        assert(pimXorScalar(keysObj_, workObj_, kHashConst[i]) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimMulScalar(workObj_, workObj_, 0xff51afd7ed558ccdULL) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimMulScalar(workObj_, workObj_, 0xc4ceb9fe1a85ec53ULL) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);
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

    void pimComputeJenkins(int i) {
        assert(pimXorScalar(keysObj_, workObj_, kHashConst[i]) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 10) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 6) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 3) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 11) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 15) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 16) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 5) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 12) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);
    }

    void pimInsertJenkins() {
        for (int i = 0; i < k_; i++) {
            pimComputeJenkins(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data()) == PIM_OK);
            for (uint64_t idx : hostIdx_) cpuMask_[idx] = 1;
        }
        flushMaskToPim();
    }

    void pimQueryJenkins(std::vector<std::vector<uint64_t>>& allIdx) {
        for (int i = 0; i < k_; i++) {
            pimComputeJenkins(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data()) == PIM_OK);
        }
    }
};


class CpuCountingBloomFilter : public BloomFilter {
public:
    CpuCountingBloomFilter(uint64_t m, int k, HashScheme hs)
        : m_(m), k_(k), hs_(hs), shift_((unsigned)(64 - __builtin_ctzll(m))),
          mask_(m - 1), counts_(m, 0) {}

    void batchInsert(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++) {
                auto& c = counts_[computeCpuIndex(key, i, shift_, mask_, hs_)];
                if (c < 255) c++; // stop before it wraps, just in case
            }
    }

    void batchDelete(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++) {
                auto& c = counts_[computeCpuIndex(key, i, shift_, mask_, hs_)];
                if (c > 0) c--; // dont go below zero
            }
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = counts_[computeCpuIndex(keys[j], i, shift_, mask_, hs_)] > 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "cpu-counting"; }

private:
    uint64_t m_;
    int k_;
    HashScheme hs_;
    unsigned shift_;
    uint64_t mask_;
    std::vector<uint8_t> counts_;
};


class PimCountingBloomFilterV2 : public BloomFilter {
public:
    PimCountingBloomFilterV2(uint64_t m, int k, HashScheme hs)
        : m_(m), k_(k), hs_(hs), shift_((unsigned)(64 - __builtin_ctzll(m))),
          mask_(m - 1), cpuDelta_(m, 0), hostCounts_(m, 0) {
        countsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT8);
        assert(countsObj_ != -1);
        deltaObj_ = pimAllocAssociated(countsObj_, PIM_UINT8);
        assert(deltaObj_ != -1);
        std::vector<uint8_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), countsObj_) == PIM_OK);
    }

    ~PimCountingBloomFilterV2() { pimFree(countsObj_); pimFree(deltaObj_); }

    void batchInsert(const std::vector<uint64_t>& keys) override { applyBatch(keys, false); }
    void batchDelete(const std::vector<uint64_t>& keys) override { applyBatch(keys, true); }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyDeviceToHost(countsObj_, (void*)hostCounts_.data()) == PIM_OK);
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = hostCounts_[computeCpuIndex(keys[j], i, shift_, mask_, hs_)] > 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "pim-counting-v2"; }

private:
    uint64_t m_;
    int k_;
    HashScheme hs_;
    unsigned shift_;
    uint64_t mask_;
    PimObjId countsObj_, deltaObj_;
    std::vector<uint8_t> cpuDelta_, hostCounts_;

    void applyBatch(const std::vector<uint64_t>& keys, bool sub) {
        std::fill(cpuDelta_.begin(), cpuDelta_.end(), 0); // clear it first, easy to foget
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++) {
                auto& d = cpuDelta_[computeCpuIndex(key, i, shift_, mask_, hs_)];
                if (d < 255) d++;
            }
        assert(pimCopyHostToDevice((void*)cpuDelta_.data(), deltaObj_) == PIM_OK);
        if (sub) assert(pimSub(countsObj_, deltaObj_, countsObj_) == PIM_OK);
        else assert(pimAdd(countsObj_, deltaObj_, countsObj_) == PIM_OK);
    }
};


class PimCountingBloomFilterV3 : public BloomFilter {
public:
    PimCountingBloomFilterV3(uint64_t m, int k, uint64_t n, HashScheme hs, bool preloadMode = false)
        : m_(m), n_(n), k_(k), hs_(hs), preloadMode_(preloadMode),
          shift_((unsigned)(64 - __builtin_ctzll(m))), mask_(m - 1),
          cpuDelta_(m, 0), hostCounts_(m, 0), hostIdx_(n) {

        countsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT8);
        assert(countsObj_ != -1);
        deltaObj_ = pimAllocAssociated(countsObj_, PIM_UINT8);
        assert(deltaObj_ != -1);

        keysObj_ = pimAlloc(PIM_ALLOC_AUTO, n, PIM_UINT64);
        assert(keysObj_ != -1);
        tempObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(tempObj_ != -1);
        workObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(workObj_ != -1);

        if (hs_ == HashScheme::KIRSCH_MITZENMACHER) {
            h1Obj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
            assert(h1Obj_ != -1);
            h2Obj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
            assert(h2Obj_ != -1);
        } else {
            h1Obj_ = h2Obj_ = -1;
        }

        std::vector<uint8_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), countsObj_) == PIM_OK);
    }

    ~PimCountingBloomFilterV3() {
        pimFree(countsObj_); pimFree(deltaObj_);
        pimFree(keysObj_); pimFree(tempObj_); pimFree(workObj_);
        if (h1Obj_ != -1) { pimFree(h1Obj_); pimFree(h2Obj_); }
    }

    void batchInsert(const std::vector<uint64_t>& keys) override { applyBatch(keys, false); }
    void batchDelete(const std::vector<uint64_t>& keys) override { applyBatch(keys, true); }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        uint64_t cnt = keys.size();

        if (!isCpuHashScheme(hs_)) {
            assert(pimCopyHostToDevice((void*)keys.data(), keysObj_, 0, cnt) == PIM_OK);
            if (preloadMode_) pimResetStats();
        }

        assert(pimCopyDeviceToHost(countsObj_, (void*)hostCounts_.data()) == PIM_OK);

        if (isCpuHashScheme(hs_)) {
            out.resize(cnt);
            for (size_t j = 0; j < cnt; j++) {
                bool ok = true;
                for (int i = 0; i < k_ && ok; i++)
                    ok = hostCounts_[computeCpuIndex(keys[j], i, shift_, mask_, hs_)] > 0;
                out[j] = ok;
            }
            return;
        }

        std::vector<std::vector<uint64_t>> allIdx(k_, std::vector<uint64_t>(cnt));
        switch (hs_) {
            // case HashScheme::FIVE_CYCLE: pimQueryXorShift(allIdx, cnt); break;
            case HashScheme::MULTIPLICATIVE: pimQueryMultiplicative(allIdx, cnt); break;
            case HashScheme::KIRSCH_MITZENMACHER: pimQueryKirschMitz(allIdx, cnt); break;
            case HashScheme::XOR_SHIFT: pimQueryXorShift(allIdx, cnt); break;
            case HashScheme::FIVE_CYCLE: pimQueryFiveCycle(allIdx, cnt); break;
            case HashScheme::JENKINS: pimQueryJenkins(allIdx, cnt); break;
            default: break;
        }

        out.resize(cnt);
        for (size_t j = 0; j < cnt; j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = hostCounts_[allIdx[i][j]] > 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return preloadMode_ ? "pim-counting-v4" : "pim-counting-v3"; }

private:
    uint64_t m_, n_;
    int k_;
    HashScheme hs_;
    bool preloadMode_;
    unsigned shift_;
    uint64_t mask_;
    PimObjId countsObj_, deltaObj_, keysObj_, tempObj_, workObj_, h1Obj_, h2Obj_;
    std::vector<uint8_t> cpuDelta_, hostCounts_;
    std::vector<uint64_t> hostIdx_;

    void flushDeltaToPim(bool sub) {
        assert(pimCopyHostToDevice((void*)cpuDelta_.data(), deltaObj_) == PIM_OK);
        if (sub) assert(pimSub(countsObj_, deltaObj_, countsObj_) == PIM_OK);
        else assert(pimAdd(countsObj_, deltaObj_, countsObj_) == PIM_OK);
    }

    void applyBatch(const std::vector<uint64_t>& keys, bool sub) {
        uint64_t cnt = keys.size();
        std::fill(cpuDelta_.begin(), cpuDelta_.end(), 0);

        if (isCpuHashScheme(hs_)) {
            for (uint64_t key : keys)
                for (int i = 0; i < k_; i++) {
                    auto& d = cpuDelta_[computeCpuIndex(key, i, shift_, mask_, hs_)];
                    if (d < 255) d++;
                }
            flushDeltaToPim(sub);
            return;
        }

        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_, 0, cnt) == PIM_OK);
        if (preloadMode_) pimResetStats();

        switch (hs_) {
            // case HashScheme::JENKINS: pimAccumulateXorShift(cnt); break;
            case HashScheme::MULTIPLICATIVE: pimAccumulateMultiplicative(cnt); break;
            case HashScheme::KIRSCH_MITZENMACHER: pimAccumulateKirschMitz(cnt); break;
            case HashScheme::XOR_SHIFT: pimAccumulateXorShift(cnt); break;
            case HashScheme::FIVE_CYCLE: pimAccumulateFiveCycle(cnt); break;
            case HashScheme::JENKINS: pimAccumulateJenkins(cnt); break;
            default: break;
        }

        flushDeltaToPim(sub);
    }

    void pimAccumulateMultiplicative(uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data(), 0, cnt) == PIM_OK);
            for (uint64_t j = 0; j < cnt; j++) { auto& d = cpuDelta_[hostIdx_[j]]; if (d < 255) d++; }
        }
    }

    void pimComputeKM() {
        assert(pimMulScalar(keysObj_, h1Obj_, kHashConst[0]) == PIM_OK);
        assert(pimShiftBitsRight(h1Obj_, h1Obj_, shift_) == PIM_OK);
        assert(pimMulScalar(keysObj_, h2Obj_, kHashConst[1]) == PIM_OK);
        assert(pimShiftBitsRight(h2Obj_, h2Obj_, shift_) == PIM_OK);
        assert(pimOrScalar(h2Obj_, h2Obj_, 1) == PIM_OK);
    }

    void pimAccumulateKirschMitz(uint64_t cnt) {
        pimComputeKM();
        for (int i = 0; i < k_; i++) {
            if (i == 0) {
                assert(pimCopyDeviceToHost(h1Obj_, (void*)hostIdx_.data(), 0, cnt) == PIM_OK);
            } else {
                assert(pimCopyObjectToObject(h2Obj_, workObj_) == PIM_OK);
                assert(pimMulScalar(workObj_, workObj_, (uint64_t)i) == PIM_OK);
                assert(pimAdd(h1Obj_, workObj_, workObj_) == PIM_OK);
                assert(pimAndScalar(workObj_, workObj_, mask_) == PIM_OK);
                assert(pimCopyDeviceToHost(workObj_, (void*)hostIdx_.data(), 0, cnt) == PIM_OK);
            }
            for (uint64_t j = 0; j < cnt; j++) { auto& d = cpuDelta_[hostIdx_[j]]; if (d < 255) d++; }
        }
    }

    void pimComputeXS(int i) {
        assert(pimXorScalar(keysObj_, workObj_, XS_SALT[i]) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 21) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 43) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);
    }

    void pimAccumulateXorShift(uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            pimComputeXS(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data(), 0, cnt) == PIM_OK);
            for (uint64_t j = 0; j < cnt; j++) { auto& d = cpuDelta_[hostIdx_[j]]; if (d < 255) d++; }
        }
    }

    void pimComputeFC(int i) {
        assert(pimXorScalar(keysObj_, workObj_, kHashConst[i]) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimMulScalar(workObj_, workObj_, 0xff51afd7ed558ccdULL) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimMulScalar(workObj_, workObj_, 0xc4ceb9fe1a85ec53ULL) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);
    }

    void pimAccumulateFiveCycle(uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            pimComputeFC(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data(), 0, cnt) == PIM_OK);
            for (uint64_t j = 0; j < cnt; j++) { auto& d = cpuDelta_[hostIdx_[j]]; if (d < 255) d++; }
        }
    }

    void pimQueryMultiplicative(std::vector<std::vector<uint64_t>>& allIdx, uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data(), 0, cnt) == PIM_OK);
        }
    }

    void pimQueryKirschMitz(std::vector<std::vector<uint64_t>>& allIdx, uint64_t cnt) {
        pimComputeKM();
        for (int i = 0; i < k_; i++) {
            if (i == 0) {
                assert(pimCopyDeviceToHost(h1Obj_, (void*)allIdx[0].data(), 0, cnt) == PIM_OK);
            } else {
                assert(pimCopyObjectToObject(h2Obj_, workObj_) == PIM_OK);
                assert(pimMulScalar(workObj_, workObj_, (uint64_t)i) == PIM_OK);
                assert(pimAdd(h1Obj_, workObj_, workObj_) == PIM_OK);
                assert(pimAndScalar(workObj_, workObj_, mask_) == PIM_OK);
                assert(pimCopyDeviceToHost(workObj_, (void*)allIdx[i].data(), 0, cnt) == PIM_OK);
            }
        }
    }

    void pimQueryXorShift(std::vector<std::vector<uint64_t>>& allIdx, uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            pimComputeXS(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data(), 0, cnt) == PIM_OK);
        }
    }

    void pimQueryFiveCycle(std::vector<std::vector<uint64_t>>& allIdx, uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            pimComputeFC(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data(), 0, cnt) == PIM_OK);
        }
    }

    void pimComputeJenkins(int i) {
        assert(pimXorScalar(keysObj_, workObj_, kHashConst[i]) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 10) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 6) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 3) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 11) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 15) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 16) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 5) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 12) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, shift_) == PIM_OK);
    }

    void pimAccumulateJenkins(uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            pimComputeJenkins(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data(), 0, cnt) == PIM_OK);
            for (uint64_t j = 0; j < cnt; j++) { auto& d = cpuDelta_[hostIdx_[j]]; if (d < 255) d++; }
        }
    }

    void pimQueryJenkins(std::vector<std::vector<uint64_t>>& allIdx, uint64_t cnt) {
        for (int i = 0; i < k_; i++) {
            pimComputeJenkins(i);
            assert(pimCopyDeviceToHost(tempObj_, (void*)allIdx[i].data(), 0, cnt) == PIM_OK);
        }
    }
};


static constexpr int CUCKOO_MAX_KICKS = 500;
static constexpr uint32_t CUCKOO_EMPTY = 0;

inline uint32_t ckFingerprint(uint64_t key, HashScheme hs) {
    return (uint32_t)((computeCpuHashValue(key, 1, hs) >> 48) & 0xFFFF) | 1u;
}

inline uint64_t ckPrimary(uint64_t key, unsigned shift, uint64_t mask, HashScheme hs) {
    return (computeCpuHashValue(key, 0, hs) >> shift) & mask;
}

inline uint64_t ckAlt(uint64_t i, uint32_t fp, unsigned shift, uint64_t mask, HashScheme hs) {
    return (i ^ ((computeCpuHashValue((uint64_t)fp, 2, hs) >> shift) & mask)) & mask;
}

inline bool ckInsertOne(std::vector<uint32_t>& buckets, uint64_t key, unsigned shift, uint64_t mask, HashScheme hs) {
    uint32_t fp = ckFingerprint(key, hs);
    uint64_t i1 = ckPrimary(key, shift, mask, hs);
    uint64_t i2 = ckAlt(i1, fp, shift, mask, hs);

    if (buckets[i1] == fp || buckets[i2] == fp) return true;
    if (buckets[i1] == CUCKOO_EMPTY) { buckets[i1] = fp; return true; }
    if (buckets[i2] == CUCKOO_EMPTY) { buckets[i2] = fp; return true; }

    return false;
}

inline bool ckQueryOne(const std::vector<uint32_t>& buckets, uint64_t key, unsigned shift, uint64_t mask, HashScheme hs) {
    uint32_t fp = ckFingerprint(key, hs);
    uint64_t i1 = ckPrimary(key, shift, mask, hs);
    if (buckets[i1] == fp) return true;
    return buckets[ckAlt(i1, fp, shift, mask, hs)] == fp;
}

inline void ckRemoveOne(std::vector<uint32_t>& buckets, uint64_t key, unsigned shift, uint64_t mask, HashScheme hs) {
    uint32_t fp = ckFingerprint(key, hs);
    uint64_t i1 = ckPrimary(key, shift, mask, hs);
    if (buckets[i1] == fp) { buckets[i1] = CUCKOO_EMPTY; return; }
    uint64_t i2 = ckAlt(i1, fp, shift, mask, hs);
    if (buckets[i2] == fp) buckets[i2] = CUCKOO_EMPTY;
}

inline bool ckStashContains(const std::unordered_set<uint64_t>& stash, uint64_t key) {
    return stash.find(key) != stash.end();
}

inline void ckStashRemove(std::unordered_set<uint64_t>& stash, uint64_t key) {
    stash.erase(key);
}

class CpuCuckooFilter : public BloomFilter {
public:
    CpuCuckooFilter(uint64_t m, HashScheme hs)
        : m_(m), hs_(hs), mask_(m - 1), shift_((unsigned)(64 - __builtin_ctzll(m))),
          buckets_(m, CUCKOO_EMPTY) {
        assert(isSupportedCpuHashScheme(hs_));
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys) {
            if (ckStashContains(stash_, key) || ckQueryOne(buckets_, key, shift_, mask_, hs_)) continue;
            if (!ckInsertOne(buckets_, key, shift_, mask_, hs_)) stash_.insert(key); // save the awkard ones
        }
    }

    void batchDelete(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys) {
            ckStashRemove(stash_, key);
            ckRemoveOne(buckets_, key, shift_, mask_, hs_);
        }
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++)
            out[j] = ckStashContains(stash_, keys[j]) || ckQueryOne(buckets_, keys[j], shift_, mask_, hs_);
    }

    const char* name() const override { return "cuckoo-cpu"; }

private:
    uint64_t m_;
    HashScheme hs_;
    uint64_t mask_;
    unsigned shift_;
    std::vector<uint32_t> buckets_;
    std::unordered_set<uint64_t> stash_;
};

class PimCuckooFilterV2 : public BloomFilter {
public:
    PimCuckooFilterV2(uint64_t m, HashScheme hs)
        : m_(m), hs_(hs), mask_(m - 1), shift_((unsigned)(64 - __builtin_ctzll(m))),
          hostBuckets_(m, CUCKOO_EMPTY) {
        assert(isSupportedCpuHashScheme(hs_));
        bucketsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT32);
        assert(bucketsObj_ != -1);
        std::vector<uint32_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bucketsObj_) == PIM_OK);
    }

    ~PimCuckooFilterV2() { pimFree(bucketsObj_); }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);
        for (uint64_t key : keys) {
            if (ckStashContains(stash_, key) || ckQueryOne(hostBuckets_, key, shift_, mask_, hs_)) continue;
            if (!ckInsertOne(hostBuckets_, key, shift_, mask_, hs_)) stash_.insert(key);
        }
        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    void batchDelete(const std::vector<uint64_t>& keys) override {
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);
        for (uint64_t key : keys) {
            ckStashRemove(stash_, key);
            ckRemoveOne(hostBuckets_, key, shift_, mask_, hs_);
        }
        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++)
            out[j] = ckStashContains(stash_, keys[j]) || ckQueryOne(hostBuckets_, keys[j], shift_, mask_, hs_);
    }

    const char* name() const override { return "cuckoo-pim-v2"; }

private:
    uint64_t m_;
    HashScheme hs_;
    uint64_t mask_;
    unsigned shift_;
    PimObjId bucketsObj_;
    std::vector<uint32_t> hostBuckets_;
    std::unordered_set<uint64_t> stash_;
};

class PimCuckooFilterV3 : public BloomFilter {
public:
    PimCuckooFilterV3(uint64_t m, uint64_t n, HashScheme hs, bool preloadMode = false)
        : m_(m), n_(n), hs_(hs), preloadMode_(preloadMode),
          mask_(m - 1), shift_((unsigned)(64 - __builtin_ctzll(m))),
          hostBuckets_(m, CUCKOO_EMPTY), hostI1_(n), hostFp_(n), hostAltHash_(n) {
        assert(isSupportedPimHashScheme(hs_));
        bucketsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT32);
        assert(bucketsObj_ != -1);
        keysObj_ = pimAlloc(PIM_ALLOC_AUTO, n, PIM_UINT64);
        assert(keysObj_ != -1);
        workObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(workObj_ != -1);
        tempObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(tempObj_ != -1);
        altObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(altObj_ != -1);

        std::vector<uint32_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bucketsObj_) == PIM_OK);
    }

    ~PimCuckooFilterV3() {
        pimFree(bucketsObj_);
        pimFree(keysObj_);
        pimFree(workObj_);
        pimFree(tempObj_);
        pimFree(altObj_);
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        computeIndices(keys);
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);

        for (size_t j = 0; j < keys.size(); j++) {
            uint64_t i1 = hostI1_[j] & mask_;
            uint32_t fp = (uint32_t)(hostFp_[j] & 0xFFFF) | 1u;
            uint64_t i2 = (i1 ^ (hostAltHash_[j] & mask_)) & mask_;

            if (ckStashContains(stash_, keys[j]) || hostBuckets_[i1] == fp || hostBuckets_[i2] == fp) continue;
            if (hostBuckets_[i1] == CUCKOO_EMPTY) { hostBuckets_[i1] = fp; continue; }
            if (hostBuckets_[i2] == CUCKOO_EMPTY) { hostBuckets_[i2] = fp; continue; }

            stash_.insert(keys[j]);
        }

        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    void batchDelete(const std::vector<uint64_t>& keys) override {
        computeIndices(keys);
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);

        for (size_t j = 0; j < keys.size(); j++) {
            uint64_t i1 = hostI1_[j] & mask_;
            uint32_t fp = (uint32_t)(hostFp_[j] & 0xFFFF) | 1u;
            uint64_t i2 = (i1 ^ (hostAltHash_[j] & mask_)) & mask_;
            ckStashRemove(stash_, keys[j]);
            if (hostBuckets_[i1] == fp) { hostBuckets_[i1] = CUCKOO_EMPTY; continue; }
            if (hostBuckets_[i2] == fp) hostBuckets_[i2] = CUCKOO_EMPTY;
        }

        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        computeIndices(keys);
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);

        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++) {
            uint64_t i1 = hostI1_[j] & mask_;
            uint32_t fp = (uint32_t)(hostFp_[j] & 0xFFFF) | 1u;
            uint64_t i2 = (i1 ^ (hostAltHash_[j] & mask_)) & mask_;
            out[j] = ckStashContains(stash_, keys[j]) || (hostBuckets_[i1] == fp) || (hostBuckets_[i2] == fp);
        }
    }

    const char* name() const override { return preloadMode_ ? "cuckoo-pim-v4" : "cuckoo-pim-v3"; }

private:
    uint64_t m_, n_;
    HashScheme hs_;
    bool preloadMode_;
    uint64_t mask_;
    unsigned shift_;
    PimObjId bucketsObj_, keysObj_, workObj_, tempObj_, altObj_;
    std::vector<uint32_t> hostBuckets_;
    std::vector<uint64_t> hostI1_, hostFp_, hostAltHash_;
    std::unordered_set<uint64_t> stash_;

    void computePimHash(int i, PimObjId srcObj, PimObjId dstObj, unsigned finalShift) {
        if (hs_ == HashScheme::XOR_SHIFT) {
            assert(pimXorScalar(srcObj, workObj_, XS_SALT[i]) == PIM_OK);
            assert(pimShiftBitsRight(workObj_, tempObj_, 33) == PIM_OK);
            assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
            assert(pimShiftBitsLeft(workObj_, tempObj_, 21) == PIM_OK);
            assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
            assert(pimShiftBitsRight(workObj_, tempObj_, 43) == PIM_OK);
            assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
            assert(pimShiftBitsRight(workObj_, dstObj, finalShift) == PIM_OK);
            return;
        }

        assert(pimXorScalar(srcObj, workObj_, kHashConst[i]) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 10) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 6) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 3) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 11) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 15) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 16) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsLeft(workObj_, tempObj_, 5) == PIM_OK);
        assert(pimAdd(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, tempObj_, 12) == PIM_OK);
        assert(pimXor(workObj_, tempObj_, workObj_) == PIM_OK);
        assert(pimShiftBitsRight(workObj_, dstObj, finalShift) == PIM_OK);
    }

    void computeIndices(const std::vector<uint64_t>& keys) {
        uint64_t cnt = keys.size();
        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_, 0, cnt) == PIM_OK);
        if (preloadMode_) pimResetStats();

        computePimHash(0, keysObj_, tempObj_, shift_);
        assert(pimCopyDeviceToHost(tempObj_, (void*)hostI1_.data(), 0, cnt) == PIM_OK);

        computePimHash(1, keysObj_, tempObj_, 48);
        assert(pimCopyDeviceToHost(tempObj_, (void*)hostFp_.data(), 0, cnt) == PIM_OK);
        for (uint64_t j = 0; j < cnt; j++) hostFp_[j] = (hostFp_[j] & 0xFFFF) | 1u;

        assert(pimCopyHostToDevice((void*)hostFp_.data(), altObj_, 0, cnt) == PIM_OK);
        computePimHash(2, altObj_, tempObj_, shift_);
        assert(pimCopyDeviceToHost(tempObj_, (void*)hostAltHash_.data(), 0, cnt) == PIM_OK);
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

inline BenchMetrics runCpuBench(BloomFilter* bf, const std::vector<uint64_t>& insertKeys, const std::vector<uint64_t>& fpKeys) {
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
    double query_ms = std::chrono::duration<double>(t3 - t2).count() * 1000.0;

    return { insertMs / n, query_ms / n, 0.0, 0.0, (double)fp / (double)fpKeys.size() };
}

inline BenchMetrics runPimBench(BloomFilter* bf, const std::vector<uint64_t>& insertKeys, const std::vector<uint64_t>& fpKeys) {
    double n = (double)insertKeys.size();

    PimOpStats s0 = capturePimStats();
    pimResetStats(); // count after this, probly
    bf->batchInsert(insertKeys);
    PimOpStats s1 = capturePimStats();

    std::vector<bool> q1;
    pimResetStats();
    bf->batchQuery(insertKeys, q1);
    PimOpStats s2 = capturePimStats();

    for (bool b : q1) assert(b);

    std::vector<bool> q2;
    bf->batchQuery(fpKeys, q2);
    uint64_t fp = 0;
    for (bool b : q2) fp += b ? 1 : 0;

    PimOpStats ins = s1 - s0;
    PimOpStats qry = s2 - s1;

    return { ins.totalMs() / n, qry.totalMs() / n, ins.totalMj(), qry.totalMj(), (double)fp / (double)fpKeys.size() };
}

inline BenchMetrics runPimBenchV4(BloomFilter* bf, const std::vector<uint64_t>& insertKeys, const std::vector<uint64_t>& fpKeys) {
    double n = (double)insertKeys.size();

    pimResetStats();
    bf->batchInsert(insertKeys);
    PimOpStats ins = capturePimStats();
    ins.copyMs = 0.0;
    ins.copyMj = 0.0;

    std::vector<bool> q1;
    pimResetStats();
    bf->batchQuery(insertKeys, q1);
    PimOpStats qry = capturePimStats();
    qry.copyMs = 0.0;
    qry.copyMj = 0.0;

    for (bool b : q1) assert(b);

    std::vector<bool> q2;
    bf->batchQuery(fpKeys, q2);
    uint64_t fp = 0;
    for (bool b : q2) fp += b ? 1 : 0;

    return { ins.totalMs() / n, qry.totalMs() / n, ins.totalMj(), qry.totalMj(), (double)fp / (double)fpKeys.size() };
}


struct CountingBenchMetrics {
    double insertMs;
    double deleteMs;
    double queryMs;
    double insertMj;
    double deleteMj;
    double queryMj;
    double fpr;
    double fnr_kept;
    double fpr_del;

    double insertThroughput() const { return insertMs > 0 ? (1000.0 / insertMs) : 0; }
    double deleteThroughput() const { return deleteMs > 0 ? (1000.0 / deleteMs) : 0; }
    double queryThroughput() const { return queryMs > 0 ? (1000.0 / queryMs) : 0; }
};

inline CountingBenchMetrics runCpuCountingBench(
    BloomFilter* bf,
    const std::vector<uint64_t>& insKeys,
    const std::vector<uint64_t>& delKeys,
    const std::vector<uint64_t>& keptKeys,
    const std::vector<uint64_t>& fpKeys)
{
    double n = (double)insKeys.size();
    double n_del = (double)delKeys.size();
    double n_kep = (double)keptKeys.size();

    auto t0 = Clock::now();
    bf->batchInsert(insKeys);
    auto t1 = Clock::now(); // mark insert stop here
    bf->batchDelete(delKeys);
    auto t2 = Clock::now(); // mark delete stop here

    std::vector<bool> qKept, qDel, qFp;
    bf->batchQuery(keptKeys, qKept);
    auto t3 = Clock::now();
    bf->batchQuery(delKeys, qDel);
    bf->batchQuery(fpKeys, qFp);

    uint64_t fn_kept = 0; for (bool b : qKept) if (!b) fn_kept++;
    uint64_t fp_del = 0; for (bool b : qDel) if (b) fp_del++;
    uint64_t fp = 0; for (bool b : qFp) if (b) fp++;

    double insertMs = std::chrono::duration<double>(t1 - t0).count() * 1000.0;
    double deleteMs = std::chrono::duration<double>(t2 - t1).count() * 1000.0;
    double queryMs = std::chrono::duration<double>(t3 - t2).count() * 1000.0;

    return { insertMs/n, deleteMs/n_del, queryMs/n_kep,
             0.0, 0.0, 0.0,
             (double)fp/(double)fpKeys.size(),
             (double)fn_kept/n_kep,
             (double)fp_del/n_del };
}

inline CountingBenchMetrics runPimCountingBench(
    BloomFilter* bf,
    const std::vector<uint64_t>& insKeys,
    const std::vector<uint64_t>& delKeys,
    const std::vector<uint64_t>& keptKeys,
    const std::vector<uint64_t>& fpKeys)
{
    double n = (double)insKeys.size();
    double n_del = (double)delKeys.size();
    double n_kep = (double)keptKeys.size();

    PimOpStats s0 = capturePimStats();
    pimResetStats();
    bf->batchInsert(insKeys);
    PimOpStats s1 = capturePimStats();

    pimResetStats();
    bf->batchDelete(delKeys);
    PimOpStats s2 = capturePimStats();

    std::vector<bool> qKept, qDel, qFp;
    pimResetStats();
    bf->batchQuery(keptKeys, qKept);
    PimOpStats s3 = capturePimStats();

    bf->batchQuery(delKeys, qDel);
    bf->batchQuery(fpKeys, qFp);

    uint64_t fn_kept = 0; for (bool b : qKept) if (!b) fn_kept++;
    uint64_t fp_del = 0; for (bool b : qDel) if (b) fp_del++;
    uint64_t fp = 0; for (bool b : qFp) if (b) fp++;

    PimOpStats ins = s1 - s0;
    PimOpStats del = s2 - s1;
    PimOpStats qry = s3 - s2;

    return { ins.totalMs()/n, del.totalMs()/n_del, qry.totalMs()/n_kep,
             ins.totalMj(), del.totalMj(), qry.totalMj(),
             (double)fp/(double)fpKeys.size(),
             (double)fn_kept/n_kep,
             (double)fp_del/n_del };
}

inline CountingBenchMetrics runPimCountingBenchV4(
    BloomFilter* bf,
    const std::vector<uint64_t>& insKeys,
    const std::vector<uint64_t>& delKeys,
    const std::vector<uint64_t>& keptKeys,
    const std::vector<uint64_t>& fpKeys)
{
    double n = (double)insKeys.size();
    double n_del = (double)delKeys.size();
    double n_kep = (double)keptKeys.size();

    pimResetStats();
    bf->batchInsert(insKeys);
    PimOpStats ins = capturePimStats();
    ins.copyMs = 0.0; ins.copyMj = 0.0;

    pimResetStats();
    bf->batchDelete(delKeys);
    PimOpStats del = capturePimStats();
    del.copyMs = 0.0; del.copyMj = 0.0;

    std::vector<bool> qKept, qDel, qFp;
    pimResetStats();
    bf->batchQuery(keptKeys, qKept);
    PimOpStats qry = capturePimStats();
    qry.copyMs = 0.0; qry.copyMj = 0.0;

    bf->batchQuery(delKeys, qDel);
    bf->batchQuery(fpKeys, qFp);

    uint64_t fn_kept = 0; for (bool b : qKept) if (!b) fn_kept++;
    uint64_t fp_del = 0; for (bool b : qDel) if (b) fp_del++;
    uint64_t fp = 0; for (bool b : qFp) if (b) fp++;

    return { ins.totalMs()/n, del.totalMs()/n_del, qry.totalMs()/n_kep,
             ins.totalMj(), del.totalMj(), qry.totalMj(),
             (double)fp/(double)fpKeys.size(),
             (double)fn_kept/n_kep,
             (double)fp_del/n_del };
}
