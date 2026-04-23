#include "util.h"
#include "libpimeval.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cassert>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>

static constexpr int MAX_K = 10;
static constexpr uint64_t PHI64 = 11400714819323198485ULL;
static uint64_t kHashConst[MAX_K];

static void initHashConsts() {
    for (int i = 0; i < MAX_K; i++)
        kHashConst[i] = ((uint64_t)(i + 1) * PHI64) | 1ULL;
}

// cuckoo hash constants - distinct from bloom hash constants
// primary index, fingerprint extractor, alt-index hash
static constexpr uint64_t CK_A_PRIMARY = 11400714819323198485ULL;         // phi64
static constexpr uint64_t CK_A_FP      = 14181476777654086739ULL;         // 5/4 * phi64 | 1
static constexpr uint64_t CK_A_ALT     = 17280765499989070263ULL;         // 3/2 * phi64 | 1

static constexpr int    CUCKOO_MAX_KICKS = 500;
static constexpr uint32_t CUCKOO_EMPTY  = 0;


// ── abstract base ─────────────────────────────────────────────────────────────

class Filter {
public:
    virtual ~Filter() = default;
    virtual void batchInsert(const std::vector<uint64_t>& keys) = 0;
    virtual void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) = 0;
    virtual void batchRemove(const std::vector<uint64_t>&) {}
    virtual const char* name() const = 0;
};


// ── bloom: cpu standard ───────────────────────────────────────────────────────

class CpuBloomFilter : public Filter {
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


// ── bloom: cpu counting (4-bit saturating counters, supports remove) ──────────

class CpuCountingBloomFilter : public Filter {
public:
    static constexpr uint8_t MAX_COUNT = 15;

    CpuCountingBloomFilter(uint64_t m, int k) : m_(m), k_(k), shift_((unsigned)(64 - __builtin_ctzll(m))), counters_(m, 0) {}

    void batchInsert(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++) {
                uint64_t idx = (key * kHashConst[i]) >> shift_;
                if (counters_[idx] < MAX_COUNT) counters_[idx]++;
            }
    }

    void batchRemove(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            for (int i = 0; i < k_; i++) {
                uint64_t idx = (key * kHashConst[i]) >> shift_;
                if (counters_[idx] > 0) counters_[idx]--;
            }
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++) {
            bool ok = true;
            for (int i = 0; i < k_ && ok; i++)
                ok = counters_[(keys[j] * kHashConst[i]) >> shift_] > 0;
            out[j] = ok;
        }
    }

    const char* name() const override { return "cpu-counting"; }

private:
    uint64_t m_;
    int k_;
    unsigned shift_;
    std::vector<uint8_t> counters_;
};


// ── bloom: pim-v2 (cpu hash, pim bitarray) ────────────────────────────────────

class PimBloomFilterV2 : public Filter {
public:
    PimBloomFilterV2(uint64_t m, int k) : m_(m), k_(k), shift_((unsigned)(64 - __builtin_ctzll(m))), mask_(m, 0), hostBits_(m, 0) {
        bitsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT8);
        assert(bitsObj_ != -1);
        maskObj_ = pimAllocAssociated(bitsObj_, PIM_UINT8);
        assert(maskObj_ != -1);
        std::vector<uint8_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bitsObj_) == PIM_OK);
    }

    ~PimBloomFilterV2() { pimFree(bitsObj_); pimFree(maskObj_); }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        std::fill(mask_.begin(), mask_.end(), 0);
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


// ── bloom: pim-v3 (pim hash + pim bitarray) ───────────────────────────────────

class PimBloomFilterV3 : public Filter {
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

    ~PimBloomFilterV3() { pimFree(bitsObj_); pimFree(maskObj_); pimFree(keysObj_); pimFree(tempObj_); }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);
        std::fill(mask_.begin(), mask_.end(), 0);
        for (int i = 0; i < k_; i++) {
            assert(pimMulScalar(keysObj_, tempObj_, kHashConst[i]) == PIM_OK);
            assert(pimShiftBitsRight(tempObj_, tempObj_, shift_) == PIM_OK);
            assert(pimCopyDeviceToHost(tempObj_, (void*)hostIdx_.data()) == PIM_OK);
            for (uint64_t idx : hostIdx_) mask_[idx] = 1;
        }
        assert(pimCopyHostToDevice((void*)mask_.data(), maskObj_) == PIM_OK);
        assert(pimOr(bitsObj_, maskObj_, bitsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);
        assert(pimCopyDeviceToHost(bitsObj_, (void*)hostBits_.data()) == PIM_OK);
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


// ── cuckoo: shared helpers ────────────────────────────────────────────────────
//
// fingerprint: 16-bit, non-zero, derived from key via multiplicative hash
// primary index:  i1 = (key * CK_A_PRIMARY) >> shift
// alt index:      i2 = (i1 XOR alt_hash(fp)) & mask   -- symmetric, so alt(i2,fp)==i1
// alt_hash(fp):   ((uint64_t)fp * CK_A_ALT) >> shift

static inline uint32_t ckFingerprint(uint64_t key, unsigned shift) {
    // top 16 bits of the multiply, forced non-zero
    return (uint32_t)(((key * CK_A_FP) >> 48) & 0xFFFF) | 1u;
}

static inline uint64_t ckPrimary(uint64_t key, unsigned shift, uint64_t mask) {
    return ((key * CK_A_PRIMARY) >> shift) & mask;
}

static inline uint64_t ckAlt(uint64_t i, uint32_t fp, unsigned shift, uint64_t mask) {
    return (i ^ (((uint64_t)fp * CK_A_ALT) >> shift)) & mask;
}

// single-key insert into a host bucket array; returns false if table full
static bool ckInsertOne(std::vector<uint32_t>& buckets, uint64_t key, unsigned shift, uint64_t mask) {
    uint32_t fp = ckFingerprint(key, shift);
    uint64_t i1 = ckPrimary(key, shift, mask);
    uint64_t i2 = ckAlt(i1, fp, shift, mask);

    if (buckets[i1] == CUCKOO_EMPTY) { buckets[i1] = fp; return true; }
    if (buckets[i2] == CUCKOO_EMPTY) { buckets[i2] = fp; return true; }

    // kick: randomly pick a starting bucket and relocate
    uint64_t curr = (rand() & 1) ? i1 : i2;
    for (int kick = 0; kick < CUCKOO_MAX_KICKS; kick++) {
        std::swap(fp, buckets[curr]);
        curr = ckAlt(curr, fp, shift, mask);
        if (buckets[curr] == CUCKOO_EMPTY) { buckets[curr] = fp; return true; }
    }
    return false;
}

static bool ckQueryOne(const std::vector<uint32_t>& buckets, uint64_t key, unsigned shift, uint64_t mask) {
    uint32_t fp = ckFingerprint(key, shift);
    uint64_t i1 = ckPrimary(key, shift, mask);
    if (buckets[i1] == fp) return true;
    uint64_t i2 = ckAlt(i1, fp, shift, mask);
    return buckets[i2] == fp;
}

static void ckRemoveOne(std::vector<uint32_t>& buckets, uint64_t key, unsigned shift, uint64_t mask) {
    uint32_t fp = ckFingerprint(key, shift);
    uint64_t i1 = ckPrimary(key, shift, mask);
    if (buckets[i1] == fp) { buckets[i1] = CUCKOO_EMPTY; return; }
    uint64_t i2 = ckAlt(i1, fp, shift, mask);
    if (buckets[i2] == fp) buckets[i2] = CUCKOO_EMPTY;
}


// ── cuckoo: cpu ───────────────────────────────────────────────────────────────

class CpuCuckooFilter : public Filter {
public:
    CpuCuckooFilter(uint64_t m) : m_(m), mask_(m - 1), shift_((unsigned)(64 - __builtin_ctzll(m))), buckets_(m, CUCKOO_EMPTY) {}

    void batchInsert(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            if (!ckInsertOne(buckets_, key, shift_, mask_))
                std::cerr << "warning: cuckoo table full, dropping key " << key << "\n";
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++)
            out[j] = ckQueryOne(buckets_, keys[j], shift_, mask_);
    }

    void batchRemove(const std::vector<uint64_t>& keys) override {
        for (uint64_t key : keys)
            ckRemoveOne(buckets_, key, shift_, mask_);
    }

    const char* name() const override { return "cuckoo-cpu"; }

private:
    uint64_t m_, mask_;
    unsigned shift_;
    std::vector<uint32_t> buckets_;
};


// ── cuckoo: pim-v2 (cpu hash + kick, pim bucket table) ───────────────────────
//
// bucket table lives in PIM as PIM_UINT32
// all cuckoo logic (hash, kick loop) runs on the host mirror
// pim is used as near-memory storage: one bulk copy per batch op

class PimCuckooFilterV2 : public Filter {
public:
    PimCuckooFilterV2(uint64_t m)
        : m_(m), mask_(m - 1), shift_((unsigned)(64 - __builtin_ctzll(m))),
          hostBuckets_(m, CUCKOO_EMPTY) {
        bucketsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT32);
        assert(bucketsObj_ != -1);
        std::vector<uint32_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bucketsObj_) == PIM_OK);
    }

    ~PimCuckooFilterV2() { pimFree(bucketsObj_); }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        // refresh host mirror from pim, mutate, push back
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);
        for (uint64_t key : keys)
            if (!ckInsertOne(hostBuckets_, key, shift_, mask_))
                std::cerr << "warning: cuckoo table full, dropping key " << key << "\n";
        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    void batchQuery(const std::vector<uint64_t>& keys, std::vector<bool>& out) override {
        // pull table from pim, check on cpu
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);
        out.resize(keys.size());
        for (size_t j = 0; j < keys.size(); j++)
            out[j] = ckQueryOne(hostBuckets_, keys[j], shift_, mask_);
    }

    void batchRemove(const std::vector<uint64_t>& keys) override {
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);
        for (uint64_t key : keys)
            ckRemoveOne(hostBuckets_, key, shift_, mask_);
        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    const char* name() const override { return "cuckoo-pim-v2"; }

private:
    uint64_t m_, mask_;
    unsigned shift_;
    PimObjId bucketsObj_;
    std::vector<uint32_t> hostBuckets_;
};


// ── cuckoo: pim-v3 (pim hash for i1+fp+altHash, pim bucket table) ────────────
//
// pim computes: i1 = (key * A_PRIMARY) >> shift  (via pimMulScalar + pimShiftBitsRight)
//               fp = ((key * A_FP) >> 48) | 1    (via pimMulScalar + pimShiftBitsRight + pimOrScalar)
//               altHash = (fp * A_ALT) >> shift   (via pimMulScalar + pimShiftBitsRight on fp obj)
//               i2 = i1 XOR altHash               (on cpu after download -- xor of two small integers)
// cuckoo kick loop and table mutations still run on host mirror
// bucket table lives in PIM, flushed after each batch

class PimCuckooFilterV3 : public Filter {
public:
    PimCuckooFilterV3(uint64_t m, uint64_t n)
        : m_(m), n_(n), mask_(m - 1), shift_((unsigned)(64 - __builtin_ctzll(m))),
          hostBuckets_(m, CUCKOO_EMPTY),
          hostI1_(n), hostFp_(n), hostAltHash_(n) {
        bucketsObj_ = pimAlloc(PIM_ALLOC_AUTO, m, PIM_UINT32);
        assert(bucketsObj_ != -1);

        // key pipeline objects (all UINT64, associated so they share bank layout)
        keysObj_ = pimAlloc(PIM_ALLOC_AUTO, n, PIM_UINT64);
        assert(keysObj_ != -1);
        i1Obj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(i1Obj_ != -1);
        fpObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(fpObj_ != -1);
        altHashObj_ = pimAllocAssociated(keysObj_, PIM_UINT64);
        assert(altHashObj_ != -1);

        std::vector<uint32_t> zeros(m, 0);
        assert(pimCopyHostToDevice((void*)zeros.data(), bucketsObj_) == PIM_OK);
    }

    ~PimCuckooFilterV3() {
        pimFree(bucketsObj_);
        pimFree(keysObj_);
        pimFree(i1Obj_);
        pimFree(fpObj_);
        pimFree(altHashObj_);
    }

    void batchInsert(const std::vector<uint64_t>& keys) override {
        computeIndices(keys);
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);

        for (size_t j = 0; j < keys.size(); j++) {
            uint64_t i1 = hostI1_[j] & mask_;
            uint32_t fp = (uint32_t)(hostFp_[j] & 0xFFFF) | 1u;
            uint64_t i2 = (i1 ^ (hostAltHash_[j] & mask_)) & mask_;

            if (hostBuckets_[i1] == CUCKOO_EMPTY) { hostBuckets_[i1] = fp; continue; }
            if (hostBuckets_[i2] == CUCKOO_EMPTY) { hostBuckets_[i2] = fp; continue; }

            // kick loop on host mirror
            uint64_t curr = (rand() & 1) ? i1 : i2;
            bool placed = false;
            for (int kick = 0; kick < CUCKOO_MAX_KICKS; kick++) {
                std::swap(fp, hostBuckets_[curr]);
                curr = (curr ^ (((uint64_t)fp * CK_A_ALT) >> shift_)) & mask_;
                if (hostBuckets_[curr] == CUCKOO_EMPTY) {
                    hostBuckets_[curr] = fp;
                    placed = true;
                    break;
                }
            }
            if (!placed)
                std::cerr << "warning: cuckoo table full, dropping key " << keys[j] << "\n";
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
            out[j] = (hostBuckets_[i1] == fp) || (hostBuckets_[i2] == fp);
        }
    }

    void batchRemove(const std::vector<uint64_t>& keys) override {
        computeIndices(keys);
        assert(pimCopyDeviceToHost(bucketsObj_, (void*)hostBuckets_.data()) == PIM_OK);

        for (size_t j = 0; j < keys.size(); j++) {
            uint64_t i1 = hostI1_[j] & mask_;
            uint32_t fp = (uint32_t)(hostFp_[j] & 0xFFFF) | 1u;
            uint64_t i2 = (i1 ^ (hostAltHash_[j] & mask_)) & mask_;
            if (hostBuckets_[i1] == fp)      { hostBuckets_[i1] = CUCKOO_EMPTY; continue; }
            if (hostBuckets_[i2] == fp)      { hostBuckets_[i2] = CUCKOO_EMPTY; }
        }

        assert(pimCopyHostToDevice((void*)hostBuckets_.data(), bucketsObj_) == PIM_OK);
    }

    const char* name() const override { return "cuckoo-pim-v3"; }

private:
    // compute i1, fp, altHash for a batch of keys entirely in PIM
    void computeIndices(const std::vector<uint64_t>& keys) {
        assert(pimCopyHostToDevice((void*)keys.data(), keysObj_) == PIM_OK);

        // i1 = (key * CK_A_PRIMARY) >> shift
        assert(pimMulScalar(keysObj_, i1Obj_, CK_A_PRIMARY) == PIM_OK);
        assert(pimShiftBitsRight(i1Obj_, i1Obj_, shift_) == PIM_OK);
        assert(pimCopyDeviceToHost(i1Obj_, (void*)hostI1_.data()) == PIM_OK);

        // fp = ((key * CK_A_FP) >> 48) -- masking and | 1 applied on cpu after download
        assert(pimMulScalar(keysObj_, fpObj_, CK_A_FP) == PIM_OK);
        assert(pimShiftBitsRight(fpObj_, fpObj_, 48) == PIM_OK);
        assert(pimCopyDeviceToHost(fpObj_, (void*)hostFp_.data()) == PIM_OK);

        // altHash = (fp * CK_A_ALT) >> shift  -- fp is back on host, re-upload for pim computation
        // re-upload fp values (16-bit in uint64 slots) to altHashObj_ and multiply
        assert(pimCopyHostToDevice((void*)hostFp_.data(), altHashObj_) == PIM_OK);
        assert(pimMulScalar(altHashObj_, altHashObj_, CK_A_ALT) == PIM_OK);
        assert(pimShiftBitsRight(altHashObj_, altHashObj_, shift_) == PIM_OK);
        assert(pimCopyDeviceToHost(altHashObj_, (void*)hostAltHash_.data()) == PIM_OK);
    }

    uint64_t m_, n_, mask_;
    unsigned shift_;
    PimObjId bucketsObj_, keysObj_, i1Obj_, fpObj_, altHashObj_;
    std::vector<uint32_t> hostBuckets_;
    std::vector<uint64_t> hostI1_, hostFp_, hostAltHash_;
};


// ── output helper (stdout + optional log file) ────────────────────────────────

static std::ofstream gLogFile;

static void emit(const std::string& msg) {
    std::cout << msg;
    if (gLogFile.is_open()) gLogFile << msg;
}


// ── main ──────────────────────────────────────────────────────────────────────

static void usage(const char* prog) {
    std::cerr << "usage: " << prog << " [--log <file>] <logfile> <variant> <m> <k> <seed_pid>...\n";
    std::cerr << "  variant:  cpu | cpu-counting | pim-v2 | pim-v3\n";
    std::cerr << "            cuckoo-cpu | cuckoo-pim-v2 | cuckoo-pim-v3\n";
    std::cerr << "  m:        table size (must be power of 2)\n";
    std::cerr << "  k:        hash functions (bloom only; ignored for cuckoo)\n";
    std::cerr << "  seed_pid: one or more root pids to seed the filter\n";
}

int main(int argc, char* argv[]) {
    // pull out optional --log <file> before positional args
    std::string logOutPath;
    std::vector<char*> args;
    for (int i = 0; i < argc; i++) {
        if (std::string(argv[i]) == "--log" && i + 1 < argc) {
            logOutPath = argv[++i];
        } else {
            args.push_back(argv[i]);
        }
    }

    if ((int)args.size() < 6) {
        usage(args[0]);
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
    const std::string variant   = args[2];
    uint64_t m = (uint64_t)std::stoull(args[3]);
    int k      = std::stoi(args[4]);

    std::vector<uint64_t> seeds;
    for (int i = 5; i < (int)args.size(); i++)
        seeds.push_back((uint64_t)std::stoull(args[i]));

    if (m == 0 || (m & (m - 1)) != 0) {
        std::cerr << "error: m must be a power of 2\n";
        return 1;
    }

    initHashConsts();

    bool usePim = (variant == "pim-v2"       || variant == "pim-v3" ||
                   variant == "cuckoo-pim-v2" || variant == "cuckoo-pim-v3");
    if (usePim)
        assert(pimCreateDevice(PIM_DEVICE_BANK_LEVEL, 4, 128, 32, 1024, 8192) == PIM_OK);

    Filter* bf = nullptr;
    if      (variant == "cpu")            bf = new CpuBloomFilter(m, k);
    else if (variant == "cpu-counting")   bf = new CpuCountingBloomFilter(m, k);
    else if (variant == "pim-v2")         bf = new PimBloomFilterV2(m, k);
    else if (variant == "pim-v3")         bf = new PimBloomFilterV3(m, k, 1);
    else if (variant == "cuckoo-cpu")     bf = new CpuCuckooFilter(m);
    else if (variant == "cuckoo-pim-v2")  bf = new PimCuckooFilterV2(m);
    else if (variant == "cuckoo-pim-v3")  bf = new PimCuckooFilterV3(m, 1);
    else {
        std::cerr << "error: unknown variant '" << variant << "'\n";
        usage(args[0]);
        return 1;
    }

    bf->batchInsert(seeds);

    std::ifstream log(eventFile);
    if (!log.is_open()) {
        std::cerr << "error: cannot open '" << eventFile << "'\n";
        delete bf;
        if (usePim) pimDeleteDevice();
        return 1;
    }

    uint64_t totalEvents   = 0;
    uint64_t totalAlerts   = 0;
    uint64_t totalInserted = (uint64_t)seeds.size();

    std::string line;
    while (std::getline(log, line)) {
        if (line.empty()) continue;

        uint64_t pid, ppid, isTarget;
        if (sscanf(line.c_str(), "%llu,%llu,%llu",
                   (unsigned long long*)&pid,
                   (unsigned long long*)&ppid,
                   (unsigned long long*)&isTarget) != 3)
            continue;

        totalEvents++;

        std::vector<bool> result;
        bf->batchQuery({ppid}, result);

        if (result[0]) {
            bf->batchInsert({pid});
            totalInserted++;

            if (isTarget) {
                emit("ALERT " + std::to_string(pid) + " " + std::to_string(ppid) + "\n");
                totalAlerts++;
            }
        }
    }

    emit("\n");
    emit("variant:          " + std::string(bf->name()) + "\n");
    emit("events processed: " + std::to_string(totalEvents) + "\n");
    emit("alerts fired:     " + std::to_string(totalAlerts) + "\n");
    emit("pids inserted:    " + std::to_string(totalInserted) + "\n");

    delete bf;
    if (usePim) pimDeleteDevice();
    return 0;
}
