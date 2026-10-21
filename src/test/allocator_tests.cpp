// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/system.h>
#include <support/hugepages.h>
#include <support/lockedpool.h>
#include <test/util/common.h>
#include <util/byte_units.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

BOOST_AUTO_TEST_SUITE(allocator_tests)

BOOST_AUTO_TEST_CASE(arena_tests)
{
    // Fake memory base address for testing
    // without actually using memory.
    void *synth_base = reinterpret_cast<void*>(0x08000000);
    const size_t synth_size{1_MiB};
    Arena b(synth_base, synth_size, 16);
    void *chunk = b.alloc(1000);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(chunk != nullptr);
    BOOST_CHECK(b.stats().used == 1008); // Aligned to 16
    BOOST_CHECK(b.stats().total == synth_size); // Nothing has disappeared?
    b.free(chunk);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(b.stats().used == 0);
    BOOST_CHECK(b.stats().free == synth_size);
    BOOST_CHECK_EXCEPTION(b.free(chunk), std::runtime_error, HasReason{"Arena: invalid or double free"});

    void *a0 = b.alloc(128);
    void *a1 = b.alloc(256);
    void *a2 = b.alloc(512);
    BOOST_CHECK(b.stats().used == 896);
    BOOST_CHECK(b.stats().total == synth_size);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    b.free(a0);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(b.stats().used == 768);
    b.free(a1);
    BOOST_CHECK(b.stats().used == 512);
    void *a3 = b.alloc(128);
#ifdef ARENA_DEBUG
    b.walk();
#endif
    BOOST_CHECK(b.stats().used == 640);
    b.free(a2);
    BOOST_CHECK(b.stats().used == 128);
    b.free(a3);
    BOOST_CHECK(b.stats().used == 0);
    BOOST_CHECK_EQUAL(b.stats().chunks_used, 0U);
    BOOST_CHECK(b.stats().total == synth_size);
    BOOST_CHECK(b.stats().free == synth_size);
    BOOST_CHECK_EQUAL(b.stats().chunks_free, 1U);

    std::vector<void*> addr;
    BOOST_CHECK(b.alloc(0) == nullptr); // allocating 0 always returns nullptr
#ifdef ARENA_DEBUG
    b.walk();
#endif
    // Sweeping allocate all memory
    addr.reserve(2048);
    for (int x=0; x<1024; ++x)
        addr.push_back(b.alloc(1024));
    BOOST_CHECK(b.stats().free == 0);
    BOOST_CHECK(b.alloc(1024) == nullptr); // memory is full, this must return nullptr
    BOOST_CHECK(b.alloc(0) == nullptr);
    for (int x=0; x<1024; ++x)
        b.free(addr[x]);
    addr.clear();
    BOOST_CHECK(b.stats().total == synth_size);
    BOOST_CHECK(b.stats().free == synth_size);

    // Now in the other direction...
    for (int x=0; x<1024; ++x)
        addr.push_back(b.alloc(1024));
    for (int x=0; x<1024; ++x)
        b.free(addr[1023-x]);
    addr.clear();

    // Now allocate in smaller unequal chunks, then deallocate haphazardly
    // Not all the chunks will succeed allocating, but freeing nullptr is
    // allowed so that is no problem.
    for (int x=0; x<2048; ++x)
        addr.push_back(b.alloc(x+1));
    for (int x=0; x<2048; ++x)
        b.free(addr[((x*23)%2048)^242]);
    addr.clear();

    // Go entirely wild: free and alloc interleaved,
    // generate targets and sizes using pseudo-randomness.
    for (int x=0; x<2048; ++x)
        addr.push_back(nullptr);
    uint32_t s = 0x12345678;
    for (int x=0; x<5000; ++x) {
        int idx = s & (addr.size()-1);
        if (s & 0x80000000) {
            b.free(addr[idx]);
            addr[idx] = nullptr;
        } else if(!addr[idx]) {
            addr[idx] = b.alloc((s >> 16) & 2047);
        }
        bool lsb = s & 1;
        s >>= 1;
        if (lsb)
            s ^= 0xf00f00f0; // LFSR period 0xf7ffffe0
    }
    for (void *ptr: addr)
        b.free(ptr);
    addr.clear();

    BOOST_CHECK(b.stats().total == synth_size);
    BOOST_CHECK(b.stats().free == synth_size);
}

/** Mock LockedPageAllocator for testing */
class TestLockedPageAllocator: public LockedPageAllocator
{
public:
    TestLockedPageAllocator(int count_in, int lockedcount_in): count(count_in), lockedcount(lockedcount_in) {}
    void* AllocateLocked(size_t len, bool *lockingSuccess) override
    {
        *lockingSuccess = false;
        if (count > 0) {
            --count;

            if (lockedcount > 0) {
                --lockedcount;
                *lockingSuccess = true;
            }

            return reinterpret_cast<void*>(uint64_t{static_cast<uint64_t>(0x08000000) + (count << 24)}); // Fake address, do not actually use this memory
        }
        return nullptr;
    }
    void FreeLocked(void* addr, size_t len) override
    {
    }
    size_t GetLimit() override
    {
        return std::numeric_limits<size_t>::max();
    }
private:
    int count;
    int lockedcount;
};

BOOST_AUTO_TEST_CASE(lockedpool_tests_mock)
{
    // Test over three virtual arenas, of which one will succeed being locked
    std::unique_ptr<LockedPageAllocator> x = std::make_unique<TestLockedPageAllocator>(3, 1);
    LockedPool pool(std::move(x));
    BOOST_CHECK(pool.stats().total == 0);
    BOOST_CHECK(pool.stats().locked == 0);

    // Ensure unreasonable requests are refused without allocating anything
    void *invalid_toosmall = pool.alloc(0);
    BOOST_CHECK(invalid_toosmall == nullptr);
    BOOST_CHECK(pool.stats().used == 0);
    BOOST_CHECK(pool.stats().free == 0);
    void *invalid_toobig = pool.alloc(LockedPool::ARENA_SIZE+1);
    BOOST_CHECK(invalid_toobig == nullptr);
    BOOST_CHECK(pool.stats().used == 0);
    BOOST_CHECK(pool.stats().free == 0);

    void *a0 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a0);
    BOOST_CHECK(pool.stats().locked == LockedPool::ARENA_SIZE);
    void *a1 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a1);
    void *a2 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a2);
    void *a3 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a3);
    void *a4 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a4);
    void *a5 = pool.alloc(LockedPool::ARENA_SIZE / 2);
    BOOST_CHECK(a5);
    // We've passed a count of three arenas, so this allocation should fail
    void *a6 = pool.alloc(16);
    BOOST_CHECK(!a6);

    pool.free(a0);
    pool.free(a2);
    pool.free(a4);
    pool.free(a1);
    pool.free(a3);
    pool.free(a5);
    BOOST_CHECK(pool.stats().total == 3*LockedPool::ARENA_SIZE);
    BOOST_CHECK(pool.stats().locked == LockedPool::ARENA_SIZE);
    BOOST_CHECK(pool.stats().used == 0);
}

// These tests used the live LockedPoolManager object, this is also used
// by other tests so the conditions are somewhat less controllable and thus the
// tests are somewhat more error-prone.
BOOST_AUTO_TEST_CASE(lockedpool_tests_live)
{
    LockedPoolManager &pool = LockedPoolManager::Instance();
    LockedPool::Stats initial = pool.stats();

    void *a0 = pool.alloc(16);
    BOOST_CHECK(a0);
    // Test reading and writing the allocated memory
    *((uint32_t*)a0) = 0x1234;
    BOOST_CHECK(*((uint32_t*)a0) == 0x1234);

    pool.free(a0);
    BOOST_CHECK_EXCEPTION(pool.free(a0), std::runtime_error, HasReason{"Arena: invalid or double free"});
    // If more than one new arena was allocated for the above tests, something is wrong
    BOOST_CHECK(pool.stats().total <= (initial.total + LockedPool::ARENA_SIZE));
    // Usage must be back to where it started
    BOOST_CHECK(pool.stats().used == initial.used);
}

BOOST_AUTO_TEST_CASE(hugepages_tests)
{
    constexpr size_t alignment{alignof(std::max_align_t)};
    for (const size_t bytes : {size_t{1}, HUGE_PAGE_BYTES, HUGE_PAGE_BYTES + 1, 3 * HUGE_PAGE_BYTES}) {
        auto* p{static_cast<std::byte*>(AllocateHugePages(bytes, alignment))};
        BOOST_CHECK(reinterpret_cast<uintptr_t>(p) % alignment == 0);
#ifdef __linux__
        // On Linux, the memory starts at a huge page boundary.
        BOOST_CHECK(reinterpret_cast<uintptr_t>(p) % HUGE_PAGE_BYTES == 0);
#endif
        // The memory is usable from its first to its last byte.
        std::fill_n(p, bytes, std::byte{0x5a});
        BOOST_CHECK(p[0] == std::byte{0x5a} && p[bytes - 1] == std::byte{0x5a});
        FreeHugePages(p, bytes, alignment);
    }
#ifdef __linux__
    BOOST_CHECK_THROW(AllocateHugePages(std::numeric_limits<size_t>::max(), alignment), std::bad_alloc);
#endif

    // Discarded memory stays usable.
    auto* p{static_cast<std::byte*>(AllocateHugePages(3 * HUGE_PAGE_BYTES, alignment))};
    std::fill_n(p, 3 * HUGE_PAGE_BYTES, std::byte{0x5a});
    DiscardHugePages(p, 3 * HUGE_PAGE_BYTES);
    std::fill_n(p, 3 * HUGE_PAGE_BYTES, std::byte{0xa5});
    BOOST_CHECK(std::all_of(p, p + 3 * HUGE_PAGE_BYTES, [](std::byte b) { return b == std::byte{0xa5}; }));
    FreeHugePages(p, 3 * HUGE_PAGE_BYTES, alignment);
}

BOOST_AUTO_TEST_CASE(hugepages_mode_tests)
{
    // The active mode is the one in brackets.
    BOOST_CHECK(ParseTransparentHugePages("[always] madvise never\n") == TransparentHugePages::ALWAYS);
    BOOST_CHECK(ParseTransparentHugePages("always [madvise] never\n") == TransparentHugePages::MADVISE);
    BOOST_CHECK(ParseTransparentHugePages("always madvise [never]\n") == TransparentHugePages::NEVER);
    BOOST_CHECK(!ParseTransparentHugePages("always madvise never\n"));
    BOOST_CHECK(!ParseTransparentHugePages("always madvise [never\n"));
    BOOST_CHECK(!ParseTransparentHugePages(""));
#ifndef __linux__
    BOOST_CHECK(!HugePagesAvailable());
#endif
    // Huge pages are only used where their mode can be read, and is not "never".
    if (HugePagesAvailable()) {
        const std::string settings{TransparentHugePagesSettings()};
        BOOST_CHECK(settings.starts_with("enabled=always,") || settings.starts_with("enabled=madvise,"));
    }
}

BOOST_AUTO_TEST_SUITE_END()
