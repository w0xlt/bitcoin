// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <support/hugepages.h>

#include <util/overflow.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <new>

#ifdef __linux__
#include <sys/mman.h>
#endif

#if defined(MADV_HUGEPAGE)

namespace {
//! Mappings are rounded up to whole huge pages, so that no two of them share a huge page.
std::size_t MappingBytes(std::size_t bytes)
{
    return CeilDiv(bytes, HUGE_PAGE_BYTES) * HUGE_PAGE_BYTES;
}
} // namespace

void* AllocateHugePages(std::size_t bytes, std::size_t alignment)
{
    // The memory is aligned to HUGE_PAGE_BYTES, which satisfies any smaller power of two.
    assert(alignment <= HUGE_PAGE_BYTES && (alignment & (alignment - 1)) == 0);
    if (bytes > std::numeric_limits<std::size_t>::max() - 2 * HUGE_PAGE_BYTES) throw std::bad_alloc{};
    const std::size_t size{MappingBytes(bytes)};

    // mmap only guarantees page alignment. Reserve one extra huge page, then unmap the parts
    // outside the huge page aligned range.
    const std::size_t reserved_size{size + HUGE_PAGE_BYTES};
    void* reserved{mmap(nullptr, reserved_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)};
    if (reserved == MAP_FAILED) throw std::bad_alloc{};
    const auto begin{reinterpret_cast<std::uintptr_t>(reserved)};
    const auto aligned{CeilDiv(begin, HUGE_PAGE_BYTES) * HUGE_PAGE_BYTES};
    if (aligned != begin) munmap(reserved, aligned - begin);
    munmap(reinterpret_cast<void*>(aligned + size), begin + reserved_size - (aligned + size));

    // Best effort: when transparent huge pages are disabled, the memory uses regular pages.
    void* memory{reinterpret_cast<void*>(aligned)};
    madvise(memory, size, MADV_HUGEPAGE);
    return memory;
}

void FreeHugePages(void* p, std::size_t bytes, std::size_t /*alignment*/) noexcept
{
    munmap(p, MappingBytes(bytes));
}

void DiscardHugePages(void* p, std::size_t bytes) noexcept
{
#ifdef MADV_FREE
    // Best effort: kernels before Linux 4.5 do not support MADV_FREE, and keep the memory.
    madvise(p, MappingBytes(bytes), MADV_FREE);
#endif
}

#else

void* AllocateHugePages(std::size_t bytes, std::size_t alignment)
{
    return ::operator new(bytes, std::align_val_t{alignment});
}

void FreeHugePages(void* p, std::size_t /*bytes*/, std::size_t alignment) noexcept
{
    ::operator delete(p, std::align_val_t{alignment});
}

void DiscardHugePages(void* /*p*/, std::size_t /*bytes*/) noexcept {}

#endif
