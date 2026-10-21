// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_HUGEPAGES_H
#define BITCOIN_SUPPORT_HUGEPAGES_H

#include <util/byte_units.h>

#include <cstddef>

/** Size of a transparent huge page on x86-64, and on arm64 with 4 KiB base pages. */
inline constexpr std::size_t HUGE_PAGE_BYTES{2_MiB};

/**
 * Allocate memory that the operating system may back with transparent huge pages.
 *
 * Huge pages reduce TLB misses in large data structures that are accessed at random, like the
 * UTXO cache. On Linux the memory is mapped directly, aligned to HUGE_PAGE_BYTES and advised with
 * MADV_HUGEPAGE, which takes effect when transparent huge pages are in "always" or "madvise" mode.
 * Elsewhere this is equivalent to operator new.
 *
 * @param[in] bytes      Number of bytes to allocate.
 * @param[in] alignment  Required alignment, a power of two of at most HUGE_PAGE_BYTES.
 * @throws std::bad_alloc when the memory can not be allocated.
 */
void* AllocateHugePages(std::size_t bytes, std::size_t alignment);

/** Free memory returned by AllocateHugePages(), passing the same bytes and alignment. */
void FreeHugePages(void* p, std::size_t bytes, std::size_t alignment) noexcept;

/**
 * Discard the contents of memory returned by AllocateHugePages(), passing the same bytes, but
 * keep it allocated for reuse. On Linux the system may then reclaim it when memory is short.
 * Until it does, the memory keeps its huge pages, and reusing it does not have to fault them in
 * again. Reading the memory before writing it gives its old contents or zeros.
 */
void DiscardHugePages(void* p, std::size_t bytes) noexcept;

#endif // BITCOIN_SUPPORT_HUGEPAGES_H
