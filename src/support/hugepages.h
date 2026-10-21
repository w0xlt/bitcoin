// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SUPPORT_HUGEPAGES_H
#define BITCOIN_SUPPORT_HUGEPAGES_H

#include <util/byte_units.h>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

/** Size of a transparent huge page on x86-64, and on arm64 with 4 KiB base pages. */
inline constexpr std::size_t HUGE_PAGE_BYTES{2_MiB};

/**
 * Allocate memory that the operating system may back with transparent huge pages.
 *
 * Huge pages reduce TLB misses in large data structures that are accessed at random, like the
 * UTXO cache. On Linux the memory is mapped directly and aligned to HUGE_PAGE_BYTES, which is
 * enough when transparent huge pages are in "always" mode. Otherwise it is also advised with
 * MADV_HUGEPAGE, which "madvise" mode needs. Elsewhere this is equivalent to operator new.
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

/** Modes of transparent huge pages, see /sys/kernel/mm/transparent_hugepage/enabled. */
enum class TransparentHugePages {
    ALWAYS,  //!< Used for all suitable memory
    MADVISE, //!< Used for memory advised with MADV_HUGEPAGE
    NEVER,   //!< Not used
};

/** Parse the contents of /sys/kernel/mm/transparent_hugepage/enabled, like "always [madvise] never". */
std::optional<TransparentHugePages> ParseTransparentHugePages(std::string_view enabled);

/**
 * Whether memory from AllocateHugePages() may be backed by huge pages. It may not be on systems
 * other than Linux, when transparent huge pages are disabled for the system ("never" mode) or
 * for this process (PR_SET_THP_DISABLE), when their mode can not be read, or when they are not
 * of HUGE_PAGE_BYTES. Regular allocations are better then: memory mapped by AllocateHugePages()
 * is returned to the system when freed, so it has to be faulted in again, page by page, when it
 * is allocated again.
 */
bool HugePagesAvailable();

/** The system's transparent huge pages settings, like "enabled=madvise, defrag=madvise", for logging. */
std::string TransparentHugePagesSettings();

#endif // BITCOIN_SUPPORT_HUGEPAGES_H
