// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <support/hugepages.h>

#include <util/overflow.h>

#include <cassert>
#include <charconv>
#include <cstdint>
#include <limits>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

#ifdef __linux__
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

namespace {
//! The active choice of a setting like "always [madvise] never", which is the one in brackets.
std::optional<std::string_view> ActiveChoice(std::string_view setting)
{
    const auto begin{setting.find('[')};
    const auto end{setting.find(']', begin)};
    if (begin == std::string_view::npos || end == std::string_view::npos) return std::nullopt;
    return setting.substr(begin + 1, end - begin - 1);
}
} // namespace

std::optional<TransparentHugePages> ParseTransparentHugePages(std::string_view enabled)
{
    const auto mode{ActiveChoice(enabled)};
    if (mode == "always") return TransparentHugePages::ALWAYS;
    if (mode == "madvise") return TransparentHugePages::MADVISE;
    if (mode == "never") return TransparentHugePages::NEVER;
    return std::nullopt;
}

#if defined(MADV_HUGEPAGE)

namespace {
//! Mappings are rounded up to whole huge pages, so that no two of them share a huge page.
std::size_t MappingBytes(std::size_t bytes)
{
    return CeilDiv(bytes, HUGE_PAGE_BYTES) * HUGE_PAGE_BYTES;
}

//! A setting in /sys/kernel/mm/transparent_hugepage. std::nullopt if it can not be read.
std::optional<std::string> ReadSetting(const char* name)
{
    const std::string path{std::string{"/sys/kernel/mm/transparent_hugepage/"} + name};
    char setting[64];
    ssize_t setting_bytes{-1};
    if (const int fd{open(path.c_str(), O_RDONLY | O_CLOEXEC)}; fd != -1) {
        setting_bytes = read(fd, setting, sizeof(setting));
        close(fd);
    }
    if (setting_bytes <= 0) return std::nullopt;
    return std::string{setting, static_cast<std::size_t>(setting_bytes)};
}

//! The system's transparent huge pages mode, which is read once. std::nullopt if it can not be read.
std::optional<TransparentHugePages> SystemTransparentHugePages()
{
    static const std::optional<TransparentHugePages> mode{[]() -> std::optional<TransparentHugePages> {
        const auto enabled{ReadSetting("enabled")};
        if (!enabled) return std::nullopt;
        return ParseTransparentHugePages(*enabled);
    }()};
    return mode;
}

//! The size of the system's transparent huge pages, which is read once. std::nullopt if it can not be read.
std::optional<std::size_t> SystemHugePageBytes()
{
    static const std::optional<std::size_t> huge_page_bytes{[]() -> std::optional<std::size_t> {
        const auto size{ReadSetting("hpage_pmd_size")};
        std::size_t bytes{0};
        if (!size || std::from_chars(size->data(), size->data() + size->size(), bytes).ec != std::errc{}) return std::nullopt;
        return bytes;
    }()};
    return huge_page_bytes;
}
} // namespace

bool HugePagesAvailable()
{
    // Memory aligned to HUGE_PAGE_BYTES does not get huge pages of another size, like those on
    // arm64 with 16 or 64 KiB base pages. PR_GET_THP_DISABLE returns 1 when transparent huge
    // pages are disabled for this process.
    const auto mode{SystemTransparentHugePages()};
    return mode && *mode != TransparentHugePages::NEVER && SystemHugePageBytes() == HUGE_PAGE_BYTES &&
           prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) != 1;
}

std::string TransparentHugePagesSettings()
{
    const auto choice{[](const char* name) -> std::string {
        const auto setting{ReadSetting(name)};
        const auto active{setting ? ActiveChoice(*setting) : std::nullopt};
        return active ? std::string{*active} : "unknown";
    }};
    return "enabled=" + choice("enabled") + ", defrag=" + choice("defrag");
}

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

    // Best effort: when transparent huge pages are disabled, the memory uses regular pages. In
    // "always" mode, the aligned memory gets huge pages without advice. Advising it anyway would,
    // with the default "defrag" setting, let page faults stall to reclaim and compact memory when
    // no huge page is free.
    void* memory{reinterpret_cast<void*>(aligned)};
    if (SystemTransparentHugePages() != TransparentHugePages::ALWAYS) madvise(memory, size, MADV_HUGEPAGE);
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

bool HugePagesAvailable()
{
    return false;
}

std::string TransparentHugePagesSettings()
{
    return "unsupported";
}

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
