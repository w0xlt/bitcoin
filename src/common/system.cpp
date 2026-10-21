// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/system.h>

#include <util/fs.h>
#include <util/log.h>
#include <util/readwritefile.h>
#include <util/string.h>
#include <util/time.h>

#ifdef WIN32
#include <compat/compat.h>
#include <util/check.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef HAVE_MALLOPT_ARENA_MAX
#include <malloc.h>
#endif

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

using util::ReplaceAll;
using util::SplitString;

#ifndef WIN32
std::string ShellEscape(const std::string& arg)
{
    std::string escaped = arg;
    ReplaceAll(escaped, "'", "'\"'\"'");
    return "'" + escaped + "'";
}
#endif

#if HAVE_SYSTEM
void runCommand(const std::string& strCommand)
{
    if (strCommand.empty()) return;
    int nErr = ::system(strCommand.c_str());
    if (nErr) {
        LogWarning("runCommand error: system(%s) returned %d", strCommand, nErr);
    }
}
#endif

void SetupEnvironment()
{
#ifdef HAVE_MALLOPT_ARENA_MAX
    // glibc-specific: On 32-bit systems set the number of arenas to 1.
    // By default, since glibc 2.10, the C library will create up to two heap
    // arenas per core. This is known to cause excessive virtual address space
    // usage in our usage. Work around it by setting the maximum number of
    // arenas to 1.
    if (sizeof(void*) == 4) {
        mallopt(M_ARENA_MAX, 1);
    }
#endif

#if defined(WIN32)
    assert(GetACP() == CP_UTF8);
    // Set the default input/output charset is utf-8
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
#endif

#ifndef WIN32
    constexpr mode_t private_umask = 0077;
    umask(private_umask);
#endif
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

int GetNumCores()
{
    return std::thread::hardware_concurrency();
}

std::optional<uint64_t> TryGetTotalRam()
{
    static const auto total_ram{[]() -> std::optional<uint64_t> {
#ifdef WIN32
        if (MEMORYSTATUSEX m{}; (m.dwLength = sizeof(m), GlobalMemoryStatusEx(&m))) return m.ullTotalPhys;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__illumos__) || defined(__linux__)
        if (long p{sysconf(_SC_PHYS_PAGES)}, s{sysconf(_SC_PAGESIZE)}; p > 0 && s > 0) return 1ULL * p * s;
#endif
        return std::nullopt;
    }()};
    return total_ram;
}

std::optional<uint64_t> TryGetCgroupMemoryLimit()
{
    static const auto limit{[]() -> std::optional<uint64_t> {
#ifdef __linux__
        std::optional<uint64_t> limit;
        for (const auto& file : CgroupMemoryLimitFiles(ReadBinaryFile("/proc/self/cgroup").second)) {
            if (const auto bytes{ParseCgroupMemoryLimit(ReadBinaryFile(fs::PathFromString(file)).second)}) {
                limit = std::min(limit.value_or(*bytes), *bytes);
            }
        }
        return limit;
#else
        return std::nullopt;
#endif
    }()};
    return limit;
}

std::vector<std::string> CgroupMemoryLimitFiles(std::string_view proc_cgroup)
{
    std::vector<std::string> files;
    for (const auto& line : SplitString(proc_cgroup, '\n')) {
        // Each line is "hierarchy-ID:controller-list:cgroup-path", see cgroups(7).
        const auto controllers_begin{line.find(':')};
        if (controllers_begin == std::string::npos) continue;
        const auto path_begin{line.find(':', controllers_begin + 1)};
        if (path_begin == std::string::npos) continue;
        const std::string_view hierarchy{std::string_view{line}.substr(0, controllers_begin)};
        const auto controllers{SplitString(std::string_view{line}.substr(controllers_begin + 1, path_begin - controllers_begin - 1), ',')};
        std::string_view path{std::string_view{line}.substr(path_begin + 1)};
        if (!path.starts_with('/')) continue;

        std::string mount_point, limit_file;
        if (hierarchy == "0" && controllers == std::vector<std::string>{""}) {
            mount_point = "/sys/fs/cgroup";
            limit_file = "memory.max";
        } else if (std::ranges::find(controllers, "memory") != controllers.end()) {
            mount_point = "/sys/fs/cgroup/memory";
            limit_file = "memory.limit_in_bytes";
        } else {
            continue;
        }
        // In a container, the cgroup of the process may be mounted as the root, where its path
        // does not exist. Its limit is then found at the root.
        while (true) {
            files.push_back(mount_point + (path == "/" ? "" : std::string{path}) + "/" + limit_file);
            if (path == "/") break;
            path = path.substr(0, std::max<size_t>(path.rfind('/'), 1));
        }
    }
    return files;
}

std::optional<uint64_t> ParseCgroupMemoryLimit(std::string_view limit)
{
    // cgroup v2 has "max" when there is no limit, and cgroup v1 a number that exceeds the memory.
    uint64_t bytes{0};
    if (std::from_chars(limit.data(), limit.data() + limit.size(), bytes).ec != std::errc{}) return std::nullopt;
    return bytes;
}

namespace {
    const auto g_startup_time{SteadyClock::now()};
} // namespace

SteadyClock::duration GetUptime() { return SteadyClock::now() - g_startup_time; }
