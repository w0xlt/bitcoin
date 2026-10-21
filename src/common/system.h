// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMMON_SYSTEM_H
#define BITCOIN_COMMON_SYSTEM_H

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <util/time.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

/// Monotonic uptime (not affected by system time changes).
SteadyClock::duration GetUptime();

void SetupEnvironment();
[[nodiscard]] bool SetupNetworking();
#ifndef WIN32
std::string ShellEscape(const std::string& arg);
#endif
#if HAVE_SYSTEM
void runCommand(const std::string& strCommand);
#endif

/**
 * Return the number of cores available on the current system.
 * @note This does count virtual cores, such as those provided by HyperThreading.
 */
int GetNumCores();

/**
 * Return the total RAM available on the current system, if detectable.
 */
std::optional<uint64_t> TryGetTotalRam();

/**
 * Return the memory limit of the control groups (cgroups) of this process, like the limit of a
 * container, if there is one and it is detectable. Linux only.
 */
std::optional<uint64_t> TryGetCgroupMemoryLimit();

/**
 * The files that may hold memory limits for a process in the cgroups listed by
 * /proc/<pid>/cgroup, for cgroup v2 and the memory controller of cgroup v1. Includes the parent
 * cgroups, whose limits apply too.
 */
std::vector<std::string> CgroupMemoryLimitFiles(std::string_view proc_cgroup);

/** Parse a cgroup memory limit file. std::nullopt when there is no limit. */
std::optional<uint64_t> ParseCgroupMemoryLimit(std::string_view limit);

#endif // BITCOIN_COMMON_SYSTEM_H
