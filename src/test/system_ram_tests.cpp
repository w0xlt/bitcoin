// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/system.h>
#include <util/byte_units.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(system_ram_tests)

BOOST_AUTO_TEST_CASE(total_ram)
{
    const auto total{TryGetTotalRam()};
    BOOST_REQUIRE(total);
    BOOST_CHECK_GE(*total, 1_GiB);
    BOOST_CHECK_LT(*total, 10'000_GiB); // ~10 TiB memory is unlikely
}

BOOST_AUTO_TEST_CASE(cgroup_memory_limit)
{
    using Files = std::vector<std::string>;
    // cgroup v2, including the parent cgroups, whose limits apply too.
    BOOST_CHECK(CgroupMemoryLimitFiles("0::/system.slice/bitcoind.service\n") == (Files{
        "/sys/fs/cgroup/system.slice/bitcoind.service/memory.max",
        "/sys/fs/cgroup/system.slice/memory.max",
        "/sys/fs/cgroup/memory.max",
    }));
    // In a container, the cgroup of the process may be its root.
    BOOST_CHECK(CgroupMemoryLimitFiles("0::/\n") == (Files{"/sys/fs/cgroup/memory.max"}));
    // cgroup v1 has a hierarchy for the memory controller, which may be shared with others.
    BOOST_CHECK(CgroupMemoryLimitFiles("12:cpu,cpuacct:/docker/abc\n4:memory:/docker/abc\n1:name=systemd:/docker/abc\n") == (Files{
        "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory/docker/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    }));
    BOOST_CHECK(CgroupMemoryLimitFiles("5:memory,cpuset:/\n") == (Files{"/sys/fs/cgroup/memory/memory.limit_in_bytes"}));
    // Hybrid systems list both.
    BOOST_CHECK(CgroupMemoryLimitFiles("4:memory:/user.slice\n0::/user.slice\n") == (Files{
        "/sys/fs/cgroup/memory/user.slice/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/user.slice/memory.max",
        "/sys/fs/cgroup/memory.max",
    }));
    // Other controllers, and malformed lines, have no memory limits.
    BOOST_CHECK(CgroupMemoryLimitFiles("1:net_cls:/\n0:cpu:/\n0::relative\n0:/\n\n").empty());
    BOOST_CHECK(CgroupMemoryLimitFiles("").empty());

    BOOST_CHECK(ParseCgroupMemoryLimit("max\n") == std::nullopt);
    BOOST_CHECK(ParseCgroupMemoryLimit("") == std::nullopt);
    BOOST_CHECK(ParseCgroupMemoryLimit("4294967296\n") == 4_GiB);
    BOOST_CHECK(ParseCgroupMemoryLimit("9223372036854771712\n") == 9223372036854771712ULL);

    // Whatever the limit of this process, it is not tiny.
    if (const auto limit{TryGetCgroupMemoryLimit()}) BOOST_CHECK_GE(*limit, 1_MiB);
}

BOOST_AUTO_TEST_SUITE_END()
