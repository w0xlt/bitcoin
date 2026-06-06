// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <ios>

FUZZ_TARGET(staletips)
{
    DataStream stream{buffer};
    StaleTipData data;
    try {
        stream >> data;
    } catch (const std::ios_base::failure&) {
        return;
    }

    const auto [tip_hash, headers]{data.ReconstructHeaders()};
    assert(headers.size() == data.m_headers.size());
    assert(!headers.empty());
    assert(headers.front().hashPrevBlock == data.m_fork_point);
    assert(headers.back().GetHash() == tip_hash);

    DataStream serialized;
    serialized << data;
    DataStream roundtrip_stream{serialized};
    StaleTipData roundtrip;
    roundtrip_stream >> roundtrip;
    assert(roundtrip == data);
}
