// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <hash.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <cassert>
#include <cstdint>
#include <memory>

static void PruneOneBlockFileScan(benchmark::Bench& bench)
{
    // Make the block index large enough to expose regressions in the prune path.
    static constexpr int NUM_BLOCK_INDEX_ENTRIES{200'000};

    const auto testing_setup{MakeNoLogFileContext<const TestingSetup>(ChainType::MAIN)};
    auto& blockman{testing_setup->m_node.chainman->m_blockman};

    {
        // Ensure block file 0 exists so PruneOneBlockFile(0) can run.
        const CBlock& genesis{testing_setup->m_node.chainman->GetParams().GenesisBlock()};
        const FlatFilePos pos{blockman.WriteBlock(genesis, /*nHeight=*/0)};
        assert(!pos.IsNull());
    }

    {
        LOCK(cs_main);

        for (int i = 0; i < NUM_BLOCK_INDEX_ENTRIES; ++i) {
            const uint256 hash{(HashWriter{} << i).GetHash()};
            CBlockIndex* const index{blockman.InsertBlockIndex(hash)};
            index->nFile = 1;
        }
        for (auto& [_, index] : blockman.m_block_index) {
            index.nFile = 1;
        }
    }

    bench.minEpochIterations(20).run([&] {
        LOCK(cs_main);
        blockman.PruneOneBlockFile(/*fileNumber=*/0);
    });
}

BENCHMARK(PruneOneBlockFileScan);
