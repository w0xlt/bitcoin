// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_NODE_BLOCKDOWNLOADCHAIN_IMPL_H
#define BITCOIN_NODE_BLOCKDOWNLOADCHAIN_IMPL_H

#include <memory>

class ChainstateManager;

namespace node {

class BlockDownloadChain;

std::unique_ptr<BlockDownloadChain> MakeValidationBlockDownloadChain(ChainstateManager& chainman);

} // namespace node

#endif // BITCOIN_NODE_BLOCKDOWNLOADCHAIN_IMPL_H
