// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>
#include <util/check.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>

namespace node {

std::optional<StaleTipMode> ParseStaleTipMode(std::string_view mode)
{
    if (mode == "none") return StaleTipMode::NONE;
    if (mode == "headers") return StaleTipMode::HEADERS;
    if (mode == "blocks") return StaleTipMode::BLOCKS;
    return std::nullopt;
}

void ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (argsman.IsArgNegated("-staletips")) {
        options.stale_tip_mode = StaleTipMode::NONE;
    } else if (auto value{argsman.GetArg("-staletips")}) {
        options.stale_tip_mode = *Assert(ParseStaleTipMode(*value));
    }

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;

    if (auto value{argsman.GetBoolArg("-blocksonly")}) options.ignore_incoming_txs = *value;

    if (auto value{argsman.GetBoolArg("-privatebroadcast")}) options.private_broadcast = *value;
}

} // namespace node
