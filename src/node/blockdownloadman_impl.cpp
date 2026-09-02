// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/blockdownloadman_impl.h>

#include <util/check.h>

#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <utility>

namespace node {
namespace {

static constexpr unsigned int BLOCK_DOWNLOAD_WINDOW{1024};
static constexpr unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS{288};
static constexpr size_t MAX_BLOCKS_IN_TRANSIT_PER_PEER{16};
/** One initial attempt followed by no more than two stale-view retries. */
static constexpr int MAX_PLANNING_ATTEMPTS{3};

struct PlanningInput {
    NodeId m_peer;
    uint64_t m_planning_generation;
    uint64_t m_in_flight_generation;
    BlockDownloadConnectionInfo m_connection_info;
    std::optional<BlockDownloadBlock> m_best_known;
    std::optional<BlockDownloadBlock> m_last_common;
    size_t m_request_count;
    size_t m_budget;
    std::map<uint256, NodeId> m_in_flight;
};

struct PlanningResult {
    std::vector<BlockDownloadBlock> m_blocks;
    std::optional<BlockDownloadBlock> m_last_common;
    std::optional<NodeId> m_staller;
    std::optional<BlockDownloadBlock> m_staller_block;
    bool m_assumeutxo_blocked{false};
    bool m_last_common_evaluated{false};
    bool m_revalidate_historical_identity{false};
};

void SelectPath(
    const PlanningInput& input,
    std::span<const BlockDownloadCandidate> path,
    const BlockDownloadBlock& best_known,
    int window_end,
    bool update_last_common,
    PlanningResult& result)
{
    NodeId waiting_for{-1};
    for (const auto& candidate : path) {
        if (!candidate.m_valid_tree) return;
        if (!input.m_connection_info.m_can_serve_witness && candidate.m_segwit_active) return;

        if (candidate.m_have_data || (update_last_common && candidate.m_in_active_chain)) {
            // Linked downloaded side-chain blocks advance last-common too. This
            // is what lets a reorg download move its bounded window forward.
            if (update_last_common && candidate.m_have_chain_txs) {
                result.m_last_common = candidate.m_block;
            }
            continue;
        }

        if (const auto it{input.m_in_flight.find(candidate.m_block.m_hash)}; it != input.m_in_flight.end()) {
            if (waiting_for == -1) waiting_for = it->second;
            continue;
        }

        if (candidate.m_block.m_height > window_end) {
            if (update_last_common && result.m_blocks.empty() &&
                waiting_for != -1 && waiting_for != input.m_peer) {
                result.m_staller = waiting_for;
                result.m_staller_block = candidate.m_block;
            }
            return;
        }

        if (input.m_connection_info.m_limited_peer &&
            best_known.m_height - candidate.m_block.m_height >=
                static_cast<int>(NODE_NETWORK_LIMITED_MIN_BLOCKS) - 2) {
            continue;
        }

        result.m_blocks.push_back(candidate.m_block);
        if (result.m_blocks.size() == input.m_budget) return;
    }
}

PlanningResult PlanDownloads(const PlanningInput& input, const BlockDownloadChainSnapshot& snapshot)
{
    PlanningResult result;
    result.m_last_common = input.m_last_common;
    const auto& best_known{snapshot.m_resolved_best_known};

    if (best_known && snapshot.m_active_tip &&
        best_known->m_chain_work >= snapshot.m_active_tip->m_chain_work &&
        best_known->m_chain_work >= snapshot.m_minimum_chain_work) {
        if (snapshot.m_snapshot_base &&
            snapshot.m_assumeutxo_state == BlockDownloadAssumeutxoState::UNVALIDATED &&
            !snapshot.m_best_known_has_snapshot_base) {
            result.m_assumeutxo_blocked = true;
        } else if (snapshot.m_last_common_block) {
            result.m_last_common_evaluated = true;
            result.m_last_common = snapshot.m_last_common_block;
            if (*snapshot.m_last_common_block != *best_known) {
                SelectPath(
                    input,
                    snapshot.m_normal_path,
                    *best_known,
                    snapshot.m_normal_window_end,
                    /*update_last_common=*/true,
                    result);
            }
        }
    }

    // Preserve current-chainstate priority, then fill the remaining budget
    // from the background chainstate when this peer can provide its target.
    if (input.m_connection_info.m_limited_peer ||
        !snapshot.m_historical_requested ||
        result.m_blocks.size() >= input.m_budget ||
        !best_known) {
        return result;
    }
    result.m_revalidate_historical_identity = true;
    if (!snapshot.m_best_known_has_historical_target) return result;
    SelectPath(
        input,
        snapshot.m_historical_path,
        *best_known,
        snapshot.m_historical_window_end,
        /*update_last_common=*/false,
        result);
    return result;
}

} // namespace

std::unique_ptr<BlockDownloadManager> MakeBlockDownloadManager(std::unique_ptr<BlockDownloadChain> chain)
{
    return std::make_unique<BlockDownloadManagerImpl>(std::move(chain));
}

BlockDownloadManagerImpl::BlockDownloadManagerImpl(std::unique_ptr<BlockDownloadChain> chain)
    : m_chain{std::move(chain)}
{
    Assume(m_chain != nullptr);
}

void BlockDownloadManagerImpl::ConnectedPeer(NodeId peer, const BlockDownloadConnectionInfo& info)
{
    LOCK(m_mutex);
    auto it{m_peer_states.find(peer)};
    const bool inserted{it == m_peer_states.end()};
    if (inserted) {
        it = m_peer_states.try_emplace(peer, info, ++m_next_peer_generation).first;
    }
    auto& state{it->second};
    if (inserted) {
        m_num_preferred_download_peers += info.m_preferred_download;
        return;
    }

    Assume(state.m_connection_info.m_is_inbound == info.m_is_inbound);
    if (state.m_connection_info.m_preferred_download == info.m_preferred_download &&
        state.m_connection_info.m_can_serve_witness == info.m_can_serve_witness &&
        state.m_connection_info.m_limited_peer == info.m_limited_peer) {
        return;
    }

    m_num_preferred_download_peers +=
        static_cast<int>(info.m_preferred_download) - static_cast<int>(state.m_connection_info.m_preferred_download);
    Assume(m_num_preferred_download_peers >= 0);
    const bool planning_changed{
        state.m_connection_info.m_can_serve_witness != info.m_can_serve_witness ||
        state.m_connection_info.m_limited_peer != info.m_limited_peer};
    state.m_connection_info.m_preferred_download = info.m_preferred_download;
    state.m_connection_info.m_can_serve_witness = info.m_can_serve_witness;
    state.m_connection_info.m_limited_peer = info.m_limited_peer;
    if (planning_changed) {
        BumpPlanningGenerationLocked(state);
    } else {
        BumpPeerGenerationLocked(state);
    }
}

void BlockDownloadManagerImpl::DisconnectedPeer(NodeId peer)
{
    LOCK(m_mutex);
    const auto peer_it{m_peer_states.find(peer)};
    if (peer_it == m_peer_states.end()) return;

    auto& state{peer_it->second};
    for (auto queue_it{state.m_requests.begin()}; queue_it != state.m_requests.end(); ++queue_it) {
        auto range{m_requests_by_hash.equal_range(queue_it->m_block.m_hash)};
        for (auto index_it{range.first}; index_it != range.second;) {
            if (index_it->second.m_peer == peer) {
                index_it = m_requests_by_hash.erase(index_it);
            } else {
                ++index_it;
            }
        }
    }
    if (!state.m_requests.empty()) {
        --m_peers_downloading_from;
        Assume(m_peers_downloading_from >= 0);
        ++m_in_flight_generation;
    }
    m_num_preferred_download_peers -= state.m_connection_info.m_preferred_download;
    m_num_sync_started -= state.m_sync_started;
    Assume(m_num_preferred_download_peers >= 0);
    Assume(m_num_sync_started >= 0);
    for (auto it{m_block_sources.begin()}; it != m_block_sources.end();) {
        if (it->second.m_peer == peer) {
            it = m_block_sources.erase(it);
        } else {
            ++it;
        }
    }
    m_peer_states.erase(peer_it);
}

void BlockDownloadManagerImpl::ProcessBlockAvailability(NodeId peer)
{
    uint64_t availability_generation;
    std::optional<uint256> pending;
    std::optional<BlockDownloadBlock> best_known;
    {
        LOCK(m_mutex);
        const auto it{m_peer_states.find(peer)};
        if (it == m_peer_states.end() || !it->second.m_pending_block_hash) return;
        availability_generation = it->second.m_availability_generation;
        pending = it->second.m_pending_block_hash;
        best_known = it->second.m_best_known_block;
    }

    BlockDownloadChainQuery query;
    query.m_pending_hash = pending;
    const auto snapshot{m_chain->Capture(query)};
    if (!snapshot.m_pending_block || snapshot.m_pending_block->m_chain_work <= 0) return;

    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() ||
        it->second.m_availability_generation != availability_generation ||
        it->second.m_pending_block_hash != pending ||
        it->second.m_best_known_block != best_known) {
        return;
    }

    auto& state{it->second};
    if (!state.m_best_known_block ||
        snapshot.m_pending_block->m_chain_work >= state.m_best_known_block->m_chain_work) {
        state.m_best_known_block = snapshot.m_pending_block;
    }
    state.m_pending_block_hash.reset();
    BumpAvailabilityGenerationLocked(state);
}

void BlockDownloadManagerImpl::UpdateBlockAvailability(NodeId peer, const uint256& hash)
{
    uint64_t availability_generation;
    std::optional<uint256> pending;
    std::optional<BlockDownloadBlock> best_known;
    {
        LOCK(m_mutex);
        const auto it{m_peer_states.find(peer)};
        if (it == m_peer_states.end()) return;
        availability_generation = it->second.m_availability_generation;
        pending = it->second.m_pending_block_hash;
        best_known = it->second.m_best_known_block;
    }

    BlockDownloadChainQuery query;
    query.m_pending_hash = pending;
    query.m_announced_hash = hash;
    const auto snapshot{m_chain->Capture(query)};

    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() ||
        it->second.m_availability_generation != availability_generation ||
        it->second.m_pending_block_hash != pending ||
        it->second.m_best_known_block != best_known) {
        return;
    }

    auto& state{it->second};
    auto new_best{state.m_best_known_block};
    auto new_pending{state.m_pending_block_hash};
    if (snapshot.m_pending_block && snapshot.m_pending_block->m_chain_work > 0) {
        if (!new_best || snapshot.m_pending_block->m_chain_work >= new_best->m_chain_work) {
            new_best = snapshot.m_pending_block;
        }
        new_pending.reset();
    }
    if (snapshot.m_announced_block && snapshot.m_announced_block->m_chain_work > 0) {
        if (!new_best || snapshot.m_announced_block->m_chain_work >= new_best->m_chain_work) {
            new_best = snapshot.m_announced_block;
        }
    } else {
        new_pending = hash.IsNull() ? std::nullopt : std::optional{hash};
    }

    if (new_best == state.m_best_known_block && new_pending == state.m_pending_block_hash) return;
    state.m_best_known_block = std::move(new_best);
    state.m_pending_block_hash = std::move(new_pending);
    BumpAvailabilityGenerationLocked(state);
}

bool BlockDownloadManagerImpl::PeerHasHeader(NodeId peer, const uint256& target_hash) const
{
    std::optional<BlockDownloadBlock> best_known;
    std::optional<BlockDownloadBlock> best_header_sent;
    {
        LOCK(m_mutex);
        const auto it{m_peer_states.find(peer)};
        if (it == m_peer_states.end()) return false;
        best_known = it->second.m_best_known_block;
        best_header_sent = it->second.m_best_header_sent;
    }

    BlockDownloadChainQuery query;
    query.m_ancestor_hash = target_hash;
    query.m_best_known_hash = best_known ? std::optional{best_known->m_hash} : std::nullopt;
    query.m_best_header_sent_hash = best_header_sent ? std::optional{best_header_sent->m_hash} : std::nullopt;
    const auto snapshot{m_chain->Capture(query)};
    return snapshot.m_ancestor_of_best_known || snapshot.m_ancestor_of_best_header_sent;
}

void BlockDownloadManagerImpl::RecordBestHeaderSent(NodeId peer, const BlockDownloadBlock& block)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() || it->second.m_best_header_sent == block) return;
    it->second.m_best_header_sent = block;
    BumpPeerGenerationLocked(it->second);
}

BlockDownloadBatch BlockDownloadManagerImpl::PlanAndReserve(
    NodeId peer,
    unsigned int budget,
    std::chrono::microseconds now,
    bool allow_historical)
{
    if (budget == 0) return {};

    // A pending availability lookup is itself generation-checked and never
    // calls the provider while holding the manager mutex.
    ProcessBlockAvailability(peer);

    for (int attempt{0}; attempt < MAX_PLANNING_ATTEMPTS; ++attempt) {
        std::optional<PlanningInput> input;
        {
            LOCK(m_mutex);
            const auto peer_it{m_peer_states.find(peer)};
            if (peer_it == m_peer_states.end()) return {};
            const auto& state{peer_it->second};
            const size_t remaining{
                state.m_requests.size() < MAX_BLOCKS_IN_TRANSIT_PER_PEER
                    ? MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.m_requests.size()
                    : 0};
            if (remaining == 0) return {};

            input.emplace(PlanningInput{
                .m_peer = peer,
                .m_planning_generation = state.m_planning_generation,
                .m_in_flight_generation = m_in_flight_generation,
                .m_connection_info = state.m_connection_info,
                .m_best_known = state.m_best_known_block,
                .m_last_common = state.m_last_common_block,
                .m_request_count = state.m_requests.size(),
                .m_budget = std::min<size_t>(budget, remaining),
                .m_in_flight = {},
            });
            for (auto it{m_requests_by_hash.begin()}; it != m_requests_by_hash.end();) {
                const auto range{m_requests_by_hash.equal_range(it->first)};
                input->m_in_flight.emplace(it->first, it->second.m_peer);
                it = range.second;
            }
        }

        BlockDownloadChainQuery query;
        query.m_best_known_hash = input->m_best_known ? std::optional{input->m_best_known->m_hash} : std::nullopt;
        query.m_last_common_hash = input->m_last_common ? std::optional{input->m_last_common->m_hash} : std::nullopt;
        query.m_plan_blocks = true;
        query.m_include_historical = allow_historical && !input->m_connection_info.m_limited_peer;
        query.m_download_window = BLOCK_DOWNLOAD_WINDOW;
        BlockDownloadChainSnapshot snapshot{m_chain->Capture(query)};
        const PlanningResult plan{PlanDownloads(*input, snapshot)};
        snapshot.m_revalidate_historical_identity = plan.m_revalidate_historical_identity;
        snapshot.m_revalidation_blocks = plan.m_blocks;
        const auto add_revalidation_block = [&](const std::optional<BlockDownloadBlock>& block) {
            if (block && std::ranges::none_of(snapshot.m_revalidation_blocks, [&](const auto& existing) {
                    return existing.m_hash == block->m_hash;
                })) {
                snapshot.m_revalidation_blocks.push_back(*block);
            }
        };
        if (plan.m_last_common_evaluated) add_revalidation_block(plan.m_last_common);
        add_revalidation_block(plan.m_staller_block);

        std::optional<NodeId> newly_stalling;
        const auto commit = [&]() EXCLUSIVE_LOCKS_REQUIRED(!m_mutex) {
            LOCK(m_mutex);
            const auto peer_it{m_peer_states.find(peer)};
            if (peer_it == m_peer_states.end()) return false;
            auto& state{peer_it->second};
            if (state.m_planning_generation != input->m_planning_generation ||
                state.m_best_known_block != input->m_best_known ||
                state.m_last_common_block != input->m_last_common ||
                state.m_requests.size() != input->m_request_count ||
                m_in_flight_generation != input->m_in_flight_generation ||
                state.m_requests.size() + plan.m_blocks.size() > MAX_BLOCKS_IN_TRANSIT_PER_PEER ||
                plan.m_blocks.size() > input->m_budget) {
                return false;
            }

            std::set<uint256> proposal_hashes;
            for (const auto& block : plan.m_blocks) {
                if (!proposal_hashes.insert(block.m_hash).second || m_requests_by_hash.contains(block.m_hash)) {
                    return false;
                }
            }

            // All rejection checks precede every mutation. From here through
            // the end of the callback the batch, last-common, and stalling
            // transitions form one manager-mutex transaction.
            if (state.m_last_common_block != plan.m_last_common) {
                state.m_last_common_block = plan.m_last_common;
                BumpPlanningGenerationLocked(state);
            }
            for (const auto& block : plan.m_blocks) {
                state.m_requests.push_back({block, {}});
                const auto queue_it{std::prev(state.m_requests.end())};
                if (state.m_requests.size() == 1) {
                    state.m_downloading_since = now;
                    ++m_peers_downloading_from;
                }
                m_requests_by_hash.emplace(block.m_hash, IndexedRequest{peer, queue_it});
                BumpPlanningGenerationLocked(state);
                ++m_in_flight_generation;
            }

            if (plan.m_blocks.empty() && state.m_requests.empty() && plan.m_staller) {
                const auto staller_it{m_peer_states.find(*plan.m_staller)};
                if (staller_it != m_peer_states.end() &&
                    staller_it->second.m_stalling_since == std::chrono::microseconds{0} &&
                    now != std::chrono::microseconds{0}) {
                    staller_it->second.m_stalling_since = now;
                    BumpPeerGenerationLocked(staller_it->second);
                    newly_stalling = *plan.m_staller;
                }
            }
            return true;
        };

        if (m_chain->Revalidate(snapshot, plan.m_blocks, commit)) {
            return {
                .m_blocks = plan.m_blocks,
                .m_staller = newly_stalling,
                .m_assumeutxo_blocked = plan.m_assumeutxo_blocked,
            };
        }
    }
    return {};
}

void BlockDownloadManagerImpl::BumpPeerGenerationLocked(PeerRequestState& state)
{
    state.m_generation = ++m_next_peer_generation;
}

void BlockDownloadManagerImpl::BumpPlanningGenerationLocked(PeerRequestState& state)
{
    BumpPeerGenerationLocked(state);
    state.m_planning_generation = state.m_generation;
}

void BlockDownloadManagerImpl::BumpAvailabilityGenerationLocked(PeerRequestState& state)
{
    BumpPlanningGenerationLocked(state);
    state.m_availability_generation = state.m_generation;
}

BlockInFlightInfo BlockDownloadManagerImpl::GetBlockInFlightInfoLocked(const uint256& hash, NodeId peer) const
{
    BlockInFlightInfo result;
    const auto range{m_requests_by_hash.equal_range(hash)};
    result.m_request_count = std::distance(range.first, range.second);
    if (range.first != range.second) result.m_first_peer = range.first->second.m_peer;
    result.m_first_in_flight = result.m_request_count == 0 || result.m_first_peer == peer;

    for (auto it{range.first}; it != range.second; ++it) {
        if (it->second.m_peer != peer) continue;
        result.m_requested_from_peer = true;
        result.m_partial_block = it->second.m_queue_it->m_partial_block;
        break;
    }
    return result;
}

BlockRequestReservation BlockDownloadManagerImpl::ReserveBlockRequest(
    NodeId peer,
    const BlockDownloadBlock& block,
    std::chrono::microseconds now,
    std::shared_ptr<PartiallyDownloadedBlock> proposed_partial)
{
    LOCK(m_mutex);

    const BlockInFlightInfo before{GetBlockInFlightInfoLocked(block.m_hash, peer)};
    BlockRequestReservation result{
        .m_status = BlockRequestStatus::NEW,
        .m_requests_before = before.m_request_count,
        .m_first_in_flight = before.m_first_in_flight,
        .m_partial_block = before.m_partial_block,
    };

    const auto peer_it{m_peer_states.find(peer)};
    if (peer_it == m_peer_states.end()) {
        result.m_status = BlockRequestStatus::PEER_NOT_FOUND;
        return result;
    }

    if (before.m_requested_from_peer) {
        if (!proposed_partial) {
            result.m_status = BlockRequestStatus::ALREADY_REQUESTED;
            return result;
        }
        if (before.m_partial_block) {
            result.m_status = BlockRequestStatus::DUPLICATE_COMPACT;
            return result;
        }

        const auto range{m_requests_by_hash.equal_range(block.m_hash)};
        for (auto it{range.first}; it != range.second; ++it) {
            if (it->second.m_peer == peer) {
                it->second.m_queue_it->m_partial_block = std::move(proposed_partial);
                result.m_partial_block = it->second.m_queue_it->m_partial_block;
                result.m_status = BlockRequestStatus::UPGRADED_TO_COMPACT;
                return result;
            }
        }
        Assume(false);
        result.m_status = BlockRequestStatus::ALREADY_REQUESTED;
        return result;
    }

    if (before.m_request_count >= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK) {
        result.m_status = BlockRequestStatus::MAX_REQUESTS_REACHED;
        return result;
    }

    auto& state{peer_it->second};
    state.m_requests.push_back({block, std::move(proposed_partial)});
    const auto queue_it{std::prev(state.m_requests.end())};
    if (state.m_requests.size() == 1) {
        state.m_downloading_since = now;
        ++m_peers_downloading_from;
    }
    m_requests_by_hash.emplace(block.m_hash, IndexedRequest{peer, queue_it});
    BumpPlanningGenerationLocked(state);
    ++m_in_flight_generation;
    result.m_partial_block = queue_it->m_partial_block;
    return result;
}

BlockRequestRemoval BlockDownloadManagerImpl::RemoveBlockRequest(
    const uint256& hash,
    std::optional<NodeId> from_peer,
    std::chrono::microseconds now)
{
    LOCK(m_mutex);
    const auto initial_range{m_requests_by_hash.equal_range(hash)};
    const size_t request_count{static_cast<size_t>(std::distance(initial_range.first, initial_range.second))};
    Assume(request_count <= MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK);

    BlockRequestRemoval result{.m_requests_before = request_count};
    auto range{initial_range};
    while (range.first != range.second) {
        const NodeId peer{range.first->second.m_peer};
        const auto queue_it{range.first->second.m_queue_it};
        if (from_peer && *from_peer != peer) {
            ++range.first;
            continue;
        }

        auto peer_it{m_peer_states.find(peer)};
        Assume(peer_it != m_peer_states.end());
        auto& state{peer_it->second};
        if (state.m_requests.begin() == queue_it) {
            state.m_downloading_since = std::max(state.m_downloading_since, now);
        }
        state.m_requests.erase(queue_it);
        if (state.m_requests.empty()) {
            --m_peers_downloading_from;
            Assume(m_peers_downloading_from >= 0);
        }
        state.m_stalling_since = std::chrono::microseconds{0};
        range.first = m_requests_by_hash.erase(range.first);
        BumpPlanningGenerationLocked(state);
        ++result.m_removed;
    }
    if (result.m_removed != 0) ++m_in_flight_generation;
    return result;
}

bool BlockDownloadManagerImpl::IsBlockRequested(const uint256& hash) const
{
    LOCK(m_mutex);
    return m_requests_by_hash.contains(hash);
}

bool BlockDownloadManagerImpl::IsBlockRequestedFromOutbound(const uint256& hash) const
{
    LOCK(m_mutex);
    const auto range{m_requests_by_hash.equal_range(hash)};
    for (auto it{range.first}; it != range.second; ++it) {
        const auto peer_it{m_peer_states.find(it->second.m_peer)};
        if (peer_it != m_peer_states.end() && !peer_it->second.m_connection_info.m_is_inbound) return true;
    }
    return false;
}

BlockInFlightInfo BlockDownloadManagerImpl::GetBlockInFlightInfo(const uint256& hash, NodeId peer) const
{
    LOCK(m_mutex);
    return GetBlockInFlightInfoLocked(hash, peer);
}

std::optional<PeerBlockDownloadSnapshot> BlockDownloadManagerImpl::GetPeerSnapshot(NodeId peer) const
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end()) return std::nullopt;

    PeerBlockDownloadSnapshot result;
    result.m_blocks.reserve(it->second.m_requests.size());
    for (const auto& queued : it->second.m_requests) result.m_blocks.push_back(queued.m_block);
    result.m_downloading_since = it->second.m_downloading_since;
    result.m_stalling_since = it->second.m_stalling_since;
    result.m_is_inbound = it->second.m_connection_info.m_is_inbound;
    result.m_preferred_download = it->second.m_connection_info.m_preferred_download;
    result.m_can_serve_witness = it->second.m_connection_info.m_can_serve_witness;
    result.m_limited_peer = it->second.m_connection_info.m_limited_peer;
    result.m_sync_started = it->second.m_sync_started;
    result.m_best_known_block = it->second.m_best_known_block;
    result.m_last_common_block = it->second.m_last_common_block;
    result.m_generation = it->second.m_generation;
    result.m_total_requests = m_requests_by_hash.size();
    result.m_peers_downloading_from = m_peers_downloading_from;
    result.m_num_preferred_download_peers = m_num_preferred_download_peers;
    result.m_num_sync_started = m_num_sync_started;
    return result;
}

BlockDownloadGlobalSnapshot BlockDownloadManagerImpl::GetGlobalSnapshot() const
{
    LOCK(m_mutex);
    return {
        .m_total_requests = m_requests_by_hash.size(),
        .m_peers_downloading_from = m_peers_downloading_from,
        .m_num_preferred_download_peers = m_num_preferred_download_peers,
        .m_num_sync_started = m_num_sync_started,
        .m_in_flight_generation = m_in_flight_generation,
        .m_last_tip_update = m_last_tip_update,
        .m_block_stalling_timeout = m_block_stalling_timeout,
    };
}

bool BlockDownloadManagerImpl::AllRequestsAreFor(const uint256& hash) const
{
    LOCK(m_mutex);
    return m_requests_by_hash.count(hash) == m_requests_by_hash.size();
}

bool BlockDownloadManagerImpl::StartStalling(NodeId peer, std::chrono::microseconds since)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (since == std::chrono::microseconds{0} ||
        it == m_peer_states.end() ||
        it->second.m_stalling_since != std::chrono::microseconds{0}) {
        return false;
    }
    it->second.m_stalling_since = since;
    BumpPeerGenerationLocked(it->second);
    return true;
}

bool BlockDownloadManagerImpl::ClearStalling(NodeId peer)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() || it->second.m_stalling_since == std::chrono::microseconds{0}) return false;
    it->second.m_stalling_since = std::chrono::microseconds{0};
    BumpPeerGenerationLocked(it->second);
    return true;
}

bool BlockDownloadManagerImpl::StartSync(NodeId peer)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() || it->second.m_sync_started) return false;
    it->second.m_sync_started = true;
    ++m_num_sync_started;
    BumpPeerGenerationLocked(it->second);
    return true;
}

bool BlockDownloadManagerImpl::ClearSync(NodeId peer)
{
    LOCK(m_mutex);
    const auto it{m_peer_states.find(peer)};
    if (it == m_peer_states.end() || !it->second.m_sync_started) return false;
    it->second.m_sync_started = false;
    --m_num_sync_started;
    Assume(m_num_sync_started >= 0);
    BumpPeerGenerationLocked(it->second);
    return true;
}

bool BlockDownloadManagerImpl::RecordBlockSource(const uint256& hash, NodeId peer, bool punish_on_invalid)
{
    LOCK(m_mutex);
    if (!m_peer_states.contains(peer)) return false;
    return m_block_sources.emplace(hash, BlockSource{peer, punish_on_invalid}).second;
}

std::optional<BlockSource> BlockDownloadManagerImpl::ConsumeBlockSource(const uint256& hash)
{
    LOCK(m_mutex);
    const auto it{m_block_sources.find(hash)};
    if (it == m_block_sources.end()) return std::nullopt;
    const BlockSource source{it->second};
    m_block_sources.erase(it);
    return source;
}

bool BlockDownloadManagerImpl::EraseBlockSource(const uint256& hash)
{
    LOCK(m_mutex);
    return m_block_sources.erase(hash) != 0;
}

bool BlockDownloadManagerImpl::TipMayBeStale(std::chrono::seconds now, std::chrono::seconds stale_after)
{
    LOCK(m_mutex);
    if (m_last_tip_update == std::chrono::seconds{0}) m_last_tip_update = now;
    return m_last_tip_update < now - stale_after && m_requests_by_hash.empty();
}

void BlockDownloadManagerImpl::UpdatedBlockTip(std::chrono::seconds now)
{
    LOCK(m_mutex);
    m_last_tip_update = now;
}

std::optional<std::chrono::seconds> BlockDownloadManagerImpl::TryIncreaseBlockStallingTimeout(
    std::chrono::seconds expected)
{
    static constexpr std::chrono::seconds MAX_BLOCK_STALLING_TIMEOUT{64};
    LOCK(m_mutex);
    if (expected < DEFAULT_BLOCK_STALLING_TIMEOUT ||
        expected >= MAX_BLOCK_STALLING_TIMEOUT ||
        m_block_stalling_timeout != expected) {
        return std::nullopt;
    }
    m_block_stalling_timeout = std::min(2 * expected, MAX_BLOCK_STALLING_TIMEOUT);
    return m_block_stalling_timeout;
}

std::optional<std::chrono::seconds> BlockDownloadManagerImpl::TryDecreaseBlockStallingTimeout(
    std::chrono::seconds expected)
{
    static constexpr std::chrono::seconds MAX_BLOCK_STALLING_TIMEOUT{64};
    LOCK(m_mutex);
    if (expected <= DEFAULT_BLOCK_STALLING_TIMEOUT ||
        expected > MAX_BLOCK_STALLING_TIMEOUT ||
        m_block_stalling_timeout != expected) {
        return std::nullopt;
    }
    m_block_stalling_timeout = std::max(
        std::chrono::duration_cast<std::chrono::seconds>(expected * 0.85),
        DEFAULT_BLOCK_STALLING_TIMEOUT);
    return m_block_stalling_timeout;
}

bool BlockDownloadManagerImpl::CheckConsistencyLocked() const
{
    size_t queue_size{0};
    int peers_downloading{0};
    int preferred_peers{0};
    int sync_started{0};
    std::set<std::pair<uint256, NodeId>> unique_requests;

    for (const auto& [peer, state] : m_peer_states) {
        if (state.m_availability_generation == 0 ||
            state.m_availability_generation > state.m_generation ||
            state.m_planning_generation == 0 ||
            state.m_planning_generation > state.m_generation) {
            return false;
        }
        queue_size += state.m_requests.size();
        peers_downloading += !state.m_requests.empty();
        preferred_peers += state.m_connection_info.m_preferred_download;
        sync_started += state.m_sync_started;
        for (auto queue_it{state.m_requests.begin()}; queue_it != state.m_requests.end(); ++queue_it) {
            if (!unique_requests.emplace(queue_it->m_block.m_hash, peer).second) return false;
            const auto range{m_requests_by_hash.equal_range(queue_it->m_block.m_hash)};
            size_t matches{0};
            for (auto index_it{range.first}; index_it != range.second; ++index_it) {
                if (index_it->second.m_peer == peer && index_it->second.m_queue_it == queue_it) ++matches;
            }
            if (matches != 1) return false;
        }
    }
    if (queue_size != m_requests_by_hash.size() ||
        peers_downloading != m_peers_downloading_from ||
        preferred_peers != m_num_preferred_download_peers ||
        sync_started != m_num_sync_started) {
        return false;
    }

    for (const auto& [_, source] : m_block_sources) {
        if (!m_peer_states.contains(source.m_peer)) return false;
    }

    for (auto it{m_requests_by_hash.begin()}; it != m_requests_by_hash.end();) {
        const auto range{m_requests_by_hash.equal_range(it->first)};
        if (static_cast<size_t>(std::distance(range.first, range.second)) > MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK) return false;
        for (auto index_it{range.first}; index_it != range.second; ++index_it) {
            const auto peer_it{m_peer_states.find(index_it->second.m_peer)};
            if (peer_it == m_peer_states.end() || index_it->second.m_queue_it->m_block.m_hash != it->first) return false;
        }
        it = range.second;
    }
    return true;
}

bool BlockDownloadManagerImpl::CheckConsistency() const
{
    LOCK(m_mutex);
    return CheckConsistencyLocked();
}

void BlockDownloadManagerImpl::CheckIsEmpty() const
{
    LOCK(m_mutex);
    Assume(CheckConsistencyLocked());
    Assume(m_peer_states.empty());
    Assume(m_requests_by_hash.empty());
    Assume(m_peers_downloading_from == 0);
    Assume(m_num_preferred_download_peers == 0);
    Assume(m_num_sync_started == 0);
    Assume(m_block_sources.empty());
}

} // namespace node
