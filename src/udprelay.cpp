// Copyright (c) 2016, 2017 Matt Corallo
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <udprelay.h>

#include <blockencodings.h>
#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/consensus.h>  // for MAX_BLOCK_SERIALIZED_SIZE
#include <consensus/validation.h> // for BlockValidationState/TxValidationState
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <streams.h>
#include <util/thread.h>
#include <validation.h>
#include <node/protocol_version.h>

#include <algorithm>
#include <condition_variable>
#include <optional>
#include <queue>
#include <sstream>
#include <filesystem>
#include <thread>

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())
#define DIV_CEIL(a, b) (((a) + (b) - 1) / (b))

static CService TRUSTED_PEER_DUMMY;
static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>> mapPartialBlocks;
static std::unordered_set<uint64_t> setBlocksRelayed;
// In cases where we receive a block without its previous block, or a block
// which is already (to us) an orphan, we will not get a UDPRelayBlock
// callback. However, we do not want to re-process the still-happening stream
// of packets into more ProcessNewBlock calls, so we have to keep a separate
// set here.
static std::set<std::pair<uint64_t, CService>> setBlocksReceived;

static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator RemovePartialBlock(std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it) {
    uint64_t hash_prefix = it->first.first;
    std::lock_guard<std::mutex> lock(it->second->state_mutex);
    // Note that we do not modify nodesWithChunksAvailableSet, as it might be "read-only" due to currentlyProcessing
    for (const auto& node : it->second->nodesWithChunksAvailableSet) {
        std::map<CService, UDPConnectionState>::iterator nodeIt = mapUDPNodes.find(node.first);
        if (nodeIt == mapUDPNodes.end())
            continue;
        std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = nodeIt->second.chunks_avail.find(hash_prefix);
        if (chunks_avail_it == nodeIt->second.chunks_avail.end())
            continue; // Peer reconnected at some point
        nodeIt->second.chunks_avail.erase(chunks_avail_it);
    }
    return mapPartialBlocks.erase(it);
}

static void RemovePartialBlock(const std::pair<uint64_t, CService>& key) {
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        RemovePartialBlock(it);
}

static void RemovePartialBlocks(uint64_t hash_prefix) {
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it = mapPartialBlocks.lower_bound(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
    while (it != mapPartialBlocks.end() && it->first.first == hash_prefix)
        it = RemovePartialBlock(it);
}

static inline void SendMessageToNode(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix, std::map<CService, UDPConnectionState>::iterator it) {
    if ((it->second.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
        return;
    const auto chunks_avail_it = it->second.chunks_avail.find(hash_prefix);

    bool use_chunks_avail = chunks_avail_it != it->second.chunks_avail.end();
    if (use_chunks_avail) {
        if (chunks_avail_it->second.AreAllAvailable())
            return;

        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER) {
            if (chunks_avail_it->second.IsHeaderChunkAvailable(le32toh(msg.msg.block.chunk_id)))
                return;
        } else {
            if (!chunks_avail_it->second.IsBlockDataChunkCountSet())
                chunks_avail_it->second.SetBlockDataChunkCount(DIV_CEIL(le32toh(msg.msg.block.obj_length), sizeof(UDPBlockMessage::data)));
            if (chunks_avail_it->second.IsBlockChunkAvailable(le32toh(msg.msg.block.chunk_id)))
                return;
        }
    }

    SendMessage(msg, length, high_prio, it);

    if (use_chunks_avail) {
        if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER)
            chunks_avail_it->second.SetHeaderChunkAvailable(le32toh(msg.msg.block.chunk_id));
        else if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS)
            chunks_avail_it->second.SetBlockChunkAvailable(le32toh(msg.msg.block.chunk_id));
    }
}

static void SendMessageToAllNodes(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix) {
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        SendMessageToNode(msg, length, high_prio, hash_prefix, it);
}

static void CopyMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, size_t msg_chunks, uint16_t chunk_id) {
    msg.msg.block.chunk_id = htole16(chunk_id);

    size_t msg_size = chunk_id == msg_chunks - 1 ? (data.size() % FEC_CHUNK_SIZE) : sizeof(msg.msg.block.data);
    if (msg_size == 0) msg_size = FEC_CHUNK_SIZE;
    memcpy(msg.msg.block.data, &data[chunk_id * FEC_CHUNK_SIZE], msg_size);
    if (msg_size != sizeof(msg.msg.block.data))
        memset(&msg.msg.block.data[msg_size], 0, sizeof(msg.msg.block.data) - msg_size);
}

// Note that algo is broken if you use both high_prio_chunks_per_peer and chunk_limit!
static void SendMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix, const size_t chunk_limit) {
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

    size_t chunks_sent_per_peer = 0;
    bool high_prio = high_prio_chunks_per_peer;
    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (uint16_t i = 0; i < msg_chunks && i < chunk_limit; i++) {
            CopyMessageData(msg, data, msg_chunks, i);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), high_prio, hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end()) {
                send_it = mapUDPNodes.begin();
                chunks_sent_per_peer++;
                if (high_prio && chunks_sent_per_peer >= high_prio_chunks_per_peer) high_prio = false;
            }
        }
    }
}

struct DataFECer {
    size_t fec_chunks;
    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> fec_data;
    FECEncoder enc;
    DataFECer(const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(&data, &fec_data) {}

    DataFECer(FECDecoder&& decoder, const std::vector<unsigned char>& data, size_t fec_chunks_in) :
        fec_chunks(fec_chunks_in),
        fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
        enc(std::move(decoder), &data, &fec_data) {}
};

static void CopyFECData(UDPMessage& msg, DataFECer& fec, size_t msg_chunks, size_t array_idx) {
    assert(fec.enc.BuildChunk(array_idx)); // TODO: Handle errors?
    assert(fec.fec_data.second[array_idx] < (1 << 24));
    msg.msg.block.chunk_id = htole32(fec.fec_data.second[array_idx]);
    memcpy(msg.msg.block.data, &fec.fec_data.first[array_idx], FEC_CHUNK_SIZE);
}

static void SendFECData(UDPMessage& msg, DataFECer& fec, const size_t msg_chunks, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix) {
    assert(fec.fec_chunks > 9);

    size_t chunks_sent_per_peer = 0;
    bool high_prio = high_prio_chunks_per_peer;
    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        auto send_it = it;
        for (size_t i = 0; i < fec.fec_chunks; i++) {
            CopyFECData(msg, fec, msg_chunks, i);

            SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPBlockMessage), high_prio, hash_prefix, send_it);
            send_it++;
            if (send_it == mapUDPNodes.end()) {
                send_it = mapUDPNodes.begin();
                chunks_sent_per_peer++;
                if (high_prio && chunks_sent_per_peer >= high_prio_chunks_per_peer) high_prio = false;
            }
        }
    }
}

static inline void FillCommonMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, uint8_t type, const std::vector<unsigned char>& data) {
    msg.header.msg_type        = type;
    msg.msg.block.hash_prefix  = htole64(hash_prefix);
    msg.msg.block.obj_length   = htole32(data.size());
}

static inline void FillBlockMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, UDPMessageType type, const std::vector<unsigned char>& data) {
    // First fill in common message elements
    FillCommonMessageHeader(msg, hash_prefix, type | HAVE_BLOCK, data);
}

static void SendFECedData(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, DataFECer& fec) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    FillBlockMessageHeader(msg, hash_prefix, type, data);

    // For header messages, the actual data is more useful.
    // For block contents, the probably generated most chunks from the header + mempool.
    // We send in usefulness-first order
    if (type == MSG_TYPE_BLOCK_HEADER) {
        // Block headers are all high priority for the data itself,
        // and 3 packets of high priority for the FEC, after that if
        // we have block data available it should be sent.
        SendMessageData(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, std::numeric_limits<size_t>::max());
        SendFECData(msg, fec, msg_chunks, 3, hash_prefix);
    } else {
        // First 10 FEC chunks are high priority, then everything is
        // low. This should be sufficient to reconstruct many blocks
        // that only missed a handful of chunks, then revert to
        // sending header chunks until we've sent them all.
        SendFECData(msg, fec, msg_chunks, 10, hash_prefix);

        // We also benchmark sending pre-calced data here to ensure there
        // isn't a lot of overhead here...
        const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
        std::chrono::steady_clock::time_point start;
        if (fBench)
            start = std::chrono::steady_clock::now();
        SendMessageData(msg, data, 0, hash_prefix, std::numeric_limits<size_t>::max());
        if (fBench) {
            std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
            LogPrintf("UDP: Sent block data chunks in %lf ms\n", to_millis_double(finished - start));
        }
    }
}

static void SendLimitedDataChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data) {
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data);

    SendMessageData(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, 3); // Send 3 packets to each peer, in RR
}

static std::unique_ptr<std::thread> process_block_thread;

void UDPRelayBlock(const CBlock& block) {
    std::chrono::steady_clock::time_point start;
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    if (fBench)
        start = std::chrono::steady_clock::now();

    uint256 hashBlock(block.GetHash());
    uint64_t hash_prefix = hashBlock.GetUint64(0);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes, std::defer_lock);

    if (maybe_have_write_nodes) { // Scope for partial_block_lock and partial_block_ptr
        const std::vector<unsigned char> *block_chunks = NULL;
        bool skipEncode = false;
        std::unique_lock<std::mutex> partial_block_lock;
        std::shared_ptr<PartialBlockData> partial_block_ptr;
        bool inUDPProcess = process_block_thread && std::this_thread::get_id() == process_block_thread->get_id();
        if (inUDPProcess) {
            lock.lock();

            auto it = mapPartialBlocks.find(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
            if (it != mapPartialBlocks.end() && it->second->currentlyProcessing) {
                partial_block_lock = std::unique_lock<std::mutex>(it->second->state_mutex); // Locked after cs_mapUDPNodes
                if (it->second->block_data.AreChunksAvailable()) {
                    if (fBench)
                        LogPrintf("UDP: Building FEC chunks from decoded block\n");
                    skipEncode = true;
                    partial_block_ptr = it->second;
                    block_chunks = &it->second->block_data.GetCodedBlock();
                }
            }

            // We unlock everything here to let the net thread relay packets,
            // but continue to use data which is theoretically under the locks.
            // This is OK - we get a copy of the shared_ptr and hold it in
            // partial_block_ptr so it wont be destroyed out from under us, and
            // are only using the chunks from PartiallyDownloadedChunkBlock and
            // the decoder, both of which, once available, will never become
            // un-available or be modified by any other thread (due to the
            // currentlyProcessing checks made in the net thread).
            // We should not otherwise be making assumptions about availability of
            // block-related data, but eg the message send functions check for the
            // availability of ChunkAvailableSets prior to access.
            if (partial_block_lock)
                partial_block_lock.unlock();
            lock.unlock();
        }

        std::chrono::steady_clock::time_point initd;
        if (fBench)
            initd = std::chrono::steady_clock::now();

        ChunkCodedBlock *codedBlock = (ChunkCodedBlock*) alloca(sizeof(ChunkCodedBlock));
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, codec_version_t::default_version, true);
        std::vector<unsigned char> data;
        data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
        VectorOutputStream stream(&data);
        stream << headerAndIDs;

        std::chrono::steady_clock::time_point coded;
        if (fBench)
            coded = std::chrono::steady_clock::now();

        DataFECer header_fecer(data, (min_per_node_mbps.load(std::memory_order_relaxed) * 1024 * 1024 / 8 / 1000 / PACKET_SIZE) + 10); // 1ms + 10 chunks of header FEC

        DataFECer *block_fecer = (DataFECer*) alloca(sizeof(DataFECer));
        size_t data_fec_chunks = 0;
        if (inUDPProcess) {
            // If we're actively receiving UDP packets, go ahead and spend the time to precalculate FEC now,
            // otherwise we want to start getting the header/first block chunks out ASAP
            header_fecer.enc.PrefillChunks();

            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }
            if (!block_chunks->empty()) {
                data_fec_chunks = DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                if (skipEncode) {
                    // If we get here, we are currently in the processing thread
                    // and have partial_block_ptr set. Additionally, because
                    // partial_block_ptr->block_data has chunks, the FEC decoder
                    // was initialized and fed FEC/data, meaning even if no FEC
                    // chunks were used to reconstruct the FECDecoder object is
                    // fully primed to be converted to a FECEncoder!
                    new (block_fecer) DataFECer(std::move(partial_block_ptr->decoder), *block_chunks, data_fec_chunks);
                } else {
                    new (block_fecer) DataFECer(*block_chunks, data_fec_chunks);
                }
                block_fecer->enc.PrefillChunks();
            }
        }

        std::chrono::steady_clock::time_point feced;
        if (fBench)
            feced = std::chrono::steady_clock::now();

        // We do all the expensive calculations before locking cs_mapUDPNodes
        // so that the forward-packets-without-block logic in HandleBlockMessage
        // continues without interruption as long as possible
        if (!lock)
            lock.lock();

        if (mapUDPNodes.empty())
            return;

        if (setBlocksRelayed.count(hash_prefix))
            return;

        SendFECedData(hashBlock, MSG_TYPE_BLOCK_HEADER, data, header_fecer);

        std::chrono::steady_clock::time_point header_sent;
        if (fBench)
            header_sent = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!skipEncode) {
                new (codedBlock) ChunkCodedBlock(block, headerAndIDs);
                block_chunks = &codedBlock->GetCodedBlock();
            }

            // Because we need the coded block's size to init block decoding, it
            // is important we get the first block packet out to peers ASAP. Thus,
            // we go ahead and send the first few non-FEC block packets here.
            if (!block_chunks->empty()) {
                data_fec_chunks = DIV_CEIL(block_chunks->size(), FEC_CHUNK_SIZE) + 10; //TODO: Pick something different?
                SendLimitedDataChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks);
            }
        }

        std::chrono::steady_clock::time_point block_coded;
        if (fBench)
            block_coded = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!block_chunks->empty()) {
                new (block_fecer) DataFECer(*block_chunks, data_fec_chunks);
            }
        }

        std::chrono::steady_clock::time_point block_fec_initd;
        if (fBench)
            block_fec_initd = std::chrono::steady_clock::now();

        // Now (maybe) send the transaction chunks
        if (!block_chunks->empty())
            SendFECedData(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *block_chunks, *block_fecer);

        if (fBench) {
            std::chrono::steady_clock::time_point all_sent(std::chrono::steady_clock::now());
            LogPrintf("UDP: Built all FEC chunks for block %s in %lf %lf %lf %lf %lf %lf %lf ms with %lu header chunks\n", hashBlock.ToString(), to_millis_double(initd - start), to_millis_double(coded - initd), to_millis_double(feced - coded), to_millis_double(header_sent - feced), to_millis_double(block_coded - header_sent), to_millis_double(block_fec_initd - block_coded), to_millis_double(all_sent - block_fec_initd), header_fecer.fec_chunks);
            if (!inUDPProcess){
                size_t block_size = ::GetSerializeSize(TX_WITH_WITNESS(block));
                LogPrintf("UDP: Block %s had serialized size %lu\n", hashBlock.ToString(), block_size);
            }
        } else
            LogPrintf("UDP: Built all FEC chunks for block %s\n", hashBlock.ToString());

        if (!skipEncode)
            codedBlock->~ChunkCodedBlock();

        if (!block_chunks->empty())
            block_fecer->~DataFECer();

        // Destroy partial_block_lock before we RemovePartialBlocks()
    }

    setBlocksRelayed.insert(hash_prefix);
    RemovePartialBlocks(hash_prefix);
}

void BlockRecvInit() {

}

void BlockRecvShutdown() {

}

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start) {
    return false;
}

void ProcessDownloadTimerEvents() {

}

// Each UDPMessage must be of sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH in length!
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs) {

}

void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<UDPMessage>& msgs) {

}