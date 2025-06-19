// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019-2020 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <udprelay.h>

#include <chainparams.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/consensus.h>  // for MAX_BLOCK_SERIALIZED_SIZE
#include <consensus/validation.h> // for BlockValidationState/TxValidationState
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <outoforder.h>
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

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period>>(t).count())
#define DIV_CEIL(a, b) (((a) + (b)-1) / (b))

static in_addr TRUSTED_PEER_DUMMY_IPADDR;
auto res = inet_pton(AF_INET, "0.0.0.0", &TRUSTED_PEER_DUMMY_IPADDR);
static unsigned short TRUSTED_PEER_DUMMY_PORT = 0;
static CService TRUSTED_PEER_DUMMY(TRUSTED_PEER_DUMMY_IPADDR, TRUSTED_PEER_DUMMY_PORT);
static bool sync_with_trusted_peer = false;
static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>> mapPartialBlocks;
static std::unordered_set<uint64_t> setBlocksRelayed;
// In cases where we receive a block without its previous block, or a block
// which is already (to us) an orphan, we will not get a UDPRelayBlock
// callback. However, we do not want to re-process the still-happening stream
// of packets into more ProcessNewBlock calls, so we have to keep a separate
// set here.
static std::set<std::pair<uint64_t, CService>> setBlocksReceived;

// Helper function to split a string (replaces boost::split)
static void SplitString(std::vector<std::string>& result, const std::string& str, char delimiter)
{
    result.clear();
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        result.push_back(token);
    }
}

static std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator RemovePartialBlock(std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it)
{
    uint64_t const hash_prefix = it->first.first;
    std::lock_guard<std::mutex> lock(it->second->state_mutex);
    // Note that we do not modify perNodeChunkCount, as it might be "read-only" due to currentlyProcessing
    for (const auto& node : it->second->perNodeChunkCount) {
        std::map<CService, UDPConnectionState>::iterator nodeIt = mapUDPNodes.find(node.first);
        if (nodeIt == mapUDPNodes.end())
            continue;

        // Copy hit ratios saved within the PartialBlockData into the node's
        // UDPConnectionState, which later becomes available for read through
        // the getfechitratio RPC
        if (it->second->txn_hit_ratio != -1 && it->second->chunk_hit_ratio) {
            nodeIt->second.last_txn_hit_ratio = it->second->txn_hit_ratio;
            nodeIt->second.last_chunk_hit_ratio = it->second->chunk_hit_ratio;
        }

        std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = nodeIt->second.chunks_avail.find(hash_prefix);
        if (chunks_avail_it == nodeIt->second.chunks_avail.end())
            continue; // Peer reconnected at some point
        nodeIt->second.chunks_avail.erase(chunks_avail_it);
    }
    // Now that we are done with the FEC data, remove any underlying mmap FEC chunk files
    it->second->header_decoder.RemoveMmapFile();
    it->second->body_decoder.RemoveMmapFile();

    // Remove the PartialBlockData from mapPartialBlocks. The PartialBlockData
    // may still survive until the last shared_ptr owning the object is
    // destroyed, so mark it as removed to prevent further processing.
    it->second->removed = true;
    return mapPartialBlocks.erase(it);
}

static void RemovePartialBlock(const std::pair<uint64_t, CService>& key)
{
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        RemovePartialBlock(it);
}

static void RemovePartialBlocks(uint64_t const hash_prefix)
{
    std::map<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>::iterator it = mapPartialBlocks.lower_bound(std::make_pair(hash_prefix, TRUSTED_PEER_DUMMY));
    while (it != mapPartialBlocks.end() && it->first.first == hash_prefix)
        it = RemovePartialBlock(it);
}

std::shared_ptr<PartialBlockData> GetPartialBlockData(const std::pair<uint64_t, CService>& key)
{
    auto it = mapPartialBlocks.find(key);
    if (it != mapPartialBlocks.end())
        return it->second;
    return nullptr;
}

static inline void SendMessageToNode(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix, std::map<CService, UDPConnectionState>::iterator it)
{
    if ((it->second.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
        return;

    const bool is_blk_content_chunk = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS;
    const size_t n_chunks = DIV_CEIL(le32toh(msg.payload.fec.obj_length), sizeof(UDPFecMessage::data));
    const uint32_t chunk_id = le32toh(msg.payload.fec.chunk_id);

    const auto chunks_avail_it = it->second.chunks_avail.find(hash_prefix);
    bool use_chunks_avail = chunks_avail_it != it->second.chunks_avail.end();

    if (use_chunks_avail) {
        if (chunks_avail_it->second.AreAllAvailable())
            return;

        if (chunks_avail_it->second.IsChunkAvailable(chunk_id, n_chunks, is_blk_content_chunk))
            return;
    }

    SendMessage(msg, length, high_prio, *it);

    if (use_chunks_avail)
        chunks_avail_it->second.SetChunkAvailable(chunk_id, n_chunks, is_blk_content_chunk);
}

static void SendMessageToAllNodes(const UDPMessage& msg, unsigned int length, bool high_prio, uint64_t hash_prefix)
{
    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++)
        if (it->second.connection.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
            SendMessageToNode(msg, length, high_prio, hash_prefix, it);
}

static size_t CopyMessageData(UDPMessage& msg, const std::vector<unsigned char>& data, size_t msg_chunks, uint16_t chunk_id)
{
    msg.payload.fec.chunk_id = htole16(chunk_id);

    size_t msg_size = (chunk_id == msg_chunks - 1) ? (data.size() % FEC_CHUNK_SIZE) : sizeof(msg.payload.fec.data);
    if (msg_size == 0) msg_size = FEC_CHUNK_SIZE;
    memcpy(msg.payload.fec.data, &data[chunk_id * FEC_CHUNK_SIZE], msg_size);
    if (msg_size != sizeof(msg.payload.fec.data))
        memset(&msg.payload.fec.data[msg_size], 0, sizeof(msg.payload.fec.data) - msg_size);
    return msg_size;
}

/**
 * Send uncoded (non FEC-coded) data chunks to all peers
 */
static void RelayUncodedChunks(UDPMessage& msg, const std::vector<unsigned char>& data, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix, const size_t chunk_limit)
{
    const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

    bool high_prio = high_prio_chunks_per_peer;

    for (uint16_t i = 0; i < msg_chunks && i < chunk_limit; i++) {
        if (high_prio && i >= high_prio_chunks_per_peer)
            high_prio = false;

        /* Send the same uncoded chunk to all peers */
        CopyMessageData(msg, data, msg_chunks, i);

        for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
            if (it->second.connection.udp_mode == udp_mode_t::unicast)
                SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPFecMessage), high_prio, hash_prefix, it);
        }

        for (const auto& node : multicast_nodes()) {
            if (node.second.tx && node.second.relay_new_blks) {
                SendMessage(msg,
                            sizeof(UDPMessageHeader) + sizeof(UDPFecMessage),
                            high_prio, std::get<0>(node.first),
                            multicast_checksum_magic, node.second.group);
            }
        }
    }
}

struct DataFECer {
    size_t fec_chunks;
    std::pair<std::unique_ptr<FECChunkType[]>, std::vector<uint32_t>> fec_data;
    FECEncoder enc;
    DataFECer(const std::vector<unsigned char>& data, size_t fec_chunks_in) : fec_chunks(fec_chunks_in),
                                                                              fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
                                                                              enc(&data, &fec_data) {}

    DataFECer(FECDecoder&& decoder, const std::vector<unsigned char>& data, size_t fec_chunks_in) : fec_chunks(fec_chunks_in),
                                                                                                    fec_data(std::piecewise_construct, std::forward_as_tuple(new FECChunkType[fec_chunks]), std::forward_as_tuple(fec_chunks)),
                                                                                                    enc(std::move(decoder), &data, &fec_data) {}
};

static void CopyFECData(UDPMessage& msg, DataFECer& fec, size_t array_idx, bool overwrite_chunk = false)
{
    bool const ret = fec.enc.BuildChunk(array_idx, overwrite_chunk);
    // TODO: Handle errors?
    assert(ret);
    assert(fec.fec_data.second[array_idx] < (1 << 24));
    msg.payload.fec.chunk_id = htole32(fec.fec_data.second[array_idx]);
    memcpy(msg.payload.fec.data, &fec.fec_data.first[array_idx], FEC_CHUNK_SIZE);
}

/**
 * Send FEC-coded chunks to all peers
 *
 * For each chunk index, a different (random) chunk id is generated for each
 * outbound service. This is useful for receive peers that are receiving from
 * (combining) more than one service.
 */
static void RelayFECedChunks(UDPMessage& msg, DataFECer& fec, const size_t high_prio_chunks_per_peer, const uint64_t hash_prefix)
{
    assert(fec.fec_chunks > 9);

    bool high_prio = high_prio_chunks_per_peer;
    for (size_t i = 0; i < fec.fec_chunks; i++) {
        if (high_prio && (i >= high_prio_chunks_per_peer))
            high_prio = false;

        /* Send over unicast services */
        for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
            if (it->second.connection.udp_mode == udp_mode_t::unicast) {
                CopyFECData(msg, fec, i, true /*regenerate chunk on index i*/);
                SendMessageToNode(msg, sizeof(UDPMessageHeader) + sizeof(UDPFecMessage), high_prio, hash_prefix, it);
            }
        }

        /* Send over each multicast Tx (outbound) service */
        for (const auto& node : multicast_nodes()) {
            if (node.second.tx && node.second.relay_new_blks) {
                CopyFECData(msg, fec, i, true /*regenerate chunk on index i*/);
                SendMessage(msg,
                            sizeof(UDPMessageHeader) + sizeof(UDPFecMessage),
                            high_prio, std::get<0>(node.first),
                            multicast_checksum_magic, node.second.group);
            }
        }
    }
}

static inline void FillCommonMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, uint8_t type, const size_t obj_size)
{
    msg.header.chk1 = 0;
    msg.header.chk2 = 0;
    msg.header.msg_type = type;
    msg.payload.fec.hash_prefix = htole64(hash_prefix);
    msg.payload.fec.obj_length = htole32(obj_size);
}

static inline void FillBlockMessageHeader(UDPMessage& msg, const uint64_t hash_prefix, UDPMessageType type, const size_t obj_size, uint8_t flags = HAVE_BLOCK)
{
    // First fill in common message elements
    FillCommonMessageHeader(msg, hash_prefix, type | flags, obj_size);
}

/**
 * Send FEC-coded and uncoded (original data) chunks to all peers
 *
 * This function processes either header chunks or block chunks, but not
 * both. So it has to be called twice. After completion, all chunks (of the
 * header or block) will be queued up for transmission.
 */
static void RelayChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data, DataFECer& fec)
{
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data.size(), (HAVE_BLOCK | TIP_BLOCK));

    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    std::chrono::steady_clock::time_point t_start, t_uncoded, t_coded;
    if (fBench)
        t_start = std::chrono::steady_clock::now();

    // For header messages, the actual data is more useful.
    // For block contents, the probably generated most chunks from the header + mempool.
    // We send in usefulness-first order
    if (type == MSG_TYPE_BLOCK_HEADER_AND_TXIDS) {
        // Block headers are all high priority for the data itself,
        // and 3 packets of high priority for the FEC, after that if
        // we have block data available it should be sent.
        RelayUncodedChunks(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, std::numeric_limits<size_t>::max());
        if (fBench)
            t_uncoded = std::chrono::steady_clock::now();

        RelayFECedChunks(msg, fec, 3, hash_prefix);
        if (fBench)
            t_coded = std::chrono::steady_clock::now();
    } else {
        // First 100 FEC chunks are high priority, then everything is low. This
        // should be sufficient to reconstruct many blocks that only missed a
        // handful of chunks, then revert to sending header chunks until we've
        // sent them all.
        RelayFECedChunks(msg, fec, 100, hash_prefix);
        /* NOTE: there is no need to send uncoded block data. Sending uncoded
         * makes sense when the receive-end doesn't know anything about the
         * data. However, here the receiver is assumed to known most of the
         * data, so sending FEC-coded chunks is preferable. */
        if (fBench)
            t_coded = std::chrono::steady_clock::now();
    }

    if (fBench) {
        const size_t msg_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);

        if (type == MSG_TYPE_BLOCK_HEADER_AND_TXIDS) {
            LogPrintf("UDP: %s: Finished queuing of %lu header chunks for tx - took %lf ms\n",
                      __func__, (msg_chunks + fec.fec_chunks),
                      to_millis_double(t_coded - t_start));
            LogPrintf("UDP: %s:     %lu Uncoded header chunks took %lf ms\n", __func__,
                      msg_chunks, to_millis_double(t_uncoded - t_start));
            LogPrintf("UDP: %s:     %lu Coded header chunks took %lf ms\n", __func__,
                      fec.fec_chunks, to_millis_double(t_coded - t_uncoded));
        } else {
            LogPrintf("UDP: %s: Finished queuing of %lu FEC-coded block chunks for tx - took %lf ms\n",
                      __func__, (fec.fec_chunks),
                      to_millis_double(t_coded - t_start));
        }
    }
}

static void SendLimitedDataChunks(const uint256& blockhash, UDPMessageType type, const std::vector<unsigned char>& data)
{
    UDPMessage msg;
    uint64_t hash_prefix = blockhash.GetUint64(0);
    FillBlockMessageHeader(msg, hash_prefix, type, data.size(), (HAVE_BLOCK | TIP_BLOCK));

    RelayUncodedChunks(msg, data, std::numeric_limits<size_t>::max(), hash_prefix, 3); // Send 3 packets to each peer, in RR
}

static std::unique_ptr<std::thread> process_block_thread;


void ResetPartialBlocks()
{
    mapPartialBlocks.clear();
}

void ResetPartialBlockState()
{
    setBlocksRelayed.clear();
    setBlocksReceived.clear();
    ResetPartialBlocks();
    ResetBlockProcessQueue();
}

const CService& GetTrustedPeer()
{
    return TRUSTED_PEER_DUMMY;
}

void UDPRelayBlock(const CBlock& block, int nHeight)
{
    std::chrono::steady_clock::time_point start;
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    if (fBench)
        start = std::chrono::steady_clock::now();

    uint256 hashBlock(block.GetHash());
    uint64_t hash_prefix = hashBlock.GetUint64(0);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes, std::defer_lock);

    if (maybe_have_write_nodes) { // Scope for partial_block_lock and partial_block_ptr
        const std::vector<unsigned char>* chunk_coded_block = NULL;
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
                    chunk_coded_block = &it->second->block_data.GetCodedBlock();
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

        std::optional<ChunkCodedBlock> codedBlock;
        CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, codec_version_t::default_version, true);
        headerAndIDs.setBlockHeight(nHeight);
        std::vector<unsigned char> header_data;
        header_data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
        VectorOutputStream stream(&header_data);
        stream << headerAndIDs;

        std::chrono::steady_clock::time_point coded;
        if (fBench)
            coded = std::chrono::steady_clock::now();

        const size_t header_fec_chunks = DIV_CEIL(header_data.size(), FEC_CHUNK_SIZE) + 10;
        DataFECer header_fecer(header_data, header_fec_chunks);

        std::optional<DataFECer> block_fecer;
        size_t data_fec_chunks = 0;
        if (inUDPProcess) {
            // If we're actively receiving UDP packets, go ahead and spend the time to precalculate FEC now,
            // otherwise we want to start getting the header/first block chunks out ASAP
            header_fecer.enc.PrefillChunks();

            if (!skipEncode) {
                codedBlock.emplace(block, headerAndIDs);
                chunk_coded_block = &codedBlock->GetCodedBlock();
            }
            if (!chunk_coded_block->empty()) {
                data_fec_chunks = DIV_CEIL(chunk_coded_block->size(), FEC_CHUNK_SIZE) + 10; // TODO: Pick something different?
                if (skipEncode) {
                    // If we get here, we are currently in the processing thread
                    // and have partial_block_ptr set. Additionally, because
                    // partial_block_ptr->block_data has chunks, the FEC decoder
                    // was initialized and fed FEC/data, meaning even if no FEC
                    // chunks were used to reconstruct the FECDecoder object is
                    // fully primed to be converted to a FECEncoder!
                    block_fecer.emplace(std::move(partial_block_ptr->body_decoder), *chunk_coded_block, data_fec_chunks);
                } else {
                    block_fecer.emplace(*chunk_coded_block, data_fec_chunks);
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

        RelayChunks(hashBlock, MSG_TYPE_BLOCK_HEADER_AND_TXIDS, header_data, header_fecer);

        std::chrono::steady_clock::time_point header_sent;
        if (fBench)
            header_sent = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!skipEncode) {
                codedBlock.emplace(block, headerAndIDs);
                chunk_coded_block = &codedBlock->GetCodedBlock();
            }
            // Because we need the coded block's size to init block decoding, it
            // is important we get the first block packet out to peers ASAP. Thus,
            // we go ahead and send the first few non-FEC block packets here.
            if (!chunk_coded_block->empty()) {
                data_fec_chunks = DIV_CEIL(chunk_coded_block->size(), FEC_CHUNK_SIZE) + 10; // TODO: Pick something different?
                SendLimitedDataChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *chunk_coded_block);
            }
        }

        std::chrono::steady_clock::time_point block_coded;
        if (fBench)
            block_coded = std::chrono::steady_clock::now();

        if (!inUDPProcess) { // We sent header before calculating any block stuff
            if (!chunk_coded_block->empty()) {
                block_fecer.emplace(*chunk_coded_block, data_fec_chunks);
            }
        }

        std::chrono::steady_clock::time_point block_fec_initd;
        if (fBench)
            block_fec_initd = std::chrono::steady_clock::now();

        // Now (maybe) send the transaction chunks
        if (!chunk_coded_block->empty())
            RelayChunks(hashBlock, MSG_TYPE_BLOCK_CONTENTS, *chunk_coded_block, *block_fecer);

        if (fBench) {
            std::chrono::steady_clock::time_point all_sent(std::chrono::steady_clock::now());
            LogPrintf("UDP: Built all FEC chunks for block %s (%lu) in %lf %lf %lf %lf %lf %lf %lf ms with %lu header chunks\n", hashBlock.ToString(), hash_prefix, to_millis_double(initd - start), to_millis_double(coded - initd), to_millis_double(feced - coded), to_millis_double(header_sent - feced), to_millis_double(block_coded - header_sent), to_millis_double(block_fec_initd - block_coded), to_millis_double(all_sent - block_fec_initd), header_fecer.fec_chunks);
            if (!inUDPProcess){
                size_t block_size = ::GetSerializeSize(TX_WITH_WITNESS(block));
                LogPrintf("UDP: Block %s had serialized size %lu\n", hashBlock.ToString(), block_size);
            }
        } else
            LogPrintf("UDP: Built all FEC chunks for block %s\n", hashBlock.ToString());

        // Destroy partial_block_lock before we RemovePartialBlocks()
    }

    setBlocksRelayed.insert(hash_prefix);
    RemovePartialBlocks(hash_prefix);
}

/**
 * Send txn over one or more messages
 *
 * All txns are sent uncoded (without FEC-coding). Yet, the txns with size
 * yielding more than a single data chunk are still treated as FEC-coded on the
 * receive-end. This is OK, , since the coding schemes (cm256 or wirehair) are
 * systematic. Most likely, such (larger) txns will be encoded by cm256.
 *
 * Also, txns are sent over variable-length UDP datagrams. If the txn size is
 * greater than a FEC chunk size, it is split into multiple messages (UDP
 * datagrams), each one (except the last) carrying a number of bytes equal to
 * the FEC chunk size. Otherwise, the txn is sent over a shorter datagram. This
 * function includes the size of each msg into the vector of msgs.
 */
void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<std::pair<UDPMessage, size_t>>& msgs)
{
    const uint256 hash(tx.GetWitnessHash());
    const uint64_t hash_prefix = hash.GetUint64(0);

    std::vector<unsigned char> data;
    VectorOutputStream stream(&data);

    codec_version_t const codec_version = codec_version_t::default_version;
    stream << static_cast<std::uint8_t>(codec_version);
    stream << CTxCompressor(tx, codec_version);

    const size_t data_chunks = DIV_CEIL(data.size(), FEC_CHUNK_SIZE);
    msgs.resize(data_chunks);

    for (size_t i = 0; i < data_chunks; i++) {
        FillCommonMessageHeader(msgs[i].first, hash_prefix, MSG_TYPE_TX_CONTENTS, data.size());
        const size_t chunk_size = CopyMessageData(msgs[i].first, data, data_chunks, i);
        msgs[i].second = sizeof(UDPMessageHeader) + udp_fec_msg_header_size + chunk_size;
    }
}

/**
 * Fill FEC messages of block header and block data
 *
 * This is used by the multicast Tx (backfill) thread only, specifically to send
 * "past blocks", i.e. blocks that are already in the chain. When a new block
 * arises and before it is added to the chain, it is instead relayed to UDP
 * peers through function `UDPRelayBlock`.
 *
 * Unlike txns, only FEC-coded chunks are sent for block data. The same strategy
 * is applied also for transmission of the block header, although based on a
 * different motivation, explained next.
 *
 * The main factor to consider when choosing between sending uncoded vs. coded
 * is whether the receive-end might know something about the data object in
 * advance. Once a block is advertised by the "block header" message, the
 * receive node tries to prefill the chunk-coded block based on the txns that it
 * already has locally in its mempool. As a result, the receive node typically
 * prefills most of the chunks before the chunk-coded block even starts to
 * arrive. In this scenario, it is advantageous to send only coded chunks. The
 * rationale is that each coded chunk generated by the fountain code (wirehair)
 * brings information about multiple other chunks (it is a XOR of multiple
 * chunks) and, as a result, the receive end tends to fill all gaps faster by
 * processing them. In contrast, uncoded chunks only bring their own
 * information, so the receive node must receive the exact chunks that are
 * missing in order to fill all gaps, which tends to be slower.
 *
 * In contrast, for objects that the receiver knows nothing about, it can be
 * slightly advantageous to send the uncoded chunks first. Since the code is
 * systematic, sending uncoded is equivalent to sending coded chunks with chunk
 * id < N, where N is the number of chunks of the original object. The reason
 * why it could be advantageous is that the decoder can process the "uncoded
 * chunks" faster (there is less computation involved). On the other hand, when
 * uncoded chunks are sent, the disadvantage is that the receive-end cannot
 * efficiently combine multiple incoming streams in order to decode the object
 * faster. When, instead, coded chunks with random chunk ids are sent, the
 * receive node that listens to multiple streams will get different chunks from
 * each stream and, consequently, complete the decoding quicker.
 *
 * So the choice for objects that the receiver doesn't know about in advance
 * depends on which factor matters the most: the longer decoding of coded chunks
 * (with random chunk ids) or the more efficient combination of chunks when
 * receiving from multiple streams. It turns out that the decoding is typically
 * in the order of microseconds. Meanwhile, transmission of chunks depends on
 * link bitrates. In the implementation that follows, we optimize for low
 * bitrate links (such as satellite links), where the bottleneck typically is
 * the transmission delay of chunks. For instance, on a 1 Mbps link, a 1 KByte
 * chunk has a delay of 8 ms, i.e. much larger than the decoding latency. Hence,
 * we choose to send all chunks as FEC-coded, even for the block header.
 *
 * Besides, the block header will essentially always be coded via cm256 (rather
 * than wirehair), due to its smaller size (compared to the chunk-coded
 * block). The difference on decoding duration will be even lower in this case.
 *
 * The ensuing function fills all FEC chunks of both header and block data. The
 * order on which chunks are filled is noteworthy. It is optimized for minimum
 * latency in the absence of data loss. First the minimum amount of chunks of
 * header and block data are sent. Receivers that successfully decode all of
 * these can then complete the decoding right away. After them, the overhead
 * header chunks are sent and, lastly, the overhead block chunks.
 *
 */
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs, const int height, const FecOverhead& overhead, codec_version_t codec_version)
{
    const uint256 hashBlock(block.GetHash());
    const uint64_t hash_prefix = hashBlock.GetUint64(0);

    /* Block header */
    CBlockHeaderAndLengthShortTxIDs headerAndIDs(block, codec_version, true);
    headerAndIDs.setBlockHeight(height);
    /* NOTE: it is not mandatory to include the block height along
     * CBlockHeaderAndLengthShortTxIDs. However, it is useful to include it here
     * in order to support out-of-order block (OOOB) storage of pre-BIP34
     * blocks. The reason is that pre-BIP34 blocks don't include the height as
     * part of the coinbase transaction's input script, and so unless we send
     * the height explicitly, the receive node won't know the height and won't
     * be able to store the block in case it is received out-of-order. */

    const bool empty_block = (headerAndIDs.ShortTxIdCount() == 0);
    const uint8_t flags = empty_block ? (HAVE_BLOCK | EMPTY_BLOCK) : HAVE_BLOCK;

    std::vector<unsigned char> header_data;
    header_data.reserve(2500 + 8 * block.vtx.size()); // Rather conservatively high estimate
    VectorOutputStream stream(&header_data);
    stream << headerAndIDs;
    const size_t n_header_chunks = DIV_CEIL(header_data.size(), FEC_CHUNK_SIZE);
    const size_t header_overhead = overhead.fixed + std::round(overhead.variable * n_header_chunks);
    const size_t n_header_fec_chunks = n_header_chunks + header_overhead;
    DataFECer header_fecer(header_data, n_header_fec_chunks);
    /* NOTE: the block header will typically be encoded by cm256, due to its
     * size. Since cm256 is MDS, in principle only the N original chunks are
     * necessary. Nevertheless, since chunks can be lost along the transport
     * link, some chunks of overhead are used. */

    /* First fill the minimum amount of header chunks for decoding
     *
     * NOTE: since cm256 is MDS, the minimum amount of header chunks is
     * guaranteed to be sufficient for decoding */
    int offset = msgs.size();
    msgs.resize(offset + n_header_chunks);
    for (size_t i = 0; i < n_header_chunks; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_HEADER_AND_TXIDS, header_data.size(), flags);
        CopyFECData(msgs[offset + i], header_fecer, i);
    }

    /* Don't send the chunk-coded block if the block does not have any
     * transaction other than the coinbase (which is sent in the header) */
    if (empty_block) {
        /* Fill overhead header chunks */
        offset = msgs.size();
        msgs.resize(offset + header_overhead);
        for (size_t i = 0; i < header_overhead; i++) {
            FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_HEADER_AND_TXIDS, header_data.size(), flags);
            CopyFECData(msgs[offset + i], header_fecer, n_header_chunks + i);
        }
        return;
    }

    ChunkCodedBlock codedBlock(block, headerAndIDs);
    const std::vector<unsigned char>& chunk_coded_block = codedBlock.GetCodedBlock();
    const size_t n_block_chunks = DIV_CEIL(chunk_coded_block.size(), FEC_CHUNK_SIZE);
    const size_t block_overhead = overhead.fixed + std::round(overhead.variable * n_block_chunks);
    const size_t n_block_fec_chunks = n_block_chunks + block_overhead;
    /* NOTE: on average wirehair needs about 0.02 chunks of overhead to recover,
     * meaning most often it doesn't need overhead at all. Again, we add
     * overhead chunks here in order to overcome loss along the link. */
    DataFECer block_fecer(chunk_coded_block, n_block_fec_chunks);

    /* Minimum amount of block chunks for decoding
     *
     * NOTE: unlike header chunks, this minimum amount sent here is only almost
     * always sufficient for decoding, but not 100% guaranteed. */
    offset = msgs.size();
    msgs.resize(offset + n_block_chunks);
    for (size_t i = 0; i < n_block_chunks; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, chunk_coded_block.size(), flags);
        CopyFECData(msgs[offset + i], block_fecer, i);
    }

    /* Overhead header chunks */
    offset = msgs.size();
    msgs.resize(offset + header_overhead);
    for (size_t i = 0; i < header_overhead; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_HEADER_AND_TXIDS, header_data.size(), flags);
        CopyFECData(msgs[offset + i], header_fecer, n_header_chunks + i);
    }

    /* Overhead block chunks */
    offset = msgs.size();
    msgs.resize(offset + block_overhead);
    for (size_t i = 0; i < block_overhead; i++) {
        FillBlockMessageHeader(msgs[offset + i], hash_prefix, MSG_TYPE_BLOCK_CONTENTS, chunk_coded_block.size(), flags);
        CopyFECData(msgs[offset + i], block_fecer, n_block_chunks + i);
    }

    return;
}

static std::mutex block_process_mutex;
static std::condition_variable block_process_cv;
static std::atomic_bool process_thread_shutdown(false);
static std::queue<std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>> block_process_queue;
static size_t queue_size_warn = 10; // Print queue size when it exceeds this

// TODO: For now, there is no good or simple solution to introduce the 
// EXCLUSIVE_LOCKS_REQUIRED(block_data.second->state_mutex) annotation without Clang's thread safety analysis complaining
static void DoBackgroundBlockProcessing(const std::pair<std::pair<uint64_t, CService>, std::shared_ptr<PartialBlockData>>& block_data) //EXCLUSIVE_LOCKS_REQUIRED(block_data.second->state_mutex)
{
    if (block_data.second->awaiting_processing)
        return;
    block_data.second->awaiting_processing = true;

    // If we just blindly call ProcessNewBlock here, we have a cs_main/cs_mapUDPNodes inversion
    // (actually because fucking P2P code calls everything with cs_main already locked).
    // Instead we pass the processing back to ProcessNewBlockThread without cs_mapUDPNodes
    std::unique_lock<std::mutex> lock(block_process_mutex);
    block_process_queue.emplace(block_data);
    if (block_process_queue.size() > queue_size_warn) {
        LogDebug(BCLog::FEC, "Block process queue size: %ld\n",
                 block_process_queue.size());
    }
    lock.unlock();
    block_process_cv.notify_all();
}

static void ProcessBlockThread(ChainstateManager* chainman)
{
    while (true) {
        std::unique_lock<std::mutex> process_lock(block_process_mutex);
        while (block_process_queue.empty() && !process_thread_shutdown)
            block_process_cv.wait(process_lock);

        if (process_thread_shutdown)
            return;

        auto process_block = block_process_queue.front();
        auto hash_peer_pair = process_block.first;

        PartialBlockData& block = *process_block.second;
        block_process_queue.pop();
        process_lock.unlock();

        ProcessBlock(chainman, hash_peer_pair, block);
    }
}

void ProcessBlock(ChainstateManager* chainman, const std::pair<uint64_t, CService>& hash_peer_pair, PartialBlockData& block)
{
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    const CService& node = hash_peer_pair.second;
    bool more_work;
    std::unique_lock<std::mutex> lock(block.state_mutex);
    block.awaiting_processing = false;

    // If the processing has already completed before (successfully or not) such
    // that RemovePartialBlock was called, don't process this block again.
    if (block.removed)
        return;

    do {
        more_work = false;
        if (block.is_header_processing) {
            std::chrono::steady_clock::time_point decode_start;
            if (fBench)
                decode_start = std::chrono::steady_clock::now();

            std::vector<unsigned char> header_data;
            try {
                header_data = block.header_decoder.GetDecodedData();
            } catch (const std::runtime_error& e) {
                lock.unlock();
                std::stringstream stream;
                stream << std::hex << hash_peer_pair.first;
                std::string hex_hash_prefix(stream.str());
                LogPrintf("UDP: Failed to decode block %lu from %s: %s\n", hex_hash_prefix, node.ToStringAddrPort(), e.what());
                break;
            }

            std::chrono::steady_clock::time_point data_copied;
            if (fBench)
                data_copied = std::chrono::steady_clock::now();

            CBlockHeaderAndLengthShortTxIDs header;
            try {
                VectorInputStream stream(&header_data);
                stream >> header;
            } catch (std::ios_base::failure& e) {
                lock.unlock();
                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                if (node == TRUSTED_PEER_DUMMY)
                    LogPrintf("UDP: Failed to decode received header and short txids from trusted peer(s), check your trusted peers are behaving well.\n");
                else {
                    LogPrintf("UDP: Failed to decode received header and short txids from %s, disconnecting\n", node.ToStringAddrPort());
                    const auto it = mapUDPNodes.find(node);
                    if (it != mapUDPNodes.end())
                        DisconnectNode(it);
                }
                break;
            }
            std::chrono::steady_clock::time_point header_deserialized;
            if (fBench)
                header_deserialized = std::chrono::steady_clock::now();

            // We may not process the header yet (depending on conditions
            // checked below), but at least we can extract the block height from
            // the header and save it on the partial block.
            block.height = header.getBlockHeight();

            // Do we have the block already?
            if (!block.chain_lookup) {
                const CBlockIndex* pblockindex;
                bool is_block_data_availale = false;
                {
                    LOCK(cs_main);
                    pblockindex = chainman->m_blockman.LookupBlockIndex(header.header.GetHash());
                    is_block_data_availale = pblockindex->nStatus & BLOCK_HAVE_DATA;
                }
                block.chain_lookup = true;
                if (pblockindex && is_block_data_availale) {
                    // We do have the full block already. Drop the partial block
                    // immediately and add it to setBlocksReceived, so that its
                    // subsequent chunks are ignored.
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    setBlocksReceived.insert(hash_peer_pair);
                    RemovePartialBlock(hash_peer_pair);
                    break;
                }
            }

            // Continue with the processing of a non-tip (repeated) block only
            // if the body is also decodable or empty. This is to save memory,
            // given that as soon as we call ProvideHeaderData below,
            // significant amounts of memory are preallocated.
            const bool non_empty_block = (header.ShortTxIdCount() != 0);
            if (!block.tip_blk && non_empty_block && !block.is_decodeable)
                break;

            ReadStatus decode_status = block.ProvideHeaderData(header);
            if (decode_status != READ_STATUS_OK) {
                lock.unlock();
                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                if (decode_status == READ_STATUS_INVALID) {
                    if (node == TRUSTED_PEER_DUMMY)
                        LogPrintf("UDP: Got invalid header and short txids from trusted peer(s), check your trusted peers are behaving well.\n");
                    else {
                        LogPrintf("UDP: Got invalid header and short txids from %s, disconnecting\n", node.ToStringAddrPort());
                        const auto it = mapUDPNodes.find(node);
                        if (it != mapUDPNodes.end())
                            DisconnectNode(it);
                    }
                } else
                    LogPrintf("UDP: Failed to read header and short txids\n");

                // Dont remove the block, let it time out...
                break;
            }

            if (block.block_data.IsBlockAvailable())
                block.is_decodeable = true;
            block.is_header_processing = false;

            const uint256 blockHash = block.block_data.GetBlockHash();

            if (fBench) {
                std::chrono::steady_clock::time_point header_provided(std::chrono::steady_clock::now());
                LogPrintf("UDP: Block %s (height %7d) - Got full header and shorttxids from %s in %lf %lf %lf ms\n", blockHash.ToString(), block.height, block.GetSenders(), to_millis_double(data_copied - decode_start), to_millis_double(header_deserialized - data_copied), to_millis_double(header_provided - header_deserialized));
            } else
                LogPrintf("UDP: Block %s (height %7d) - Got full header and shorttxids from: [%s]\n", blockHash.ToString(), block.height, block.GetSenders());

            if (block.block_data.AreAllTxnsInMempool())
                LogPrintf("UDP: Block %s - Ready to be decoded (all txns available)\n", blockHash.ToString());
            else if (block.block_data.IsBlockAvailable())
                LogPrintf("UDP: Block %s - Ready to be decoded (all uncoded chunks available)\n", blockHash.ToString());
            else if (block.is_decodeable)
                LogPrintf("UDP: Block %s - Ready to be decoded (enough FEC chunks available)\n", blockHash.ToString());

            if (block.tip_blk) {
                size_t mempool_txns = block.block_data.GetMempoolCount();
                size_t n_blk_txns = header.BlockShortTxCount();
                block.txn_hit_ratio = (double)mempool_txns / n_blk_txns;
                LogDebug(BCLog::FEC, "UDP: Block %s - Txns available: %ld/%ld  Txn hit ratio: %f\n",
                         blockHash.ToString(), mempool_txns, n_blk_txns, block.txn_hit_ratio);
                // When all txns are available in the mempool, the FEC-coded
                // block is not even decoded. The block is decoded directly
                // based on the local txns. However, mark as if all chunks were
                // available for consistency with the txn hit ratio.
                if (block.block_data.AreAllTxnsInMempool())
                    block.chunk_hit_ratio = 1.0;
            }

            // Do more work if we can already decode the block or in case we
            // should try to fill in the erasures based on mempool txns that we
            // already have (for new blocks, i.e., tip blocks)
            if (block.is_decodeable || (block.blk_initialized && block.tip_blk))
                more_work = true;
            else
                lock.unlock();

        } else if (block.block_data.IsHeaderNull()) {
            // If we are not going to process the header data now, it is because
            // we are either going to process block data or fill block data.
            // However, in order for this to succeed we must have had processed
            // the header before. Double check.
            break;
        } else if (block.is_decodeable || block.block_data.IsBlockAvailable()) {
            if (block.currentlyProcessing) {
                // We often duplicatively schedule DoBackgroundBlockProcessing,
                // but we do not do anything to avoid duplicate
                // final-processing. Thus, we have to check if we have already
                // done final processing by checking currentlyProcessing (which
                // is never un-set after we set it).
                break;
            }
            block.currentlyProcessing = true;
            std::chrono::steady_clock::time_point reconstruct_start;
            if (fBench)
                reconstruct_start = std::chrono::steady_clock::now();

            if (!block.block_data.IsBlockAvailable()) {
                block.ReconstructBlockFromDecoder();
                assert(block.block_data.IsBlockAvailable());
            }

            std::chrono::steady_clock::time_point fec_reconstruct_finished;
            if (fBench)
                fec_reconstruct_finished = std::chrono::steady_clock::now();

            ReadStatus status = block.block_data.FinalizeBlock();

            std::chrono::steady_clock::time_point block_finalized;
            if (fBench)
                block_finalized = std::chrono::steady_clock::now();

            if (status != READ_STATUS_OK) {
                lock.unlock();
                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                if (status == READ_STATUS_INVALID) {
                    if (node == TRUSTED_PEER_DUMMY)
                        LogPrintf("UDP: Unable to decode block from trusted peer(s), check your trusted peers are behaving well.\n");
                    else {
                        const auto it = mapUDPNodes.find(node);
                        if (it != mapUDPNodes.end())
                            DisconnectNode(it);
                    }
                    // Make sure this invalid block is not downloaded again in the future
                    setBlocksReceived.insert(hash_peer_pair);
                } else if (status == READ_STATUS_UNSUPPORTED) {
                    LogPrintf("UDP: Dropping block %s received with unsupported txn codec version.\n", block.block_data.GetBlockHash().ToString());
                } else {
                    LogPrintf("UDP: Failed to process block %s. Dropping.\n", block.block_data.GetBlockHash().ToString());
                }
                RemovePartialBlock(hash_peer_pair);
                break;
            } else {
                std::shared_ptr<const CBlock> pdecoded_block = block.block_data.GetBlock();
                const CBlock& decoded_block = *pdecoded_block;
                if (fBench) {
                    uint32_t total_chunks_recvd = 0, total_chunks_used = 0;
                    std::map<CService, std::pair<uint32_t, uint32_t>>& chunksProvidedByNode = block.perNodeChunkCount;
                    for (const auto& provider : chunksProvidedByNode) {
                        total_chunks_recvd += provider.second.second;
                        total_chunks_used += provider.second.first;
                    }
                    // NOTE: the chunk count printed next is not necessarily
                    // accurate. It reflects the count up to when the block is
                    // decoded. However, further chunks may still be received
                    // after the block is decoded.
                    LogPrintf("UDP: Block %s reconstructed with %u chunks in %lf ms (%u recvd from %u peers)\n", decoded_block.GetHash().ToString(), total_chunks_used, to_millis_double(std::chrono::steady_clock::now() - block.t_created), total_chunks_recvd, chunksProvidedByNode.size());
                    for (const auto& provider : chunksProvidedByNode)
                        LogPrintf("UDP:    %u/%u used from %s\n", provider.second.first, provider.second.second, provider.first.ToStringAddrPort());
                }

                lock.unlock();

                std::chrono::steady_clock::time_point process_start;
                if (fBench)
                    process_start = std::chrono::steady_clock::now();

                // Treat the block as a solicited block in case it came from a
                // trusted peer
                const bool force_requested = (node == TRUSTED_PEER_DUMMY);

                bool fNewBlock;
                if (!chainman->ProcessNewBlock(pdecoded_block, force_requested, /*min_pow_checked=*/true, &fNewBlock)) {
                    bool have_prev, outoforder_and_valid;
                    {
                        LOCK(cs_main);

                        have_prev = chainman->BlockIndex().count(pdecoded_block->hashPrevBlock);
                        BlockValidationState state;
                        outoforder_and_valid = !have_prev &&
                                               CheckBlock(*pdecoded_block, state, Params().GetConsensus());
                    }

                    LogPrintf("UDP: Failed to decode block %s\n", decoded_block.GetHash().ToString());

                    // Only save out-of-order blocks that are minimally valid
                    bool ooob_saved = false;
                    if (outoforder_and_valid) {
                        ooob_saved = StoreOoOBlock(*chainman, Params(), pdecoded_block, force_requested, block.height);

                        // If the OOOB was actually a tip block coming from a
                        // trusted peer, we are no longer in sync
                        if (ooob_saved && node == TRUSTED_PEER_DUMMY && block.tip_blk) {
                            sync_with_trusted_peer = false;
                        }
                    }

                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);

                    if (ooob_saved) {
                        setBlocksReceived.insert(hash_peer_pair);
                    } else {
                        // Allow re-downloading again later, useful for local backfill downloads
                        setBlocksReceived.erase(hash_peer_pair);
                    }
                    RemovePartialBlock(hash_peer_pair);
                    break; // Probably a tx collision generating merkle-tree errors
                }
                if (fBench) {
                    LogPrintf("UDP: Final block processing for %s took %lf %lf %lf %lf ms (new: %d)\n", decoded_block.GetHash().ToString(), to_millis_double(fec_reconstruct_finished - reconstruct_start), to_millis_double(block_finalized - fec_reconstruct_finished), to_millis_double(process_start - block_finalized), to_millis_double(std::chrono::steady_clock::now() - process_start), fNewBlock);
                    if (fNewBlock) {
                        size_t block_size = ::GetSerializeSize(TX_WITH_WITNESS(decoded_block));
                        LogPrintf("UDP: Block %s had serialized size %lu\n", decoded_block.GetHash().ToString(), block_size);
                    }
                }

                // Assume we are in sync when, upon reception of a tip block
                // from a trusted peer, the received block actually becomes the
                // tip of the active chain.
                uint256 tip_hash;
                {
                    LOCK(cs_main);
                    tip_hash = chainman->ActiveChain().Tip()->GetBlockHash();
                }
                if (node == TRUSTED_PEER_DUMMY && block.tip_blk) {
                    sync_with_trusted_peer = tip_hash == decoded_block.GetHash();
                }

                std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                setBlocksReceived.insert(hash_peer_pair);
                RemovePartialBlocks(hash_peer_pair.first); // Ensure we remove even if we didnt UDPRelayBlock()
            }
        } else if (!block.in_header && block.blk_initialized && block.tip_blk) {
            uint32_t mempool_provided_chunks = 0;
            uint32_t total_chunk_count = 0;
            uint256 blockHash;
            bool fDone = block.block_data.IsIterativeFillDone();
            while (!fDone) {
                size_t firstChunkProcessed;
                if (!lock)
                    lock.lock();
                if (!total_chunk_count) {
                    total_chunk_count = block.block_data.GetChunkCount();
                    blockHash = block.block_data.GetBlockHash();
                }
                ReadStatus res = block.block_data.DoIterativeFill(firstChunkProcessed);
                if (res != READ_STATUS_OK) {
                    lock.unlock();
                    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
                    if (res == READ_STATUS_INVALID) {
                        if (node == TRUSTED_PEER_DUMMY)
                            LogPrintf("UDP: Unable to process mempool for block %s from trusted peer(s), check your trusted peers are behaving well.\n", blockHash.ToString());
                        else {
                            LogPrintf("UDP: Unable to process mempool for block %s from %s, disconnecting\n", blockHash.ToString(), node.ToStringAddrPort());
                            const auto it = mapUDPNodes.find(node);
                            if (it != mapUDPNodes.end())
                                DisconnectNode(it);
                        }
                    } else
                        LogPrintf("UDP: Unable to process mempool for block %s, dropping block\n", blockHash.ToString());
                    setBlocksReceived.insert(hash_peer_pair);
                    RemovePartialBlock(hash_peer_pair);
                    break;
                } else {
                    while (firstChunkProcessed < total_chunk_count && block.block_data.IsChunkAvailable(firstChunkProcessed)) {
                        if (!block.body_decoder.HasChunk(firstChunkProcessed)) {
                            block.body_decoder.ProvideChunk(block.block_data.GetChunk(firstChunkProcessed), firstChunkProcessed);
                            mempool_provided_chunks++;
                        }
                        firstChunkProcessed++;
                    }

                    if (block.body_decoder.DecodeReady() || block.block_data.IsBlockAvailable()) {
                        block.is_decodeable = true;
                        more_work = true;
                        break;
                    }
                }
                fDone = block.block_data.IsIterativeFillDone();
                if (!fDone && block.packet_awaiting_lock) {
                    lock.unlock();
                    std::this_thread::yield();
                }
            }

            double chunk_hit_ratio = (double)mempool_provided_chunks / total_chunk_count;

            if (lock)
                block.chunk_hit_ratio = chunk_hit_ratio;

            if (lock && !more_work)
                lock.unlock();
            LogPrintf("UDP: Block %s - Initialized with %ld/%ld mempool-provided chunks (or more)\n", blockHash.ToString(), mempool_provided_chunks, total_chunk_count);
            LogDebug(BCLog::FEC, "UDP: Block %s - Chunk hit ratio: %f\n",
                     blockHash.ToString(), chunk_hit_ratio);
        }
    } while (more_work);
}

void ResetBlockProcessQueue()
{
    std::unique_lock<std::mutex> lock(block_process_mutex);
    while (!block_process_queue.empty())
        block_process_queue.pop();
}

void BlockRecvInit(ChainstateManager* chainman)
{
    process_block_thread.reset(new std::thread(&util::TraceThread, "udpprocess", std::function<void()>(std::bind(&ProcessBlockThread, chainman))));
}

void BlockRecvShutdown()
{
    if (process_block_thread) {
        process_thread_shutdown = true;
        block_process_cv.notify_all();
        process_block_thread->join();
        process_block_thread.reset();
    }
}

/*
 * Detect whether a FEC chunk file contains recoverable partial block data
 *
 * Assume the file is recoverable if it is named according to the following
 * format: "<ipaddr>_<port>_<hashprefix>_<blockpart>_<size>", where:
 *
 * - <ipaddr>      : IP address of the sender (trusted dummy peer is "0.0.0.0").
 * - <port>        : port of the sender peer (trusted dummy peer uses port "0").
 * - <hashprefix>  : block hash prefix.
 * - <blockpart>   : part of the block the chunk file holds (header or body).
 * - "size"        : object size in bytes.
 */
bool IsChunkFileRecoverable(const std::string& filename, ChunkFileNameParts& cfp)
{
    std::vector<std::string> parts;
    SplitString(parts, filename, '_');
    if (parts.size() != 5) {
        return false;
    }

    auto res = inet_pton(AF_INET, parts[0].c_str(), &(cfp.ipv4Addr));
    if (res <= 0) {
        return false;
    }

    cfp.port = static_cast<unsigned short>(strtoul(parts[1].c_str(), nullptr, 10));

    cfp.hash_prefix = strtoull(parts[2].c_str(), nullptr, 10);
    if (cfp.hash_prefix == 0) {
        return false;
    }

    if (parts[3] != "header" && parts[3] != "body") {
        return false;
    }
    cfp.is_header = (parts[3] == "header");

    cfp.length = strtoul(parts[4].c_str(), nullptr, 10);
    if (cfp.length == 0) {
        return false;
    }

    return true;
}

// Scan the disk for recoverable FEC chunk files and try to rebuild the
// mapPartialBlocks state. Clean up the chunk files that are not recoverable.
static bool load_partial_blocks_stop = false;
void LoadPartialBlocks(CTxMemPool* mempool)
{
    LogPrintf("Loading partial blocks from disk...\n");
    uint32_t n_imported = 0;
    uint32_t n_removed = 0;
    fs::path chunk_files_dir = gArgs.GetDataDirNet() / "partial_blocks";
    std::unique_lock<std::recursive_mutex> partial_block_map_lock(cs_mapUDPNodes, std::defer_lock);
    if (is_directory(chunk_files_dir)) {
        for (const auto& entry : fs::directory_iterator(chunk_files_dir)) {
            if (load_partial_blocks_stop)
                break;

            fs::path chunk_file_path(entry.path());
            ChunkFileNameParts cfp;
            if (!IsChunkFileRecoverable(fs::PathToString(chunk_file_path.filename()), cfp)) {
                fs::remove(chunk_file_path);
                n_removed++;
                continue;
            }
            CService peer(cfp.ipv4Addr, cfp.port);
            const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(cfp.hash_prefix, peer);

            std::shared_ptr<PartialBlockData> block;
            {
                std::lock_guard<std::recursive_mutex> partial_block_map_lock(cs_mapUDPNodes);
                if (setBlocksReceived.count(hash_peer_pair))
                    continue;
                block = GetPartialBlockData(hash_peer_pair);
                if (!block) {
                    auto res = mapPartialBlocks.insert(std::make_pair(hash_peer_pair, std::make_shared<PartialBlockData>(peer, mempool, cfp)));
                    block = res.first->second;
                    n_imported++;
                }
            }

            // HandleBlockTxMessage() calls Init() after locking the state
            // mutex. Make sure to lock this mutex here too so that there is no
            // racing between loading a partial block from disk and the
            // disk-recovery mechanism triggered on reception via UDP.
            std::unique_lock<std::mutex> lock(block->state_mutex);
            if (!block->Init(cfp)) {
                LogPrintf("UDP: Got block contents that couldn't match header for block id %lu\n", cfp.hash_prefix);
                fs::remove(chunk_file_path);
                continue;
            }

            // Let the block processing thread process this block if the header
            // is already decodable and the chain look-up procedure is pending.
            // The look-up will be useful to obtain the block height and check
            // whether the height exists in the chain already. Furthermore,
            // schedule the background processing if both the header and body
            // are decodable, in which case the full processing will take place.
            // Note all disk-recovered blocks are non-tip blocks, so the header
            // can only be fully processed when the body is decodable too.
            // Nevertheless, it is still possible for a recovered block to be
            // mixed with tip-flagged chunks, in which case the block is
            // ultimately considered a tip block and its header can be processed
            // earlier. To cover this scenario, trigger the background
            // processing also if the body is decodable and the header is
            // already processed (in_header = false).
            if ((block->is_header_processing && (!block->chain_lookup || block->is_decodeable)) ||
                (block->is_decodeable && !block->in_header)) {
                DoBackgroundBlockProcessing(std::make_pair(hash_peer_pair, block));
            }
        }
    }
    LogPrintf("Loaded %lu partial blocks from disk\n", n_imported);
    if (n_removed > 0) {
        LogPrintf("Removed %lu non-recoverable partial blocks from disk\n", n_removed);
    }
}

void StopLoadPartialBlocks()
{
    load_partial_blocks_stop = true;
}

// TODO: Use the one from net_processing (with appropriate lock-free-ness)
static std::vector<CTransactionRef> udpnet_dummy_extra_txn;
ReadStatus PartialBlockData::ProvideHeaderData(const CBlockHeaderAndLengthShortTxIDs& header)
{
    assert(in_header);
    in_header = false;
    return block_data.InitData(header, udpnet_dummy_extra_txn);
}

static std::string GetChunkFilePrefix(const CService& peer, uint64_t hash_prefix)
{
    return peer.ToStringAddr() + "_" + std::to_string(peer.GetPort()) + "_" + std::to_string(hash_prefix);
}

bool PartialBlockData::Init(const UDPMessage& msg)
{
    assert(IS_BLOCK_HEADER_AND_TXIDS_MSG(msg) || IS_BLOCK_CONTENTS_MSG(msg));
    const uint32_t obj_length = msg.payload.fec.obj_length;
    if (obj_length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR)
        return false;

    tip_blk |= IS_TIP_BLOCK(msg); // true if at least one msg flags true (see HandleBlockTxMessage)
    const bool is_blk_header_chunk = IS_BLOCK_HEADER_AND_TXIDS_MSG(msg);

    // When receiving a block at the tip of the blockchain, load FEC chunks
    // directly in memory. They are expected to remain there only briefly until
    // the block FEC-decoding completes. In contrast, if receiving non-tip
    // (repeated/historic) blocks, use the decoder in mmap mode so that FEC
    // chunks are offloaded to disk. The non-tip blocks can take a long time to
    // complete when many (thousands of) non-tip blocks are sent in parallel.
    const MemoryUsageMode memory_usage_mode = tip_blk ? MemoryUsageMode::USE_MEMORY : MemoryUsageMode::USE_MMAP;

    // In mmap mode, save chunks on a consistently-named file that persists
    // across bitcoind sessions. The name includes the two unique identifiers
    // used to map partial blocks in mapPartialBlocks: the peer (potentially a
    // "trusted peer") and the block hash prefix.
    std::string chunk_file_prefix = GetChunkFilePrefix(peer, msg.payload.fec.hash_prefix);

    if (is_blk_header_chunk && !header_initialized) {
        header_decoder = FECDecoder(
            obj_length,
            memory_usage_mode,
            chunk_file_prefix + "_header",
            true /* persist mmap file */
        );
        header_len = obj_length;
        header_initialized = true;
    }

    if (!is_blk_header_chunk && !blk_initialized) {
        body_decoder = FECDecoder(
            obj_length,
            memory_usage_mode,
            chunk_file_prefix + "_body",
            true /* persist mmap file */
        );
        blk_len = obj_length;
        blk_initialized = true;
    }
    // NOTE: The decoders could be initialized already due the disk data
    // recovery mechanism from LoadPartialBlocks() executed on a thread.

    return true;
}

PartialBlockData::PartialBlockData(const CService& peer, CTxMemPool* mempool, const UDPMessage& msg, const std::chrono::steady_clock::time_point& packet_recv) : t_created(packet_recv), t_last_rx(packet_recv), peer(peer),
                                                                                                                                                                 in_header(true), blk_initialized(false), header_initialized(false),
                                                                                                                                                                 is_decodeable(false), is_header_processing(false),
                                                                                                                                                                 packet_awaiting_lock(false), awaiting_processing(false),
                                                                                                                                                                 chain_lookup(false), removed(false), currentlyProcessing(false),
                                                                                                                                                                 blk_len(0), header_len(0), block_data(mempool), tip_blk(false)
{
}


bool PartialBlockData::Init(const ChunkFileNameParts& cfp)
{
    if (cfp.length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR)
        return false;

    std::string chunk_file_prefix = GetChunkFilePrefix(peer, cfp.hash_prefix);

    if (cfp.is_header && !header_initialized) {
        header_decoder = FECDecoder(
            cfp.length,
            MemoryUsageMode::USE_MMAP,
            chunk_file_prefix + "_header",
            true /* persist mmap file */
        );
        header_len = cfp.length;
        header_initialized = true;
        // The recovered header object could be decodable already
        is_header_processing = header_decoder.DecodeReady();
    }

    if (!cfp.is_header && !blk_initialized) {
        body_decoder = FECDecoder(
            cfp.length,
            MemoryUsageMode::USE_MMAP,
            chunk_file_prefix + "_body",
            true /* persist mmap file */
        );
        blk_len = cfp.length;
        blk_initialized = true;
        // The recovered body object could be decodable already
        is_decodeable = body_decoder.DecodeReady();
    }

    // NOTE: this function finds the decoders in initialized state whenever a
    // chunk of the same FEC object has been received previously by the Rx
    // handler (HandleBlockTxMessage). In this case, the data saved in disk has
    // been recovered already, so it's not necessary to recover it again.

    return true;
}

PartialBlockData::PartialBlockData(const CService& peer, CTxMemPool* mempool, const ChunkFileNameParts& cfp) : t_created(std::chrono::steady_clock::now()), t_last_rx(t_created), peer(peer),
                                                                                                               in_header(true), blk_initialized(false), header_initialized(false),
                                                                                                               is_decodeable(false), is_header_processing(false),
                                                                                                               packet_awaiting_lock(false), awaiting_processing(false),
                                                                                                               chain_lookup(false), removed(false), currentlyProcessing(false),
                                                                                                               blk_len(0), header_len(0), block_data(mempool), tip_blk(false)
{
}

void PartialBlockData::ReconstructBlockFromDecoder()
{
    assert(body_decoder.DecodeReady());

    for (uint32_t i = 0; i < DIV_CEIL(blk_len, sizeof(UDPFecMessage::data)); i++) {
        if (!block_data.IsChunkAvailable(i)) {
            const void* data_ptr = body_decoder.GetDataPtr(i);
            assert(data_ptr);
            memcpy(block_data.GetChunk(i), data_ptr, sizeof(UDPFecMessage::data));
            block_data.MarkChunkAvailable(i);
        }
    }

    body_decoder.GetDataPtrDone();
    assert(block_data.IsBlockAvailable());
};

/* Get FEC chunk senders corresponding to the partial block
 *
 * When "PartialBlockData.peer" is a "trusted peer", there can be multiple
 * senders aggregated in the same partial block. In this case, the multiple
 * senders can be obtained from the perNodeChunkCount map. In contrast, when
 * "PartialBlockData.peer" is a non-trusted peer, all chunks come from the same
 * peer. In this case, "PartialBlockData.peer" is the actual peer instead of a
 * dummy value.
 */
std::string PartialBlockData::GetSenders()
{
    if (peer != TRUSTED_PEER_DUMMY) {
        assert(perNodeChunkCount.size() == 1);
        return peer.ToStringAddrPort();
    }

    std::string senders;
    const size_t n_nodes = perNodeChunkCount.size();
    size_t i_node = 1;
    for (const auto& node : perNodeChunkCount) {
        senders += node.first.ToStringAddrPort();
        if (i_node++ < n_nodes)
            senders += ", ";
    }
    return senders;
}

static void BlockMsgHToLE(UDPMessage& msg)
{
    msg.payload.fec.hash_prefix = htole64(msg.payload.fec.hash_prefix);
    msg.payload.fec.obj_length = htole32(msg.payload.fec.obj_length);
    msg.payload.fec.chunk_id = htole32(msg.payload.fec.chunk_id);
}

static bool HandleTx(UDPMessage& msg, const CService& node, UDPConnectionState& state, const node::NodeContext* const node_context)
{
    if (msg.payload.fec.obj_length > 400000) {
        LogPrintf("UDP: Got massive tx obj_length of %u\n", msg.payload.fec.obj_length);
        return false;
    }

    if (state.tx_in_flight_hash_prefix != msg.payload.fec.hash_prefix) {
        state.tx_in_flight_hash_prefix = msg.payload.fec.hash_prefix;
        state.tx_in_flight_msg_size = msg.payload.fec.obj_length;
        state.tx_in_flight.reset(new FECDecoder(msg.payload.fec.obj_length, MemoryUsageMode::USE_MEMORY));
        // NOTE: always place txn chunks directly in memory instead of disk. The
        // FEC decoding is expected to be quick in this case.
    }

    if (!state.tx_in_flight) return true; // Already finished decode

    if (state.tx_in_flight_msg_size != msg.payload.fec.obj_length) {
        LogPrintf("UDP: Got inconsistent object length for tx %lu\n", msg.payload.fec.hash_prefix);
        return true;
    }

    assert(!state.tx_in_flight->DecodeReady());

    if (!state.tx_in_flight->ProvideChunk(msg.payload.fec.data, msg.payload.fec.chunk_id)) {
        // Bad chunk id, maybe FEC is upset? Don't disconnect in case it can be random
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from tx %lu from %s\n", msg.payload.fec.chunk_id, msg.payload.fec.hash_prefix, node.ToStringAddrPort());
        return true;
    }

    if (state.tx_in_flight->DecodeReady()) {
        std::vector<unsigned char> tx_data = state.tx_in_flight->GetDecodedData();

        try {
            VectorInputStream stream(&tx_data);
            codec_version_t codec_version;
            stream >> *reinterpret_cast<std::uint8_t*>(&codec_version);
            CTransactionRef tx;
            stream >> CTxCompressor(tx, codec_version);
            LOCK(cs_main);
            TxValidationState state;
            const MempoolAcceptResult result = AcceptToMemoryPool(node_context->chainman->ActiveChainstate(), tx, GetTime(), /*bypass_limits=*/false, /*test_accept=*/false);
            if (result.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                node_context->peerman->RelayTransaction(tx->GetHash(), tx->GetWitnessHash());
            }
        } catch (std::exception& e) {
            LogPrintf("UDP: Tx decode failed for tx %lu from %s: %s\n", msg.payload.fec.hash_prefix, node.ToStringAddrPort(), e.what());
        }

        state.tx_in_flight.reset();
    }

    return true;
}

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start, const node::NodeContext* const node_context)
{
    // TODO: There are way too many damn tree lookups here...either cut them down or increase parallelism
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    std::chrono::steady_clock::time_point start;
    if (fBench)
        start = std::chrono::steady_clock::now();

    assert(IS_BLOCK_HEADER_AND_TXIDS_MSG(msg) || IS_BLOCK_CONTENTS_MSG(msg) || IS_TX_CONTENTS_MSG(msg));

    if (length != sizeof(UDPMessageHeader) + sizeof(UDPFecMessage)) {
        LogPrintf("UDP: Got invalidly-sized (%d bytes) message from %s\n", length, node.ToStringAddrPort());
        return false;
    }

    msg.payload.fec.hash_prefix = le64toh(msg.payload.fec.hash_prefix);
    msg.payload.fec.obj_length = le32toh(msg.payload.fec.obj_length);
    msg.payload.fec.chunk_id = le32toh(msg.payload.fec.chunk_id);

    if ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS)
        return HandleTx(msg, node, state, node_context);

    const bool is_blk_header_chunk = IS_BLOCK_HEADER_AND_TXIDS_MSG(msg);
    const bool is_blk_content_chunk = IS_BLOCK_CONTENTS_MSG(msg);
    const bool they_have_block = msg.header.msg_type & HAVE_BLOCK;
    const bool empty_block = IS_EMPTY_BLOCK(msg); // a block that comes entirely through the header

    const uint64_t hash_prefix = msg.payload.fec.hash_prefix; // Need a reference in a few places, but its packed, so we can't have one directly
    CService peer = state.connection.fTrusted ? TRUSTED_PEER_DUMMY : node;
    const std::pair<uint64_t, CService> hash_peer_pair = std::make_pair(hash_prefix, peer);

    if (msg.payload.fec.obj_length > MAX_BLOCK_SERIALIZED_SIZE * MAX_CHUNK_CODED_BLOCK_SIZE_FACTOR) {
        LogPrintf("UDP: Got massive obj_length of %u\n", msg.payload.fec.obj_length);
        return false;
    }

    // Number of chunks that the data object (before FEC enconding) would occupy
    const size_t n_chunks = DIV_CEIL(msg.payload.fec.obj_length, sizeof(UDPFecMessage::data));

    if (setBlocksRelayed.count(msg.payload.fec.hash_prefix) || setBlocksReceived.count(hash_peer_pair))
        return true;

    std::map<uint64_t, ChunksAvailableSet>::iterator chunks_avail_it = state.chunks_avail.find(msg.payload.fec.hash_prefix);

    if (chunks_avail_it == state.chunks_avail.end()) {
        if (is_blk_header_chunk) {
            if (state.chunks_avail.size() > 1 && !state.connection.fTrusted) {
                // Non-trusted nodes can only be forwarding up to 2 blocks at a time
                assert(state.chunks_avail.size() == 2);
                auto first_partial_block_it = mapPartialBlocks.find(std::make_pair(state.chunks_avail.begin()->first, node));
                assert(first_partial_block_it != mapPartialBlocks.end());
                auto second_partial_block_it = mapPartialBlocks.find(std::make_pair(state.chunks_avail.rbegin()->first, node));
                assert(second_partial_block_it != mapPartialBlocks.end());
                if (first_partial_block_it->second->t_created < second_partial_block_it->second->t_created) {
                    state.chunks_avail.erase(first_partial_block_it->first.first);
                    mapPartialBlocks.erase(first_partial_block_it);
                } else {
                    state.chunks_avail.erase(second_partial_block_it->first.first);
                    mapPartialBlocks.erase(second_partial_block_it);
                }
            }
        }

        /* NOTE: once we add to chunks_avail, we MUST add to
         * PartialBlockData.perNodeChunkCount, or we will leak memory.
         *
         * This is mostly because chunks_avail is a state that is kept per node,
         * whereas perNodeChunkCount is kept per partial block. When the
         * decoding of a partial block is completed, function RemovePartialBlock
         * is called and the partial block is provided as argument. This
         * function, then, iterates over all nodes that are present in
         * PartialBlockData.perNodeChunkCount (nodes that delivered chunks of
         * the partial block) and, for each node, it erases the corresponding
         * entry (with the hash of the given block as key) from the chunks_avail
         * maps. Hence, the node must be registered in perNodeChunkCount in
         * order for the erasing from chunks_avail to work.
         */
        chunks_avail_it = state.chunks_avail.emplace(std::piecewise_construct,
                                                     std::forward_as_tuple(hash_prefix),
                                                     std::forward_as_tuple(they_have_block, n_chunks, is_blk_header_chunk))
                              .first;
    }

    if (they_have_block)
        chunks_avail_it->second.SetAllAvailable();
    else {
        // By calling Set*ChunkAvailable before SendMessageToNode's
        // SetHeaderDataAndFECChunkCount call, we will miss the first block packet we
        // receive and re-send that in UDPRelayBlock...this is OK because we'll save
        // more by doing this before the during-process relay below
        chunks_avail_it->second.SetChunkAvailable(msg.payload.fec.chunk_id, n_chunks, is_blk_content_chunk);
    }

    bool new_block = false;
    auto it = mapPartialBlocks.find(hash_peer_pair);
    if (it == mapPartialBlocks.end()) {
        it = mapPartialBlocks.insert(std::make_pair(hash_peer_pair, std::make_shared<PartialBlockData>(peer, node_context->mempool.get(), msg, packet_process_start))).first;
        new_block = true;
    }
    PartialBlockData& block = *it->second;

    std::chrono::steady_clock::time_point maps_scanned;
    if (fBench)
        maps_scanned = std::chrono::steady_clock::now();

    std::unique_lock<std::mutex> block_lock(block.state_mutex, std::try_to_lock);

    if ((is_blk_content_chunk && (block.is_decodeable || block.currentlyProcessing)) || // condition 1
        (is_blk_header_chunk && block.is_header_processing) ||                          // condition 2
        (is_blk_header_chunk && !block.in_header)) {                                    // condition 3
        /*
         * It seems this chunk isn't necessary, so it will be dropped. Yet, the
         * fact that we are here indicates that the block has not been processed
         * yet (setBlocksRelayed and setBlocksReceived don't have the block
         * yet). Thus, while the block is processing in ProcessNewBlockThread,
         * we continue forwarding chunks received from trusted peers.
         *
         * Note the conditions that lead to dropping:
         *
         * - Condition 1: We are already processing or ready to decode and
         *   process the block, so block content chunks are no longer necessary.
         *
         * - Condition 2: We know the header is already decodable, so further
         *   header FEC chunks are no longer necessary.
         *
         * - Condition 3: The header has already been decoded (ProvideHeaderData
         *   was called), so header chunks are no longer useful for decoding.
         */
        if (state.connection.fTrusted) {
            BlockMsgHToLE(msg);
            if (block.is_decodeable || block.currentlyProcessing)
                msg.header.msg_type |= HAVE_BLOCK;
            else
                msg.header.msg_type &= ~HAVE_BLOCK;
            // We didn't need this chunk, call it low priority assuming our
            // peers didn't as well
            SendMessageToAllNodes(msg, length, false, hash_prefix);
        }
    }

    if (!block_lock) {
        block.packet_awaiting_lock = true;
        block_lock.lock();
        block.packet_awaiting_lock = false;
    }

    auto perNodeChunkCountIt =
        block.perNodeChunkCount.insert(std::make_pair(node, std::make_pair(0, 0))).first;
    perNodeChunkCountIt->second.second++;

    // Check one more time after finally locking. Maybe the state changed inside
    // ProcessBlockThread. If the conditions still indicate the chunk is
    // unnecessary, return now that we already registered the chunk on
    // perNodeChunkCount.
    if ((is_blk_content_chunk && (block.is_decodeable || block.currentlyProcessing)) || // condition 1
        (is_blk_header_chunk && block.is_header_processing) ||                          // condition 2
        (is_blk_header_chunk && !block.in_header)) {                                    // condition 3
        return true;
    }

    if ((is_blk_content_chunk && !block.blk_initialized) ||
        (is_blk_header_chunk && !block.header_initialized)) {
        if (!block.Init(msg)) {
            LogPrintf("UDP: Got block contents that couldn't match header for block id %lu\n", msg.payload.fec.hash_prefix);
            return true;
        }

        /* If this is the first body chunk, and we've processed the header
         * already, we can kick off the processing whereby the the erasures of
         * the FEC-coded block are filled based on mempool txns. This processing
         * will start as long as !block.in_header && block.blk_initialized when
         * the PartialBlockData queued in block_process_queue is finally
         * processed. Otherwise, it won't start. Also, if the header is still
         * waiting on the block_process_queue to be processed, the
         * erasure-filling process will start automatically right after the
         * header processing, now that we have the first body chunk (i.e.,
         * block.blk_initialized). Importantly, the scan is only useful for
         * tip-of-the-chain (relayed) blocks inserted. Further notes below. */
        if (is_blk_content_chunk && block.tip_blk) {
            DoBackgroundBlockProcessing(*it); // Kick off mempool scan (waits on us to unlock block_lock)
        }
    }

    // If the block was initialized as non-tip, but later we received a chunk
    // marking the block as a tip block, treat it as a tip-of-the-chain block
    // regardless. This will affect how soon the block is pushed to the block
    // processing thread, or whether or not to run the block prefilling
    // mechanism. However, it won't necessarily determine the memory mode used
    // by the FECDecoder. The FECDecoder's memory mode may still be based on
    // memory-mapped storage if the very first chunk passed to the Init function
    // was not flagged as a tip block.
    block.tip_blk |= IS_TIP_BLOCK(msg);

    FECDecoder& decoder = is_blk_header_chunk ? block.header_decoder : block.body_decoder;

    if ((is_blk_header_chunk && (msg.payload.fec.obj_length != block.header_len)) ||
        (is_blk_content_chunk && (msg.payload.fec.obj_length != block.blk_len))) {
        // Duplicate hash_prefix or bad trusted peer
        LogPrintf("UDP: Got wrong obj_length/chunsk_sent for block id %lu from peer %s! Check your trusted peers are behaving well\n", msg.payload.fec.hash_prefix, node.ToStringAddrPort());
        return true;
    }

    if (decoder.HasChunk(msg.payload.fec.chunk_id)) {
        /* We are probably receiving a repeated chunk while the block is not
         * decodable yet. This is typical (and acceptable) when receiving from
         * multiple peers, especially for the initial uncoded chunks that are
         * sent by all peers through SendLimitedDataChunks. */
        return true;
    }

    if (is_blk_content_chunk && !block.in_header && msg.payload.fec.chunk_id < block.block_data.GetChunkCount()) {
        /* If in_header is true, ProvideHeaderData has not be called yet, which
         * means PartiallyDownloadedChunkBlock::InitData also has not been
         * called yet and, hence, chunksAvailable has not been resized. So
         * GetChunkCount() will fail. Thus, we check in_header before calling
         * GetChunkCount(). Also, this means we can't mark an uncoded chunk as
         * available yet. We can still feed it to the FEC decoder, though. And
         * FEC-coded chunks (chunk ids exceeding GetChunkCount()) are not
         * affected by this, as they are not marked as available.
         */
        assert(!block.block_data.IsChunkAvailable(msg.payload.fec.chunk_id)); // HasChunk should have returned false, then
        memcpy(block.block_data.GetChunk(msg.payload.fec.chunk_id), msg.payload.fec.data, sizeof(UDPFecMessage::data));
        block.block_data.MarkChunkAvailable(msg.payload.fec.chunk_id);
    }

    if (!decoder.ProvideChunk(msg.payload.fec.data, msg.payload.fec.chunk_id)) {
        // Bad chunk id, maybe FEC is upset? Don't disconnect in case it can be random
        LogPrintf("UDP: FEC chunk decode failed for chunk %d from block %lu from %s\n", msg.payload.fec.chunk_id, msg.payload.fec.hash_prefix, node.ToStringAddrPort());
        return true;
    }

    std::chrono::steady_clock::time_point chunks_processed;
    if (fBench)
        chunks_processed = std::chrono::steady_clock::now();

    // Keep track of chunks that are actually used for decoding
    perNodeChunkCountIt->second.first++;

    // Track the timestamp of the last FEC chunk actually used for decoding
    // (used to detect and time out inactive partial blocks)
    block.t_last_rx = packet_process_start;

    if (state.connection.fTrusted) {
        BlockMsgHToLE(msg);
        msg.header.msg_type &= ~HAVE_BLOCK;
        // We needed this chunk, call it high priority assuming our
        // peers will as well
        SendMessageToAllNodes(msg, length, true, hash_prefix);
    }

    if (decoder.DecodeReady()) {
        if (is_blk_header_chunk)
            block.is_header_processing = true;
        else
            block.is_decodeable = true;

        /* If this is a relayed block (from the tip of the chain), we kick-off
         * the processing of the FEC object as soon as it is ready, regardless
         * of which object it is. By doing so, if the header is the object that
         * is decoded first (the usual case), the ProcessBlockThread will
         * process the header immediately and prepare (reserved space for) the
         * chunk-coded block. Subsequently, as soon as the first body chunk
         * comes, the process thread will start to prefill the chunk-coded block
         * with txns from the mempool.
         *
         * In contrast, if this is a backfill block, we can wait until both
         * header and body FEC objects are ready to be decoded. If we pushed the
         * header right now, we would end up wasting a lot of memory with
         * reserved chunk-coded blocks that would not be prefilled (only tip
         * blocks are prefilled). In fact, the current implementation of the
         * ProcessBlockThread won't even allow this to happen. Nevertheless,
         * there are two main reasons to consider the early processing of a
         * non-tip block header:
         *
         * 1) We need to decode the header in order to find out if we already
         *    have the corresponding block. If we do have the block already, we
         *    can ignore subsequent chunks of the block and, with that, save
         *    significant processing. We can push the header FEC object for
         *    processing just so that the chain is looked up. After that, we can
         *    wait until the body is decodable to process the header again.
         *
         * 2) If the backfill block has an empty "body", i.e. contains only the
         *    coinbase txn, which comes in the header. Such empty blocks are
         *    sent through the header only, in which case the header must be
         *    processed as soon as ready.
         *
         * Note also that it's perfectly possible that we start receiving a
         * block from a tip block object, but fail to complete it, and then we
         * complete it based on the redundant (non-tip) block. From the tip
         * object, we could have completed either the header or the body
         * already. If we completed the header, we already processed it, as it
         * was processed immediately. So now we could be getting the body from a
         * non-tip block, and it's possible that flag block.is_header_processing
         * is false because the header has already been decoded, rather than
         * because it's not ready yet. So the missing piece is to check also
         * whether the header has already been processed (i.e. block.in_header
         * is false) when the body becomes decodable.
         *
         * To avoid confusion, instead of taking the "tip-block flag" from the
         * current packet, we always read it from the value initialized on the
         * partial block (i.e., block.tip_blk below). This way, the partial
         * block that started from a tip block remains like so.
         */
        if ((block.tip_blk ||
             (block.is_header_processing && (!block.chain_lookup || empty_block || block.is_decodeable)) ||
             (block.is_decodeable && !block.in_header)) // if for some reason we've processed the header of the non-tip block already
        ) {
            DoBackgroundBlockProcessing(*it);
        }

        // We do not RemovePartialBlock as we want ChunkAvailableSets to be there when UDPRelayBlock gets called
        // from inside ProcessBlockThread, so after we notify the ProcessNewBlockThread we cannot access block.
        block_lock.unlock();
    }

    if (fBench && new_block) {
        std::chrono::steady_clock::time_point finished(std::chrono::steady_clock::now());
        LogPrintf("UDP: Processed first block header chunk in %lf %lf %lf %lf\n", to_millis_double(start - packet_process_start), to_millis_double(maps_scanned - start), to_millis_double(chunks_processed - maps_scanned), to_millis_double(finished - chunks_processed));
    }

    return true;
}

void ProcessDownloadTimerEvents()
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    std::chrono::steady_clock::time_point t_now(std::chrono::steady_clock::now());
    for (auto it = mapPartialBlocks.begin(); it != mapPartialBlocks.end();) {
        // Time out partial blocks after 36h. However, if the block is coming
        // from a trusted peer, and we are not yet in sync with this peer, don't
        // time out the block at all.
        if (((it->second->peer != TRUSTED_PEER_DUMMY) || sync_with_trusted_peer) && (t_now - it->second->t_last_rx > std::chrono::hours(6))) {
            LogDebug(BCLog::FEC, "Timing out partial block %lu\n", it->first.first);
            it = RemovePartialBlock(it);
        } else {
            it++;
        }
    }
    // TODO: Prune setBlocksRelayed and setBlocksReceived to keep lookups fast?
}

struct BlkChunkStats {
    int height = -1;
    size_t header_rcvd = 0;
    size_t header_expected = 0;
    size_t body_rcvd = 0;
    size_t body_expected = 0;
    double progress = 0.0;
};

struct ChunkStats {
    int min_height = std::numeric_limits<int>::max();
    int max_height = 0;
    size_t n_blks = 0;
    size_t n_chunks = 0;
    BlkChunkStats min_blk;
    BlkChunkStats max_blk;
};

BlkChunkStats GetBlkChunkStats(const PartialBlockData& b)
{
    BlkChunkStats s;
    s.height = b.height;
    s.header_rcvd = b.header_decoder.GetChunksRcvd();
    s.body_rcvd = b.body_decoder.GetChunksRcvd();
    const bool h_init = b.header_initialized;
    const bool b_init = b.blk_initialized;
    s.header_expected = (h_init) ? b.header_decoder.GetChunkCount() : 0;
    s.body_expected = (b_init) ? b.body_decoder.GetChunkCount() : 0;
    s.progress = (h_init && b_init) ?
                     100.0 * ((double)(s.header_rcvd + s.body_rcvd)) /
                         (s.header_expected + s.body_expected) :
                     0.0;
    return s;
}

/* Convert block stats to JSON */
UniValue BlkChunkStatsToJSON(const BlkChunkStats& s)
{
    std::ostringstream h_stream;
    std::ostringstream b_stream;
    std::ostringstream p_stream;
    h_stream << s.header_rcvd << " / " << s.header_expected;
    b_stream << s.body_rcvd << " / " << s.body_expected;
    p_stream << std::setprecision(4) << s.progress << "%";

    UniValue info(UniValue::VOBJ);
    if (s.height != -1)
        info.pushKV("height", s.height);
    info.pushKV("header_chunks", h_stream.str());
    info.pushKV("body_chunks", b_stream.str());
    info.pushKV("progress", p_stream.str());
    return info;
}

/* Given a block height of interest, search if there is a partial block with
 * that height currently in memory and return the stats of that block in JSON */
UniValue BlkChunkStatsToJSON(const int target_height)
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (const auto& b : mapPartialBlocks) {
        std::unique_lock<std::mutex> block_lock(b.second->state_mutex);
        const int height = b.second->height;
        if (height != -1 && height == target_height) {
            const BlkChunkStats s = GetBlkChunkStats(*b.second);
            return BlkChunkStatsToJSON(s);
        }
    }
    return UniValue::VNULL;
}

/* Return JSON with chunk stats of the current partial blocks with min and max height */
UniValue MaxMinBlkChunkStatsToJSON()
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    ChunkStats s;

    s.n_blks = mapPartialBlocks.size();

    for (const auto& b : mapPartialBlocks) {
        std::unique_lock<std::mutex> block_lock(b.second->state_mutex);
        const BlkChunkStats blk_s = GetBlkChunkStats(*b.second);
        s.n_chunks += blk_s.header_rcvd;
        s.n_chunks += blk_s.body_rcvd;

        if (blk_s.height == -1)
            continue;

        if (blk_s.height < s.min_height) {
            s.min_height = blk_s.height;
            s.min_blk = blk_s;
        }

        if (blk_s.height > s.max_height) {
            s.max_height = blk_s.height;
            s.max_blk = blk_s;
        }
    }

    UniValue ret(UniValue::VOBJ);
    if (s.min_height != std::numeric_limits<int>::max())
        ret.pushKV("min_blk", BlkChunkStatsToJSON(s.min_blk));

    if (s.max_height != 0)
        ret.pushKV("max_blk", BlkChunkStatsToJSON(s.max_blk));

    ret.pushKV("n_blks", (uint64_t)s.n_blks);
    ret.pushKV("n_chunks", (uint64_t)s.n_chunks);

    return ret;
}

/* Return JSON with chunk stats of all current partial blocks */
UniValue AllBlkChunkStatsToJSON()
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UniValue o(UniValue::VOBJ);
    for (const auto& b : mapPartialBlocks) {
        std::unique_lock<std::mutex> block_lock(b.second->state_mutex);
        const uint64_t hash_prefix = b.first.first;
        std::stringstream stream;
        stream << std::hex << hash_prefix;
        std::string hex_hash_prefix(stream.str());
        const BlkChunkStats s = GetBlkChunkStats(*b.second);
        UniValue info = BlkChunkStatsToJSON(s);
        o.pushKV(hex_hash_prefix, info);
    }
    return o;
}

/* Get the most recent FEC hit ratios: the chunk and txn hit ratios
 *
 * The ratio refers to the number FEC chunks or txns already available for
 * incoming compact blocks in relation to the total number of chunks or txns in
 * the block. */
UniValue FecHitRatioToJson()
{
    UniValue ret(UniValue::VOBJ);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    for (auto it = mapUDPNodes.begin(); it != mapUDPNodes.end(); it++) {
        if (it->second.last_txn_hit_ratio != -1 &&
            it->second.last_chunk_hit_ratio != -1) {
            UniValue info(UniValue::VOBJ);
            info.pushKV("txn_ratio", it->second.last_txn_hit_ratio);
            info.pushKV("chunk_ratio", it->second.last_chunk_hit_ratio);
            ret.pushKV(it->first.ToStringAddrPort(), info);
        }
    }
    return ret;
}
