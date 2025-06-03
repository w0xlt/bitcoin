// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019-2020 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#ifndef BITCOIN_UDPNET_H
#define BITCOIN_UDPNET_H

#include <assert.h>
#include <atomic>
#include <chain.h>
#include <mutex>
#include <stdint.h>
#include <vector>

#include <netaddress.h>

#include <blockencodings.h>
#include <fec.h>

// This is largely the API between udpnet and udprelay, see udpapi for the
// external-facing API

// Local stuff only uses magic, net stuff only uses protocol_version,
// so both need to be changed any time wire format changes
static const unsigned char LOCAL_MAGIC_BYTES[] = {0xab, 0xad, 0xca, 0xfe};
static const uint32_t UDP_PROTOCOL_VERSION = (4 << 16) | 4; // Min version 3, current version 3

enum UDPMessageType {
    MSG_TYPE_SYN = 0,
    MSG_TYPE_KEEPALIVE = 1, // aka SYN_ACK
    MSG_TYPE_DISCONNECT = 2,
    MSG_TYPE_BLOCK_HEADER_AND_TXIDS = 3,
    MSG_TYPE_BLOCK_CONTENTS = 4,
    MSG_TYPE_PING = 5,
    MSG_TYPE_PONG = 6,
    MSG_TYPE_TX_CONTENTS = 7,
};

#define IS_BLOCK_HEADER_AND_TXIDS_MSG(msg) ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_HEADER_AND_TXIDS)
#define IS_BLOCK_CONTENTS_MSG(msg) ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_BLOCK_CONTENTS)
#define IS_TX_CONTENTS_MSG(msg) ((msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK) == MSG_TYPE_TX_CONTENTS)

static const uint8_t UDP_MSG_TYPE_FLAGS_MASK = 0b11100000;
static const uint8_t UDP_MSG_TYPE_TYPE_MASK = 0b00011111;

struct __attribute__((packed)) UDPMessageHeader {
    uint64_t chk1 = 0;
    uint64_t chk2 = 0;
    uint8_t msg_type; // UDPMessageType + UDPBlockMessageFlags(s)
};
static_assert(sizeof(UDPMessageHeader) == 17, "__attribute__((packed)) must work");

// Message body cannot exceed 1167 bytes (1185 bytes in total UDP message contents, with a padding byte in message)
// Local send logic assumes this to be the size of block data packets in a few places!
#define MAX_UDP_MESSAGE_LENGTH 1167

enum UDPBlockMessageFlags { // Put in the msg_type
    EMPTY_BLOCK = (1 << 5), // mark when block body is empty (only header is sent)
    HAVE_BLOCK = (1 << 6),
    TIP_BLOCK = (1 << 7) // mark that this is a block on the chain's tip (relayed)
};

#define IS_TIP_BLOCK(msg) (msg.header.msg_type & TIP_BLOCK)
#define IS_EMPTY_BLOCK(msg) (msg.header.msg_type & EMPTY_BLOCK)

struct __attribute__((packed)) UDPFecMessage {
    /**
     * First 8 bytes of blockhash, interpreted in LE (note that this will not include 0s, those are at the end).
     * For txn, first 8 bytes of tx, though this should change in the future.
     * Neither block nor tx recv-side logic cares what this is as long as it mostly-uniquely identifies the
     * object being sent!
     */
    uint64_t hash_prefix;
    uint32_t obj_length; // Size of full FEC-coded data
    uint32_t chunk_id : 24;
    unsigned char data[FEC_CHUNK_SIZE];
};
static_assert(sizeof(UDPFecMessage) == MAX_UDP_MESSAGE_LENGTH, "FEC messages must be == MAX_UDP_MESSAGE_LENGTH");
static const size_t udp_fec_msg_header_size = sizeof(UDPFecMessage) - FEC_CHUNK_SIZE;

struct __attribute__((packed)) UDPMessage {
    UDPMessageHeader header;
    union __attribute__((packed)) {
        unsigned char message[MAX_UDP_MESSAGE_LENGTH + 1];
        uint64_t longint;
        struct UDPFecMessage fec;
    } payload;
};
static_assert(sizeof(UDPMessage) == 1185, "__attribute__((packed)) must work");
#define PACKET_SIZE (sizeof(UDPMessage) + 40 + 8)
static_assert(PACKET_SIZE <= 1280, "All packets must fit in min-MTU for IPv6");
static_assert(sizeof(UDPMessage) == sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH + 1, "UDPMessage should have 1 padding byte");

enum UDPState {
    STATE_INIT = 0,                                          // Indicating the node was just added
    STATE_GOT_SYN = 1,                                       // We received their SYN
    STATE_GOT_SYN_ACK = 1 << 1,                              // We've received a KEEPALIVE (which they only send after receiving our SYN)
    STATE_INIT_COMPLETE = STATE_GOT_SYN | STATE_GOT_SYN_ACK, // We can now send data to this peer
};

struct ChunkFileNameParts {
    struct in_addr ipv4Addr;
    unsigned short port;
    size_t length;
    uint64_t hash_prefix;
    bool is_header;
};

struct FecOverhead {
    uint32_t fixed;
    double variable;
};

#endif