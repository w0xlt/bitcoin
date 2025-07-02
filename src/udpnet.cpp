// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019-2020 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <udpapi.h>
#include <udpnet.h>

#include <bitcoin-build-config.h>
#include <chainparams.h>
#include <common/args.h>
#include <common/bloom.h>
#include <compat/endian.h>
#include <consensus/validation.h>
#include <crypto/poly1305.h>
#include <hash.h>
#include <init.h> // for ShutdownRequested()
#include <logging.h>
#include <netbase.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <txmempool.h>
#include <util/strencodings.h>
#include <common/system.h>
#include <util/thread.h>
#include <util/time.h>
#include <validation.h>

#include <span.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <event2/event.h>

#include <poll.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <future>
#include <thread>

#ifndef WIN32
#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period> >(t).count())

static std::vector<int> udp_socks; // The sockets we use to send/recv (bound to *:GetUDPInboundPorts()[*])
static bool last_sock_is_local;

std::recursive_mutex cs_mapUDPNodes;
std::map<CService, UDPConnectionState> mapUDPNodes;
std::atomic<uint64_t> min_per_node_mbps(1024);
bool maybe_have_write_nodes;

static std::map<int64_t, std::tuple<CService, uint64_t, size_t> > nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

static CService LOCAL_WRITE_DEVICE_SERVICE(CNetAddr(), 1);
static CService LOCAL_READ_DEVICE_SERVICE(CNetAddr(), 2);

#define LOCAL_DEVICE_CHECKSUM_MAGIC htole64(0xdeadbeef)

// TODO: The checksum stuff is not endian-safe (esp the poly impl):
static void FillChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length)
{
    assert(length <= sizeof(UDPMessage));

    uint8_t key[Poly1305::KEYLEN]; // (32 bytes)
    memcpy(key, &magic, sizeof(magic));
    memcpy(key + 8, &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[Poly1305::TAGLEN]; // (16 bytes)
    
    // Create Poly1305 object with key and compute hash
    Poly1305 poly1305{std::span<const std::byte>{reinterpret_cast<const std::byte*>(key), Poly1305::KEYLEN}};
    poly1305.Update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&msg.header.msg_type), length - 16});
    poly1305.Finalize(std::span<std::byte>{reinterpret_cast<std::byte*>(hash), Poly1305::TAGLEN});
    
    memcpy(&msg.header.chk1, hash, sizeof(msg.header.chk1));
    memcpy(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));

    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type)[i + j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }
}

static bool CheckChecksum(uint64_t magic, UDPMessage& msg, const unsigned int length)
{
    assert(length <= sizeof(UDPMessage));
    for (unsigned int i = 0; i < length - 16; i += 8) {
        for (unsigned int j = 0; j < 8 && i + j < length - 16; j++) {
            ((unsigned char*)&msg.header.msg_type)[i + j] ^= ((unsigned char*)&msg.header.chk1)[j];
        }
    }

    uint8_t key[Poly1305::KEYLEN]; // (32 bytes)
    memcpy(key, &magic, sizeof(magic));
    memcpy(key + 8, &magic, sizeof(magic));
    memcpy(key + 16, &magic, sizeof(magic));
    memcpy(key + 24, &magic, sizeof(magic));

    uint8_t hash[Poly1305::TAGLEN]; // (16 bytes)
    
    // Create Poly1305 object with key and compute hash
    Poly1305 poly1305{std::span<const std::byte>{reinterpret_cast<const std::byte*>(key), Poly1305::KEYLEN}};
    poly1305.Update(std::span<const std::byte>{reinterpret_cast<const std::byte*>(&msg.header.msg_type), length - 16});
    poly1305.Finalize(std::span<std::byte>{reinterpret_cast<std::byte*>(hash), Poly1305::TAGLEN});
    
    return !memcmp(&msg.header.chk1, hash, sizeof(msg.header.chk1)) && !memcmp(&msg.header.chk2, hash + 8, sizeof(msg.header.chk2));
}

/**
 * Init/shutdown logic follows
 */

static struct event_base* event_base_read = NULL;
static event *timer_event;
static std::vector<event*> read_events;
static struct timeval timer_interval;

static void ThreadRunReadEventLoop() { event_base_dispatch(event_base_read); }
static void do_send_messages();
static void do_read_local_messages();
static std::atomic_bool local_read_messages_break(false);
static void send_messages_flush_and_break();
static void send_messages_init(const std::vector<std::pair<unsigned short, uint64_t> >& group_list, const std::tuple<int64_t, bool, std::string>& local_write_device);
static void ThreadRunWriteEventLoop() { do_send_messages(); }
static void ThreadRunLocalReadEventLoop() { do_read_local_messages(); }

static void read_socket_func(evutil_socket_t fd, short event, void* arg);
static void timer_func(evutil_socket_t fd, short event, void* arg);

static std::unique_ptr<std::thread> udp_local_read_thread;
static std::unique_ptr<std::thread> udp_read_thread;
static std::vector<std::thread> udp_write_threads;

static void OpenLocalDeviceConnection(bool fWrite);
static void StartLocalBackfillThread();
static std::tuple<int64_t, bool, std::string> get_local_device();

static void AddConnectionFromString(const std::string& node, bool fTrust) {
    size_t host_port_end = node.find(',');
    size_t local_pass_end = node.find(',', host_port_end + 1);
    size_t remote_pass_end = node.find(',', local_pass_end + 1);
    size_t group_end = node.find(',', remote_pass_end + 1);
    if (host_port_end == std::string::npos || local_pass_end == std::string::npos || (remote_pass_end != std::string::npos && group_end != std::string::npos)) {
        LogPrintf("UDP: Failed to parse parameter to -add[trusted]udpnode: %s\n", node);
        return;
    }

    std::string host_port = node.substr(0, host_port_end);
    std::optional<CService> addr = Lookup(host_port.c_str(), -1, true);
    if (!addr.has_value()) {
        LogPrintf("UDP: Failed to lookup hostname for -add[trusted]udpnode: %s\n", host_port);
        return;
    }

    std::string local_pass = node.substr(host_port_end + 1, local_pass_end - host_port_end - 1);
    uint64_t local_magic = Hash(local_pass).GetUint64(0);

    std::string remote_pass;
    if(remote_pass_end == std::string::npos)
        remote_pass = node.substr(local_pass_end + 1);
    else
        remote_pass = node.substr(local_pass_end + 1, remote_pass_end - local_pass_end - 1);
    uint64_t remote_magic = Hash(remote_pass).GetUint64(0);

    size_t group = 0;
    if (remote_pass_end != std::string::npos) {
        std::string group_str(node.substr(remote_pass_end + 1));
        group = LocaleIndependentAtoi<int>(group_str);
    }

    OpenPersistentUDPConnectionTo(addr.value(), local_magic, remote_magic, fTrust, UDP_CONNECTION_TYPE_NORMAL, group);
}

static void AddConfAddedConnections() {
    if (gArgs.IsArgSet("-addudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addudpnode")) {
            AddConnectionFromString(node, false);
        }
    }
    if (gArgs.IsArgSet("-addtrustedudpnode")) {
        for (const std::string& node : gArgs.GetArgs("-addtrustedudpnode")) {
            AddConnectionFromString(node, true);
        }
    }
}

static void CloseSocketsAndReadEvents() {
    for (event* ev : read_events)
        event_free(ev);
    for (int sock : udp_socks)
        close(sock);
    read_events.clear();
    udp_socks.clear();
}

bool InitializeUDPConnections() {
    assert(udp_write_threads.empty() && !udp_read_thread);

    const std::vector<std::pair<unsigned short, uint64_t> > group_list(GetUDPInboundPorts());
    for (std::pair<unsigned short, uint64_t> port : group_list) {
        udp_socks.push_back(socket(AF_INET6, SOCK_DGRAM, 0));
        assert(udp_socks.back());

        int opt = 1;
        assert(setsockopt(udp_socks.back(), SOL_SOCKET, SO_REUSEADDR, &opt,  sizeof(opt)) == 0);
        opt = 0;
        assert(setsockopt(udp_socks.back(), IPPROTO_IPV6, IPV6_V6ONLY, &opt,  sizeof(opt)) == 0);
        fcntl(udp_socks.back(), F_SETFL, fcntl(udp_socks.back(), F_GETFL) | O_NONBLOCK);

        struct sockaddr_in6 wildcard;
        memset(&wildcard, 0, sizeof(wildcard));
        wildcard.sin6_family = AF_INET6;
        memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
        wildcard.sin6_port = htons(port.first);

        if (bind(udp_socks.back(), (sockaddr*) &wildcard, sizeof(wildcard))) {
            CloseSocketsAndReadEvents();
            return false;
        }

        LogPrintf("UDP: Bound to port %hd for group %lu with %lu Mbps\n", port.first, udp_socks.size() - 1, port.second);
    }

    event_base_read = event_base_new();
    if (!event_base_read) {
        CloseSocketsAndReadEvents();
        return false;
    }

    for (int socket : udp_socks) {
        event *read_event = event_new(event_base_read, socket, EV_READ | EV_PERSIST, read_socket_func, NULL);
        if (!read_event) {
            event_base_free(event_base_read);
            CloseSocketsAndReadEvents();
            return false;
        }
        read_events.push_back(read_event);
        event_add(read_event, NULL);
    }

    // Init local write device only after udp socks were all added to read_event
    auto local_write_device = get_local_device();
    if (std::get<0>(local_write_device)) {
        int fd = open(std::get<2>(local_write_device).c_str(), O_WRONLY);
        if (fd < 0) {
            LogPrintf("Failed to open -fecwritedevice, not running any FIBRE connections\n");
            event_base_free(event_base_read);
            CloseSocketsAndReadEvents();
            return false;
        }
        udp_socks.push_back(fd);
    }

    timer_event = event_new(event_base_read, -1, EV_PERSIST, timer_func, NULL);
    if (!timer_event) {
        CloseSocketsAndReadEvents();
        event_base_free(event_base_read);
        return false;
    }
    timer_interval.tv_sec = 0;
    timer_interval.tv_usec = 500*1000;
    evtimer_add(timer_event, &timer_interval);

    send_messages_init(group_list, local_write_device);
    udp_write_threads.emplace_back(&util::TraceThread, "udpwrite", &ThreadRunWriteEventLoop);

    AddConfAddedConnections();

    if (std::get<0>(local_write_device)) {
        OpenLocalDeviceConnection(true);
        if (std::get<1>(local_write_device))
            StartLocalBackfillThread();
    }

    if (gArgs.IsArgSet("-fecreaddevice")) {
        OpenLocalDeviceConnection(false);
        udp_local_read_thread.reset(new std::thread(&util::TraceThread, "udpreadlocal", &ThreadRunLocalReadEventLoop));
    }

    // BlockRecvInit();

    udp_read_thread.reset(new std::thread(&util::TraceThread, "udpread", &ThreadRunReadEventLoop));

    return true;
}

// ---

/**
 * Network handling follows
 */

static std::map<CService, UDPConnectionState>::iterator silent_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    return mapUDPNodes.erase(it);
}

static std::map<CService, UDPConnectionState>::iterator send_and_disconnect(const std::map<CService, UDPConnectionState>::iterator& it) {
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    SendMessage(msg, sizeof(UDPMessageHeader), false, it);

    int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());;
    while (!nodesToRepeatDisconnect.insert(std::make_pair(now + 1000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second)
        now++;
    assert(nodesToRepeatDisconnect.insert(std::make_pair(now + 10000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second);

    return silent_disconnect(it);
}

void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it) {
    send_and_disconnect(it);
}

// ~10MB of outbound messages pending
#define PENDING_MESSAGES_BUFF_SIZE 8192
static std::atomic_bool send_messages_break(false);
std::mutex send_messages_mutex;
std::condition_variable send_messages_wake_cv;
struct PendingMessagesBuff {
    std::tuple<CService, UDPMessage, unsigned int, uint64_t> messagesPendingRingBuff[PENDING_MESSAGES_BUFF_SIZE];
    std::atomic<uint16_t> nextPendingMessage, nextUndefinedMessage;
    PendingMessagesBuff() : nextPendingMessage(0), nextUndefinedMessage(0) {}
};
struct MessageStateCache {
    ssize_t buff_id;
    uint16_t nextPendingMessage;
    uint16_t nextUndefinedMessage;
};
struct PerGroupMessageQueue {
    std::array<PendingMessagesBuff, 3> buffs;
    inline MessageStateCache NextBuff(std::memory_order order) {
        for (size_t i = 0; i < buffs.size(); i++) {
            uint16_t next_undefined_message = buffs[i].nextUndefinedMessage.load(order);
            uint16_t next_pending_message = buffs[i].nextPendingMessage.load(order);
            if (next_undefined_message != next_pending_message)
                return {(ssize_t)i, next_pending_message, next_undefined_message};
        }
        return {-1, 0, 0};
    }
    uint64_t bw;
    PerGroupMessageQueue() : bw(0) {}
    PerGroupMessageQueue(PerGroupMessageQueue&& q) = delete;
};
static std::vector<PerGroupMessageQueue> messageQueues;
static const size_t LOCAL_RECEIVE_GROUP = (size_t)-1;
static size_t LOCAL_SEND_GROUP = (size_t)-1;

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    assert(info.group < messageQueues.size() || addr == LOCAL_READ_DEVICE_SERVICE);

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    if (info.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
        maybe_have_write_nodes = true;

    bool fIsLocal = (addr == LOCAL_WRITE_DEVICE_SERVICE || addr == LOCAL_READ_DEVICE_SERVICE);

    LogDebug(BCLog::UDPNET, "UDP: Initializing connection to %s...\n", addr.ToStringAddrPort());

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = fIsLocal ? STATE_INIT_COMPLETE : STATE_INIT;
    state.lastSendTime = 0;
    state.lastRecvTime = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());

    if (addr != LOCAL_READ_DEVICE_SERVICE) {
        size_t group_count = 0;
        for (const auto& it : mapUDPNodes)
            if (it.second.connection.group == info.group)
                group_count++;
        min_per_node_mbps = std::min(min_per_node_mbps.load(), messageQueues[info.group].bw / group_count);
    }

    if (fIsLocal) {
        for (size_t i = 0; i < sizeof(state.last_pings) / sizeof(double); i++) {
            state.last_pings[i] = 0;
        }
    }
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group) {
    if (connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY)
        group = LOCAL_RECEIVE_GROUP;

    OpenUDPConnectionTo(addr, {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group) {
    if (connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY)
        group = LOCAL_RECEIVE_GROUP;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;

    UDPConnectionInfo info = {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type};
    OpenUDPConnectionTo(addr, info);
    mapPersistentNodes[addr] = info;
}

void CloseUDPConnectionTo(const CService& addr) {
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    auto it = mapPersistentNodes.find(addr);
    if (it != mapPersistentNodes.end())
        mapPersistentNodes.erase(it);

    auto it2 = mapUDPNodes.find(addr);
    if (it2 == mapUDPNodes.end())
        return;
    DisconnectNode(it2);
}

static void OpenLocalDeviceConnection(bool fWrite) {
    const CService& service = fWrite ? LOCAL_WRITE_DEVICE_SERVICE : LOCAL_READ_DEVICE_SERVICE;
    OpenPersistentUDPConnectionTo(service, LOCAL_DEVICE_CHECKSUM_MAGIC, LOCAL_DEVICE_CHECKSUM_MAGIC, false,
            fWrite ? UDP_CONNECTION_TYPE_OUTBOUND_ONLY : UDP_CONNECTION_TYPE_INBOUND_ONLY,
            fWrite ? LOCAL_SEND_GROUP : LOCAL_RECEIVE_GROUP);
}
