// Copyright (c) 2016, 2017 Matt Corallo
// Copyright (c) 2019-2020 Blockstream
// Unlike the rest of Bitcoin Core, this file is
// distributed under the Affero General Public License (AGPL v3)

#include <ringbuffer.h>
#include <throttle.h>
#include <udpmulticasttx.h>
#include <udpmulticasttxdb.h>
#include <udpnet.h>
#include <udprelay.h>

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

#define to_millis_double(t) (std::chrono::duration_cast<std::chrono::duration<double, std::chrono::milliseconds::period>>(t).count())
#define DIV_CEIL(a, b) (((a) + (b)-1) / (b))

template <typename Duration>
double to_seconds(Duration d)
{
    return std::chrono::duration_cast<std::chrono::duration<double, std::chrono::seconds::period>>(d).count();
}

/**
 * Copy string using strncpy while enforcing a null termination
 *
 * Copies at most count-1 from src to dest and places the terminating null
 * character at the last dst position.
 */
static char* strncpy_wrapper(char* dest, const char* src, std::size_t count)
{
    strncpy(dest, src, count - 1);
    dest[count - 1] = '\0';
    return dest;
}

static std::vector<int> udp_socks; // The sockets we use to send/recv (bound to *:GetUDPInboundPorts()[*])

std::recursive_mutex cs_mapUDPNodes;
std::map<CService, UDPConnectionState> mapUDPNodes;
bool maybe_have_write_nodes;

static std::map<int64_t, std::tuple<CService, uint64_t, size_t>> nodesToRepeatDisconnect;
static std::map<CService, UDPConnectionInfo> mapPersistentNodes;

static uint32_t g_mcast_log_interval = 10;

static node::NodeContext* g_node_context; // Initialized by InitializeUDPConnections

/*
 * UDP multicast service
 *
 * Unlike the main UDP communication mechanism, the multicast service does not
 * require a "connection". The multicast Tx node transmits messages without ever
 * knowing about the existing receivers and receivers only need to listen to a
 * particular multicast ip:port by joining the multicast group.
 */
namespace {
std::map<std::tuple<CService, int, uint16_t>, UDPMulticastInfo> mapMulticastNodes;
const std::string multicast_pass = "multicast";
uint64_t const multicast_magic = Hash(multicast_pass).GetUint64(0);
} // namespace
uint64_t const multicast_checksum_magic = htole64(multicast_magic);

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

static struct event_base* event_base_read = nullptr;
static event* timer_event;
static std::vector<event*> read_events;
static struct timeval timer_interval;

// ~10MB of outbound messages pending
static std::atomic_bool send_messages_break(false);
std::mutex non_empty_queues_cv_mutex;
std::condition_variable non_empty_queues_cv;

struct RingBufferElement {
    CService service;
    UDPMessage msg;
    unsigned int length;
    uint64_t magic;
};

typedef RingBuffer<RingBufferElement> UdpMsgRingBuffer;

struct PerGroupMessageQueue {
    std::array<UdpMsgRingBuffer, 4> buffs;
    ssize_t buff_id; // active buffer
    /* Three message queues (buffers) per group:
     * 0) high priority
     * 1) best-effort (non priority)
     * 2) background txns (used by txn thread)
     * 3) background blocks (used by backfill thread)
     *
     * The current buffer is indicated by `state.buff_id`. This id is set to -1
     * when all buffers are empty.
     */

    /* Find the next buffer with data available for transmission, while
     * respecting buffer priorities. */
    inline void NextBuff()
    {
        for (size_t i = 0; i < buffs.size(); i++) {
            if (!buffs[i].IsEmpty()) {
                buff_id = i;
                return;
            }
        }
        buff_id = -1;
    }

    uint64_t bw;
    bool multicast;
    bool unlimited;  // when non rate-limited (limited by a blocking socket instead)
    bool lossy_exit; // whether the Tx loop can exit while the ring buffers are non-empty
    Throttle ratelimiter;
    std::chrono::steady_clock::time_point next_send;
    PerGroupMessageQueue() : buff_id(-1), bw(0), multicast(false), unlimited(false), lossy_exit(false), ratelimiter(0) {}
    PerGroupMessageQueue(size_t buff_depth, bool lossy_exit) : buffs{
                                                                   {UdpMsgRingBuffer(buff_depth),
                                                                    UdpMsgRingBuffer(buff_depth),
                                                                    UdpMsgRingBuffer(buff_depth),
                                                                    UdpMsgRingBuffer(buff_depth)}},
                                                               buff_id(-1), bw(0), multicast(false), unlimited(false), lossy_exit(lossy_exit), ratelimiter(0) {}
    PerGroupMessageQueue(PerGroupMessageQueue&& q) = delete;
};
static std::map<size_t, PerGroupMessageQueue> mapTxQueues;

static void ThreadRunReadEventLoop() { event_base_dispatch(event_base_read); }
static void do_send_messages();
static void send_messages_flush_and_break();
static std::map<size_t, PerGroupMessageQueue> InitTxQueues(const std::vector<std::pair<unsigned short, uint64_t>>& group_list,
                                                           const std::vector<UDPMulticastInfo>& multicast_list);
static void ThreadRunWriteEventLoop() { do_send_messages(); }

static void read_socket_func(evutil_socket_t fd, short event, void* arg);
static void timer_func(evutil_socket_t fd, short event, void* arg);

static std::unique_ptr<std::thread> partial_block_load_thread;
static std::unique_ptr<std::thread> udp_read_thread;
static std::vector<std::thread> udp_write_threads;

static void OpenMulticastConnection(const CService& service, bool multicast_tx, size_t group, bool trusted);
static bool ParseUDPMulticastInfo(const std::string& s, UDPMulticastInfo& info);
static bool ParseUDPMulticastTxInfo(const std::string& s, UDPMulticastInfo& info);
static bool GetUDPMulticastInfo(std::vector<UDPMulticastInfo>& v);

static void MulticastBackfillThread(const CService& mcastNode, const UDPMulticastInfo* info);
static void LaunchMulticastBackfillThreads();
static std::vector<std::thread> mcast_tx_threads;


static void AddConnectionFromString(const std::string& node, bool fTrust)
{
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
    if (remote_pass_end == std::string::npos)
        remote_pass = node.substr(local_pass_end + 1);
    else
        remote_pass = node.substr(local_pass_end + 1, remote_pass_end - local_pass_end - 1);
    uint64_t remote_magic = Hash(remote_pass).GetUint64(0);

    size_t group = 0;
    if (remote_pass_end != std::string::npos) {
        std::string group_str(node.substr(remote_pass_end + 1));
        group = LocaleIndependentAtoi<int>(group_str);
    }

    OpenPersistentUDPConnectionTo(addr.value(), local_magic, remote_magic, fTrust, UDP_CONNECTION_TYPE_NORMAL, group, udp_mode_t::unicast);
}

static void AddConfAddedConnections()
{
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

static void CloseSocketsAndReadEvents()
{
    for (event* ev : read_events)
        event_free(ev);
    for (int sock : udp_socks)
        close(sock);
    read_events.clear();
    udp_socks.clear();
}

/* Find the IPv4 address corresponding to a given interface name */
static struct in_addr GetIfIpAddr(const char* const ifname)
{
    struct in_addr res_sin_addr;
    bool if_ip_found = false;

#ifdef _WIN32
    // Windows implementation using GetAdaptersAddresses
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG retVal = 0;
    
    // Allocate buffer
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (pAddresses == nullptr) {
        throw std::runtime_error("Memory allocation failed");
    }
    
    // Get adapter information
    retVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, 
                                  pAddresses, &bufferSize);
    
    if (retVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
        if (pAddresses == nullptr) {
            throw std::runtime_error("Memory allocation failed");
        }
        retVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, nullptr, 
                                     pAddresses, &bufferSize);
    }
    
    if (retVal == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        
        while (pCurrAddresses) {
            // Check if this is the interface we're looking for
            // Windows can use either AdapterName or FriendlyName
            if (strcmp(pCurrAddresses->AdapterName, ifname) == 0 ||
                wcscmp(pCurrAddresses->FriendlyName, 
                       std::wstring(ifname, ifname + strlen(ifname)).c_str()) == 0) {
                
                // Get the first IPv4 address
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                while (pUnicast) {
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                        struct sockaddr_in* sa_in = (struct sockaddr_in*)pUnicast->Address.lpSockaddr;
                        res_sin_addr = sa_in->sin_addr;
                        if_ip_found = true;
                        break;
                    }
                    pUnicast = pUnicast->Next;
                }
                
                if (if_ip_found) break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    if (pAddresses) {
        free(pAddresses);
    }
    
#else
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0) {
        for (struct ifaddrs* ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                char astring[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(s4->sin_addr), astring, INET_ADDRSTRLEN);
                if (strcmp(ifa->ifa_name, ifname) == 0) {
                    res_sin_addr = s4->sin_addr;
                    if_ip_found = true;
                    break;
                }
            }
        }
        freeifaddrs(myaddrs);
    }
#endif

    if (!if_ip_found) {
        LogPrintf("UDP: find IP address of interface %s\n", ifname);
        throw std::runtime_error("Couldn't find IP address");
    }

    return res_sin_addr;
}

__attribute__((unused)) static void ListNetworkInterfaces()
{
#ifdef _WIN32
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, 
                            pAddresses, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        
        LogPrintf("Available network interfaces on Windows:\n");
        while (pCurrAddresses) {
            LogPrintf("  Adapter Name: %s\n", pCurrAddresses->AdapterName);
            char friendlyName[256];
            wcstombs(friendlyName, pCurrAddresses->FriendlyName, sizeof(friendlyName));
            LogPrintf("  Friendly Name: %s\n", friendlyName);
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    free(pAddresses);
#else
    struct ifaddrs* myaddrs;
    
    LogPrintf("Available network interfaces:\n");
    if (getifaddrs(&myaddrs) == 0) {
        for (struct ifaddrs* ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                LogPrintf("  Interface: %s\n", ifa->ifa_name);
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}

static void DumpUdpMulticastTxConfig(const UDPMulticastInfo& info)
{
    std::ostringstream out;

    out << "Multicast tx " << info.physical_idx << "-" << info.logical_idx << "\n"
        << "[Networking]\n"
        << " - Multicast address: " << info.mcast_ip << "\n"
        << " - Interface: " << info.ifname << "\n"
        << " - Bandwidth: " << ((info.bw == 0) ? "unlimited" : tfm::format("%u bps", info.bw)) << "\n"
        << " - TTL: " << info.ttl << "\n"
        << " - DSCP: " << info.dscp << "\n"
        << "[Streams]\n"
        << tfm::format(" - New blocks: %s\n", info.relay_new_blks ? "true" : "false")
        << tfm::format(" - Historic blocks: %s\n", info.send_rep_blks ? "true" : "false")
        << tfm::format(" - Mempool txns: %s\n", info.txn_per_sec > 0 ? "true" : "false")
        << "[Tx Ring Buffers]\n"
        << " - Depth: " << info.ringbuff_depth << "\n"
        << tfm::format(" - Lossy exit: %s\n", info.lossy_exit ? "true" : "false");

    if (info.send_rep_blks) {
        out << "[Historic Blocks]\n"
            << " - Depth: " << info.depth << "\n"
            << " - Offset: " << info.offset << "\n"
            << " - Interleave: " << info.interleave_len << "\n"
            << tfm::format(" - Overhead: %d + %.2f%%\n", info.overhead_rep_blks.fixed,
                           (100 * info.overhead_rep_blks.variable));
    }

    if (info.txn_per_sec > 0) {
        out << "[Mempool Txns]\n"
            << " - Txns/sec: " << info.txn_per_sec << "\n";
    }

    LogPrintf("UDP: %s", out.str());
}

/**
 * Initialize multicast tx/rx services
 *
 * Initialize the multicast tx services configured via `udpmulticasttx` and the
 * multicast reception groups configured via `udpmulticast`.
 */
static bool InitializeUDPMulticast(std::vector<int>& udp_socks,
                                   std::vector<UDPMulticastInfo>& multicast_list)
{
    size_t group = udp_socks.size() - 1;
    std::map<std::pair<CService, int>, int> physical_idx_map;
    std::map<std::pair<CService, int>, int> logical_idx_map;

    for (auto& mcast_info : multicast_list) {
        udp_socks.push_back(socket(AF_INET6, SOCK_DGRAM, 0));
        assert(udp_socks.back());
        mcast_info.fd = udp_socks.back();

        int opt = 1;
        if (setsockopt(udp_socks.back(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
            LogPrintf("UDP: setsockopt failed: %s\n", NetworkErrorString(errno));
            return false;
        }

        opt = 0;
        if (setsockopt(udp_socks.back(), IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0) {
            LogPrintf("UDP: setsockopt failed: %s\n", NetworkErrorString(errno));
            return false;
        }

        fcntl(udp_socks.back(), F_SETFL, fcntl(udp_socks.back(), F_GETFL) | O_NONBLOCK);

        /* Bind socket to the multicast service UDP port for any IP address */
        unsigned short multicast_port = mcast_info.port;

        struct sockaddr_in6 wildcard;
        memset(&wildcard, 0, sizeof(wildcard));
        wildcard.sin6_family = AF_INET6;
        memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
        wildcard.sin6_port = htons(multicast_port);

        if (bind(udp_socks.back(), (sockaddr*)&wildcard, sizeof(wildcard))) {
            LogPrintf("UDP: bind failed: %s\n", NetworkErrorString(errno));
            return false;
        }

        /* Get index of network interface */
        const int ifindex = if_nametoindex(mcast_info.ifname);
        if (ifindex == 0) {
            LogPrintf("Error: couldn't find an index for interface %s: %s\n",
                      mcast_info.ifname, NetworkErrorString(errno));
            return false;
        }

        /* Get network interface IPv4 address */
        struct in_addr imr_interface = GetIfIpAddr(mcast_info.ifname);
        char imr_interface_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &imr_interface, imr_interface_str,
                  INET_ADDRSTRLEN);

        struct sockaddr_in multicastaddr;
        memset(&multicastaddr, 0, sizeof(multicastaddr));

        /* Is this a multicast Tx group? i.e. if target bandwidth is defined */
        if (mcast_info.tx) {
            LogPrintf("UDP: bind multicast Tx socket %d to interface %s\n",
                      udp_socks.back(), mcast_info.ifname);

            /* Don't loop messages that we send back to us */
            int no_loop = 0;
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_MULTICAST_LOOP, &no_loop, sizeof(no_loop)) != 0) {
                LogPrintf("UDP: setsockopt(IP_MULTICAST_LOOP) failed: %s\n", NetworkErrorString(errno));
                return false;
            }

            /* Set TTL of multicast messages */
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_MULTICAST_TTL, &mcast_info.ttl, sizeof(mcast_info.ttl)) != 0) {
                LogPrintf("UDP: setsockopt(IP_MULTICAST_TTL) failed: %s\n", NetworkErrorString(errno));
                return false;
            }

            /* Ensure multicast packets are tx'ed by the chosen interface
             *
             * NOTE: the preceding binding restricts the device used for
             * reception, whereas the option that follows determines the
             * device for transmission. */
            struct ip_mreqn req;
            memset(&req, 0, sizeof(req));
            req.imr_ifindex = ifindex;
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_MULTICAST_IF, &req, sizeof(req)) != 0) {
                LogPrintf("UDP: setsockopt(IP_MULTICAST_IF) failed: %s\n", NetworkErrorString(errno));
                return false;
            }

            /* DSCP */
            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_TOS, &mcast_info.dscp, sizeof(mcast_info.dscp)) != 0) {
                LogPrintf("UDP: setsockopt failed: %s\n", NetworkErrorString(errno));
                return false;
            }

            /* CService identifier: destination multicast IP address */
            inet_pton(AF_INET, mcast_info.mcast_ip, &multicastaddr.sin_addr);
        } else {
            /* Multicast Rx mode */

            // Check the current maximum socket receive buffer size in bytes
            int actual_rcvbuf;
            socklen_t optlen = sizeof(actual_rcvbuf);
            if (getsockopt(udp_socks.back(), SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf, &optlen) != 0) {
                LogPrintf("UDP: getsockopt(SO_RCVBUF) failed: %s\n", NetworkErrorString(errno));
                return false;
            }
            actual_rcvbuf >>= 1; // getsockopt returns double the rcvbuf size

            // Make the buffer large enough to hold 1000 max-length packets
            const int min_rcvbuf = 1000 * PACKET_SIZE;
            if (actual_rcvbuf < min_rcvbuf) {
                if (setsockopt(udp_socks.back(), SOL_SOCKET, SO_RCVBUF, &min_rcvbuf, sizeof(int)) != 0) {
                    LogPrintf("UDP: setsockopt(SO_RCVBUF) failed: %s\n", NetworkErrorString(errno));
                    return false;
                }

                /* The kernel may not set the size we asked for depending on the
                 * rmem_max setting. Double check: */
                socklen_t optlen = sizeof(actual_rcvbuf);
                if (getsockopt(udp_socks.back(), SOL_SOCKET, SO_RCVBUF, &actual_rcvbuf, &optlen) != 0) {
                    LogPrintf("UDP: getsockopt(SO_RCVBUF) failed: %s\n", NetworkErrorString(errno));
                    return false;
                }
                actual_rcvbuf >>= 1; // getsockopt returns double the rcvbuf size

                if (actual_rcvbuf < min_rcvbuf) {
                    LogPrintf("WARNING: failed to configure UDP receive buffer size of %d bytes.\n",
                              min_rcvbuf);
                    LogPrintf("Please configure the maximum receive buffer size allowed by the OS.\n");
#ifdef __linux__
                    LogPrintf("You can check the current setting by running:\n\n"
                              "> sysctl net.core.rmem_max\n\n");
                    LogPrintf("If the current maximum is less than %d, you can increase it by running:\n\n"
                              "> sysctl -w net.core.rmem_max=%d\n\n",
                              min_rcvbuf, min_rcvbuf);
#endif
                }
            }

            /* Join multicast group, but only allow multicast packets from a
             * specific source address */
            struct ip_mreq_source req;
            memset(&req, 0, sizeof(req));
            inet_pton(AF_INET, mcast_info.mcast_ip, &(req.imr_multiaddr));
            req.imr_interface = imr_interface;
            inet_pton(AF_INET, mcast_info.tx_ip, &(req.imr_sourceaddr));

            if (setsockopt(udp_socks.back(), IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &req, sizeof(req)) != 0) {
                LogPrintf("UDP: setsockopt(IP_ADD_SOURCE_MEMBERSHIP) failed: %s\n", NetworkErrorString(errno));
                return false;
            }

            /* CService identifier: Tx node IP address (source address). On
             * "read_socket_func", the source address obtained by "recvfrom"
             * is used in order to find the corresponding CService */
            inet_pton(AF_INET, mcast_info.tx_ip, &multicastaddr.sin_addr);

            LogPrintf("UDP: multicast rx -  multiaddr: %s, interface: %s (%s)"
                      ", sourceaddr: %s, trusted: %u\n",
                      mcast_info.mcast_ip,
                      mcast_info.ifname,
                      imr_interface_str,
                      mcast_info.tx_ip,
                      mcast_info.trusted);
        }

        group++;
        mcast_info.group = group;
        /* For multicast Rx, don't care about the UDP port of the Tx node */
        const unsigned short cservice_port = mcast_info.tx ? multicast_port : 0;
        const CService addr{multicastaddr.sin_addr, cservice_port};

        /* Each address-ifindex pair is associated to an unique physical
         * index. Tx streams sharing the same physical index are configured with
         * different (unique) logical stream indexes. */
        if (mcast_info.tx) {
            const auto addr_ifindex_pair = std::make_pair(addr, ifindex);

            // The physical index depends only on the address/ifindex pair
            if (physical_idx_map.find(addr_ifindex_pair) == physical_idx_map.end())
                physical_idx_map[addr_ifindex_pair] = physical_idx_map.size();

            // The logical index increments for every stream reusing a
            // pre-existing address/ifindex pair
            if (logical_idx_map.find(addr_ifindex_pair) == logical_idx_map.end())
                logical_idx_map[addr_ifindex_pair] = 0;
            else
                logical_idx_map[addr_ifindex_pair]++;

            mcast_info.physical_idx = physical_idx_map[addr_ifindex_pair];
            mcast_info.logical_idx = logical_idx_map[addr_ifindex_pair];

            DumpUdpMulticastTxConfig(mcast_info);
        }

        /* Index based on multicast "addr", ifindex and logical index
         *
         * On udpmulticasttx, the logical stream index is unique among instances
         * that share the same addr-ifindex pair, whereas all udpmulticast (Rx)
         * instances have the same stream index.
         *
         * As a result, in Rx it is only possible to receive from the same
         * source address if the network interface differs. In contrast, in tx,
         * it is possible to feed two or more streams to the same destination
         * multicast address and the same network interface. This is used to
         * multiplex logical multicast streams with different rates and
         * coverages of past blocks.
         *
         * NOTE: on udpmulticasttx, "addr" is the destination multicast address,
         * while on udpmulticast (rx), "addr" is the source address.
         */
        const auto mcast_map_key = std::make_tuple(addr, ifindex,
                                                   mcast_info.logical_idx);
        if (mapMulticastNodes.count(mcast_map_key) > 0) {
            LogPrintf("UDP: error - multicast instance (%s, %s, %d) already exists\n",
                      addr.ToStringAddrPort(), ifindex, mcast_info.logical_idx);
            return false;
        }
        mapMulticastNodes[mcast_map_key] = mcast_info;

        LogPrintf("UDP: Socket %d bound to port %hd for multicast group %zu %s\n",
                  udp_socks.back(), multicast_port, group,
                  mcast_info.groupname);
    }

    return true;
}

/* Get information from the UDP multicast Rx instances */
UniValue UdpMulticastRxInfoToJson()
{
    UniValue ret(UniValue::VOBJ);
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    const auto t_now = std::chrono::steady_clock::now();
    for (const auto& node : mapMulticastNodes) {
        if (node.second.tx)
            continue;

        /* Average bitrate since the last RPC call */
        UDPMulticastStats& stats = node.second.stats;
        const double elapsed = to_millis_double(t_now - stats.t_last_rpc);
        stats.t_last_rpc = t_now;
        uint64_t new_bytes = stats.rcvd_bytes - stats.last_rcvd_bytes_rpc;
        stats.last_rcvd_bytes_rpc = stats.rcvd_bytes;
        const double bitrate_kbps = (double)(new_bytes * 8) / (elapsed);

        double bitrate;
        std::string unit;
        if (bitrate_kbps > 1e3) {
            bitrate = bitrate_kbps / 1000;
            unit = "Mbps";
        } else {
            bitrate = bitrate_kbps;
            unit = "kbps";
        }

        UniValue info(UniValue::VOBJ);
        info.pushKV("bitrate", std::to_string(bitrate) + " " + unit);
        info.pushKV("group", (uint64_t)node.second.group);
        info.pushKV("groupname", node.second.groupname);
        info.pushKV("ifname", node.second.ifname);
        info.pushKV("mcast_ip", node.second.mcast_ip);
        info.pushKV("port", node.second.port);
        info.pushKV("rcvd_bytes", stats.rcvd_bytes);
        info.pushKV("trusted", node.second.trusted);
        ret.pushKV(std::get<0>(node.first).ToStringAddrPort(), info);
    }
    return ret;
}

bool InitializeUDPConnections(node::NodeContext* const node_context)
{
    assert(udp_write_threads.empty() && !udp_read_thread);
    g_node_context = node_context;

    if (!InitFec()) {
        return false;
    }

    if (gArgs.IsArgSet("-udpmulticastloginterval"))
        g_mcast_log_interval = LocaleIndependentAtoi<uint32_t>(gArgs.GetArg("-udpmulticastloginterval", ""));

    const std::vector<std::pair<unsigned short, uint64_t>> group_list(GetUDPInboundPorts());
    for (std::pair<unsigned short, uint64_t> port : group_list) {
        udp_socks.push_back(socket(AF_INET6, SOCK_DGRAM, 0));
        assert(udp_socks.back());

        int opt = 1;
        assert(setsockopt(udp_socks.back(), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0);
        opt = 0;
        assert(setsockopt(udp_socks.back(), IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) == 0);
        fcntl(udp_socks.back(), F_SETFL, fcntl(udp_socks.back(), F_GETFL) | O_NONBLOCK);

        struct sockaddr_in6 wildcard;
        memset(&wildcard, 0, sizeof(wildcard));
        wildcard.sin6_family = AF_INET6;
        memcpy(&wildcard.sin6_addr, &in6addr_any, sizeof(in6addr_any));
        wildcard.sin6_port = htons(port.first);

        if (bind(udp_socks.back(), (sockaddr*)&wildcard, sizeof(wildcard))) {
            CloseSocketsAndReadEvents();
            return false;
        }

        LogPrintf("UDP: Bound to port %hd for group %zu with %lu Mbps\n", port.first, udp_socks.size() - 1, port.second);
    }

    event_base_read = event_base_new();
    if (!event_base_read) {
        CloseSocketsAndReadEvents();
        return false;
    }

    std::vector<UDPMulticastInfo> multicast_list;
    if (!GetUDPMulticastInfo(multicast_list)) {
        CloseSocketsAndReadEvents();
        return false;
    }

    if (!InitializeUDPMulticast(udp_socks, multicast_list)) {
        CloseSocketsAndReadEvents();
        return false;
    }

    for (int socket : udp_socks) {
        event* read_event = event_new(event_base_read, socket, EV_READ | EV_PERSIST, read_socket_func, nullptr);
        if (!read_event) {
            event_base_free(event_base_read);
            CloseSocketsAndReadEvents();
            return false;
        }
        read_events.push_back(read_event);
        event_add(read_event, nullptr);
    }

    timer_event = event_new(event_base_read, -1, EV_PERSIST, timer_func, nullptr);
    if (!timer_event) {
        CloseSocketsAndReadEvents();
        event_base_free(event_base_read);
        return false;
    }
    timer_interval.tv_sec = 0;
    timer_interval.tv_usec = 500 * 1000;
    evtimer_add(timer_event, &timer_interval);

    /* Initialize Tx message queues */
    mapTxQueues = InitTxQueues(group_list, multicast_list);

    udp_write_threads.emplace_back(&util::TraceThread, "udpwrite", &ThreadRunWriteEventLoop);

    /* Add persistent connections to pre-defined udpnodes or trustedudpnodes */
    AddConfAddedConnections();

    /* One-way multicast connections */
    for (const auto& multicastNode : mapMulticastNodes) {
        OpenMulticastConnection(std::get<0>(multicastNode.first),
                                multicastNode.second.tx,
                                multicastNode.second.group,
                                multicastNode.second.trusted);
    }

    /* Multicast transmission threads */
    LaunchMulticastBackfillThreads();

    BlockRecvInit(node_context->chainman.get());

    partial_block_load_thread.reset(new std::thread(&util::TraceThread,
                                                    "udploadpartialblks",
                                                    std::bind(LoadPartialBlocks, node_context->mempool.get())));

    udp_read_thread.reset(new std::thread(&util::TraceThread, "udpread", &ThreadRunReadEventLoop));

    return true;
}

void StopUDPConnections()
{
    if (!udp_read_thread)
        return;

    StopLoadPartialBlocks();
    partial_block_load_thread->join();
    partial_block_load_thread.reset();

    event_base_loopbreak(event_base_read);
    udp_read_thread->join();
    udp_read_thread.reset();

    BlockRecvShutdown();

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    for (auto const& s : mapUDPNodes) {
        if (s.second.connection.connection_type == UDP_CONNECTION_TYPE_NORMAL)
            SendMessage(msg, sizeof(UDPMessageHeader), true, s);
    }
    mapUDPNodes.clear();

    send_messages_flush_and_break();

    for (std::thread& t : udp_write_threads)
        t.join();
    udp_write_threads.clear();

    for (std::thread& t : mcast_tx_threads)
        t.join();
    mcast_tx_threads.clear();

    CloseSocketsAndReadEvents();

    event_free(timer_event);
    event_base_free(event_base_read);
}


/**
 * Network handling follows
 */

static std::map<CService, UDPConnectionState>::iterator silent_disconnect(const std::map<CService, UDPConnectionState>::iterator& it)
{
    return mapUDPNodes.erase(it);
}

static std::map<CService, UDPConnectionState>::iterator send_and_disconnect(const std::map<CService, UDPConnectionState>::iterator& it)
{
    UDPMessage msg;
    msg.header.msg_type = MSG_TYPE_DISCONNECT;
    SendMessage(msg, sizeof(UDPMessageHeader), false, *it);

    int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());;
    while (!nodesToRepeatDisconnect.insert(std::make_pair(now + 1000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second)
        now++;
    assert(nodesToRepeatDisconnect.insert(std::make_pair(now + 10000, std::make_tuple(it->first, it->second.connection.remote_magic, it->second.connection.group))).second);

    return silent_disconnect(it);
}

void DisconnectNode(const std::map<CService, UDPConnectionState>::iterator& it)
{
    send_and_disconnect(it);
}

static void UpdateUdpMulticastRxBytes(const UDPMulticastInfo& mcast_info, const size_t rcvd_bytes)
{
    UDPMulticastStats& stats = mcast_info.stats;
    stats.rcvd_bytes += rcvd_bytes;

    // Print the bit rate periodically if the required logging level is active
    if (!LogAcceptCategory(BCLog::UDPMCAST, BCLog::Level::Debug))
        return;

    auto t_now = std::chrono::steady_clock::now();
    const double elapsed = to_millis_double(t_now - stats.t_last_print);
    if (elapsed > (1000 * g_mcast_log_interval)) {
        uint64_t new_bytes = stats.rcvd_bytes - stats.last_rcvd_bytes_print;
        LogDebug(BCLog::UDPMCAST, "UDP multicast group %zu: Average bit rate %7.2f Mbit/sec (%s)\n",
                 mcast_info.group,
                 (double)(new_bytes * 8) / (1000 * elapsed),
                 mcast_info.groupname);
        stats.t_last_print = t_now;
        stats.last_rcvd_bytes_print = stats.rcvd_bytes;
    }
}

static void read_socket_func(evutil_socket_t fd, short event, void* arg)
{
    const bool fBench = LogAcceptCategory(BCLog::BENCH, BCLog::Level::Debug);
    std::chrono::steady_clock::time_point start(std::chrono::steady_clock::now());

    UDPMessage msg{};
    /* We will place the incoming UDP message payload into `msg`. However, not
     * necessarily the incoming payload will fill the entire `UDPMessage`
     * structure. Hence, zero-initialize `msg` here. */
    struct sockaddr_in6 remoteaddr;
    socklen_t remoteaddrlen = sizeof(remoteaddr);

    ssize_t res = recvfrom(fd, &msg, sizeof(msg), MSG_DONTWAIT, (sockaddr*)&remoteaddr, &remoteaddrlen);
    if (res < 0) {
        int err = errno;
        LogPrintf("UDP: Error reading from socket: %d (%s)!\n", err, NetworkErrorString(err));
        return;
    }
    assert(remoteaddrlen == sizeof(remoteaddr));
    CService c_remoteaddr(remoteaddr);

    if (size_t(res) < sizeof(UDPMessageHeader) || size_t(res) >= sizeof(UDPMessage))
        return;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    /* Is this coming from a multicast Tx node and through a multicast Rx
     * socket? */
    bool from_mcast_tx = false;
    std::map<std::tuple<CService, int, uint16_t>, UDPMulticastInfo>::iterator itm;
    for (itm = mapMulticastNodes.begin(); itm != mapMulticastNodes.end(); ++itm) {
        if ((CNetAddr)c_remoteaddr == (CNetAddr)(std::get<0>(itm->first))) {
            if (fd == itm->second.fd) {
                from_mcast_tx = true;
                break;
            }
        }
    }

    /* If receiving from a multicast service, find node by IP only and not with
     * the address brought by `recvfrom`, which includes the source port. This
     * is because the source port of multicast Tx nodes can be random. */
    std::map<CService, UDPConnectionState>::iterator it;
    if (from_mcast_tx) {
        const CService& mcasttx_addr = std::get<0>(itm->first);
        it = mapUDPNodes.find(mcasttx_addr);
    } else
        it = mapUDPNodes.find(c_remoteaddr);

    if (it == mapUDPNodes.end())
        return;
    if (!CheckChecksum(it->second.connection.local_magic, msg, res)) {
        LogPrintf("UDP: Checksum error on message from %s\n", it->first.ToStringAddrPort());
        return;
    }

    UDPConnectionState& state = it->second;

    const uint8_t msg_type_masked = (msg.header.msg_type & UDP_MSG_TYPE_TYPE_MASK);

    /* Handle multicast msgs first (no need to check connection state) */
    if (state.connection.udp_mode == udp_mode_t::multicast) {
        if (itm == mapMulticastNodes.end()) {
            LogPrintf("Couldn't find multicast node\n");
            return;
        }
        const UDPMulticastInfo& mcast_info = itm->second;

        if (msg_type_masked == MSG_TYPE_BLOCK_HEADER_AND_TXIDS ||
            msg_type_masked == MSG_TYPE_BLOCK_CONTENTS ||
            msg_type_masked == MSG_TYPE_TX_CONTENTS) {
            if (!HandleBlockTxMessage(msg, sizeof(UDPMessage) - 1, it->first, it->second, start, g_node_context))
                send_and_disconnect(it);
            else
                UpdateUdpMulticastRxBytes(mcast_info, res);
        } else
            LogPrintf("UDP: Unexpected message from %s!\n", it->first.ToStringAddrPort());

        return;
    }

    state.lastRecvTime = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());;
    if (msg_type_masked == MSG_TYPE_SYN) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized SYN message from %s\n", it->first.ToStringAddrPort());
            send_and_disconnect(it);
            return;
        }

        state.protocolVersion = le64toh(msg.payload.longint);
        if (PROTOCOL_VERSION_MIN(state.protocolVersion) > PROTOCOL_VERSION_CUR(UDP_PROTOCOL_VERSION)) {
            LogPrintf("UDP: Got min protocol version we didnt understand (%u:%u) from %s\n", PROTOCOL_VERSION_MIN(state.protocolVersion), PROTOCOL_VERSION_CUR(state.protocolVersion), it->first.ToStringAddrPort());
            send_and_disconnect(it);
            return;
        }

        if (!(state.state & STATE_GOT_SYN))
            state.state |= STATE_GOT_SYN;
    } else if (msg_type_masked == MSG_TYPE_KEEPALIVE) {
        if (res != sizeof(UDPMessageHeader)) {
            LogPrintf("UDP: Got invalidly-sized KEEPALIVE message from %s\n", it->first.ToStringAddrPort());
            send_and_disconnect(it);
            return;
        }
        if ((state.state & STATE_INIT_COMPLETE) != STATE_INIT_COMPLETE)
            LogDebug(BCLog::UDPNET, "UDP: Successfully connected to %s!\n", it->first.ToStringAddrPort());

        // If we get a SYNACK without a SYN, that probably means we were restarted, but the other side wasn't
        // ...this means the other side thinks we're fully connected, so just switch to that mode
        state.state |= STATE_GOT_SYN_ACK | STATE_GOT_SYN;
    } else if (msg_type_masked == MSG_TYPE_DISCONNECT) {
        LogPrintf("UDP: Got disconnect message from %s\n", it->first.ToStringAddrPort());
        silent_disconnect(it);
        return;
    }

    if (!(state.state & STATE_INIT_COMPLETE))
        return;

    if (msg_type_masked == MSG_TYPE_BLOCK_HEADER_AND_TXIDS || msg_type_masked == MSG_TYPE_BLOCK_CONTENTS) {
        if (!HandleBlockTxMessage(msg, res, it->first, it->second, start, g_node_context)) {
            send_and_disconnect(it);
            return;
        }
    } else if (msg_type_masked == MSG_TYPE_TX_CONTENTS) {
        LogPrintf("UDP: Got tx message over the wire from %s, this isn't supposed to happen!\n", it->first.ToStringAddrPort());
        /* NOTE Only the multicast service sends tx messages. */
        send_and_disconnect(it);
        return;
    } else if (msg_type_masked == MSG_TYPE_PING) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PING message from %s\n", it->first.ToStringAddrPort());
            send_and_disconnect(it);
            return;
        }

        msg.header.msg_type = MSG_TYPE_PONG;
        SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, *it);
    } else if (msg_type_masked == MSG_TYPE_PONG) {
        if (res != sizeof(UDPMessageHeader) + 8) {
            LogPrintf("UDP: Got invalidly-sized PONG message from %s\n", it->first.ToStringAddrPort());
            send_and_disconnect(it);
            return;
        }

        uint64_t nonce = le64toh(msg.payload.longint);
        std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.find(nonce);
        if (nonceit == state.ping_times.end()) // Possibly duplicated packet
            LogPrintf("UDP: Got PONG message without PING from %s\n", it->first.ToStringAddrPort());
        else {
            int64_t timeMicros = TicksSinceEpoch<std::chrono::microseconds>(SystemClock::now());
            double rtt = (timeMicros - nonceit->second) / 1000.0;
            LogPrintf("UDP: RTT to %s is %lf ms\n", it->first.ToStringAddrPort(), rtt);
            state.ping_times.erase(nonceit);
            state.last_pings[state.last_ping_location] = rtt;
            state.last_ping_location = (state.last_ping_location + 1) % (sizeof(state.last_pings) / sizeof(double));
        }
    }

    if (fBench) {
        std::chrono::steady_clock::time_point finish(std::chrono::steady_clock::now());
        if (to_millis_double(finish - start) > 1)
            LogPrintf("UDP: Packet took %lf ms to process\n", to_millis_double(finish - start));
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info);
static void timer_func(evutil_socket_t fd, short event, void* arg)
{
    ProcessDownloadTimerEvents();

    UDPMessage msg;
    const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());;

    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    {
        std::map<int64_t, std::tuple<CService, uint64_t, size_t>>::iterator itend = nodesToRepeatDisconnect.upper_bound(now);
        for (std::map<int64_t, std::tuple<CService, uint64_t, size_t>>::const_iterator it = nodesToRepeatDisconnect.begin(); it != itend; it++) {
            msg.header.msg_type = MSG_TYPE_DISCONNECT;
            SendMessage(msg, sizeof(UDPMessageHeader), false, std::get<0>(it->second), std::get<1>(it->second), std::get<2>(it->second));
        }
        nodesToRepeatDisconnect.erase(nodesToRepeatDisconnect.begin(), itend);
    }

    for (std::map<CService, UDPConnectionState>::iterator it = mapUDPNodes.begin(); it != mapUDPNodes.end();) {
        if (it->second.connection.connection_type != UDP_CONNECTION_TYPE_NORMAL) {
            it++;
            continue;
        }

        UDPConnectionState& state = it->second;

        int64_t origLastSendTime = state.lastSendTime;

        if (state.lastRecvTime < now - 1000 * 60 * 10) {
            LogDebug(BCLog::UDPNET, "UDP: Peer %s timed out\n", it->first.ToStringAddrPort());
            it = send_and_disconnect(it); // Removes it from mapUDPNodes
            continue;
        }

        if (!(state.state & STATE_GOT_SYN_ACK) && origLastSendTime < now - 1000) {
            msg.header.msg_type = MSG_TYPE_SYN;
            msg.payload.longint = htole64(UDP_PROTOCOL_VERSION);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, *it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_GOT_SYN) && origLastSendTime < now - 1000 * ((state.state & STATE_GOT_SYN_ACK) ? 10 : 1)) {
            msg.header.msg_type = MSG_TYPE_KEEPALIVE;
            SendMessage(msg, sizeof(UDPMessageHeader), false, *it);
            state.lastSendTime = now;
        }

        if ((state.state & STATE_INIT_COMPLETE) == STATE_INIT_COMPLETE && state.lastPingTime < now - 1000 * 60 * 15) {
            uint64_t pingnonce = FastRandomContext().rand64();
            msg.header.msg_type = MSG_TYPE_PING;
            msg.payload.longint = htole64(pingnonce);
            SendMessage(msg, sizeof(UDPMessageHeader) + 8, false, *it);
            int64_t timeMicros = TicksSinceEpoch<std::chrono::microseconds>(SystemClock::now());
            state.ping_times[pingnonce] = timeMicros;
            state.lastPingTime = now;
        }

        for (std::map<uint64_t, int64_t>::iterator nonceit = state.ping_times.begin(); nonceit != state.ping_times.end();) {
            if (nonceit->second < (now - 5000) * 1000)
                nonceit = state.ping_times.erase(nonceit);
            else
                nonceit++;
        }

        it++;
    }

    for (const auto& conn : mapPersistentNodes) {
        if (!mapUDPNodes.count(conn.first)) {
            bool fWaitingOnDisconnect = false;
            for (const auto& repeatNode : nodesToRepeatDisconnect) {
                if (std::get<0>(repeatNode.second) == conn.first)
                    fWaitingOnDisconnect = true;
            }
            if (fWaitingOnDisconnect)
                continue;

            OpenUDPConnectionTo(conn.first, conn.second);
        }
    }
}

static inline void SendMessage(const UDPMessage& msg, const unsigned int length, PerGroupMessageQueue& queue, UdpMsgRingBuffer& buff, const CService& service, const uint64_t magic)
{
    std::unique_lock<std::mutex> lock(non_empty_queues_cv_mutex);
    const bool was_empty = buff.IsEmpty();
    lock.unlock();

    buff.WriteElement([&](RingBufferElement& elem) {
        elem.service = service;
        elem.length = length;
        elem.magic = magic;
        memcpy(&elem.msg, &msg, length);
    });

    if (was_empty)
        non_empty_queues_cv.notify_all();
}

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const CService& service, const uint64_t magic, size_t group)
{
    assert(length <= sizeof(UDPMessage));
    assert(mapTxQueues.count(group));
    PerGroupMessageQueue& queue = mapTxQueues[group];
    UdpMsgRingBuffer& buff = high_prio ? queue.buffs[0] : queue.buffs[1];
    SendMessage(msg, length, queue, buff, service, magic);
}

void SendMessage(const UDPMessage& msg, const unsigned int length, bool high_prio, const std::pair<const CService, UDPConnectionState>& node)
{
    SendMessage(msg, length, high_prio, node.first, node.second.connection.remote_magic, node.second.connection.group);
}

static inline bool IsAnyQueueReady()
{
    bool have_work = false;
    for (auto& q : mapTxQueues) {
        PerGroupMessageQueue& queue = q.second;
        queue.NextBuff();
        if (queue.buff_id != -1) {
            have_work = true;
            break;
        }
    }
    return have_work;
}

// Maximum number of consecutive transmissions from the same queue
static int max_consecutive_tx = 10;

static void do_send_messages()
{
#ifndef WIN32
    {
        struct sched_param sched {
            sched_get_priority_max(SCHED_RR)
        };
        int res = pthread_setschedparam(pthread_self(), SCHED_RR, &sched);
        LogPrintf("UDP: %s write thread priority to SCHED_RR%s\n", !res ? "Set" : "Was unable to set", !res ? "" : (res == EPERM ? " (permission denied)" : " (other error)"));
        if (res) {
            res = nice(-20);
            errno = 0;
            LogPrintf("UDP: %s write thread nice value to %d%s\n", !errno ? "Set" : "Was unable to set", res, !errno ? "" : (errno == EPERM ? " (permission denied)" : " (other error)"));
        }
    }
#endif

    // Keep one poll configuration for each queue */
    std::map<ssize_t, int> map_pollfd;
    struct pollfd* pfds;
    const int nfds = mapTxQueues.size();
    pfds = (struct pollfd*)calloc(nfds, sizeof(struct pollfd));

    /* Initialize state of the Tx queues and the corresponding pollfd structs */
    const std::chrono::steady_clock::time_point t_now(std::chrono::steady_clock::now());
    int i_pollfd = 0;
    for (auto& q : mapTxQueues) {
        q.second.next_send = t_now;
        q.second.buff_id = -1;
        pfds[i_pollfd].fd = udp_socks[q.first];
        pfds[i_pollfd].events = POLLOUT;
        map_pollfd[q.first] = i_pollfd;
        assert(pfds[i_pollfd].revents == 0);
        i_pollfd++;
    }

    while (true) {
        /* If all queues are rate-limited, keep track of the next upcoming
         * transmission time and, by the end of this loop, sleep until this time
         * comes. Start with a timestamp far into the future and reduce the
         * timestamp for each queue. If there is any non rate-limited (i.e.,
         * unlimited) queue, this sleeping mechanism will be effectively
         * disabled, as t_next_tx will always converge to the current time in
         * subsequent calls to std::min. In this case (with unlimited queues),
         * the sleeping is handled through blocking calls to poll() instead of
         * using "sleep_until(t_next_tx)".
         *
         * Ideally, either all queues are rate-limited or all unlimited. Mixing
         * rate-limited with unlimited queues won't lead to efficient
         * sleeping. */
        std::chrono::steady_clock::time_point t_next_tx(
            std::chrono::steady_clock::now() + std::chrono::minutes(60));

        /* Iterate over Tx queues and schedule transmissions */
        bool maybe_all_empty = true;                    // unless told otherwise
        bool maybe_all_full = (mapTxQueues.size() > 0); // likewise

        for (auto& q : mapTxQueues) {
            PerGroupMessageQueue& queue = q.second;
            const size_t group = q.first;
            const std::chrono::steady_clock::time_point t_now(std::chrono::steady_clock::now());

            if (queue.next_send > t_now) {
                t_next_tx = std::min(t_next_tx, queue.next_send);
                continue;
            }

            /* Search a higher priority non-empty buffer if... */
            if (queue.buff_id != 0 ||                   // we are not currently in the highest priority buffer
                queue.buffs[queue.buff_id].IsEmpty()) { // ...the current buffer is empty
                queue.NextBuff();
            }

            if (queue.buff_id == -1) { // all buffers of this group are empty
                /* NOTE: although this group is empty, do not assume prematurely
                 * that the corresponding socket is not full (i.e., do not set
                 * maybe_all_full=false). Otherwise, we could end up in a
                 * situation where both maybe_all_full and maybe_all_empty are
                 * false in case there are other groups with non-empty status to
                 * set maybe_all_empty=false. In this scenario, the scheduler
                 * would keep spinning, as it would not call poll and neither
                 * wait on the non_empty_queues_cv condition variable. Instead,
                 * set maybe_all_full to false only when we know there is at
                 * least one non-full socket after trying the "sendto" calls
                 * below. Meanwhile, for the empty groups we haven't tried any
                 * sendto call (like the current), simply remove them from the
                 * list of sockets to be polled. See the assignment to
                 * "pfds[map_pollfd[group]].fd" below. */
                continue;
            }

            // Read from the ring buffer and send over the network
            UdpMsgRingBuffer* buff = &queue.buffs[queue.buff_id];

            int consecutive_tx = 0; // packets tx'ed consecutively from this queue
            bool wouldblock = false;
            /* Keep going as long as... */
            while ((queue.buff_id != -1) &&                                               // the queue has messages to transmit
                   (queue.unlimited || queue.ratelimiter.HasQuota(sizeof(UDPMessage))) && // the output bitrate is OK
                   (consecutive_tx < max_consecutive_tx)) {                               // we are not depriving other queues
                // Get the next message for transmission
                ReadProxy<RingBufferElement> rd_proxy(buff);
                RingBufferElement* next_tx = rd_proxy.GetObj();

                // Set the checksum and scramble the data
                if (next_tx->msg.header.chk1 == 0 && next_tx->msg.header.chk2 == 0) {
                    if (queue.multicast) {
                        assert(IS_BLOCK_HEADER_AND_TXIDS_MSG(next_tx->msg) ||
                               IS_BLOCK_CONTENTS_MSG(next_tx->msg) ||
                               IS_TX_CONTENTS_MSG(next_tx->msg));
                    }
                    FillChecksum(next_tx->magic, next_tx->msg, next_tx->length);
                }

                // Set destination address
                sockaddr_storage ss = {};
                socklen_t addrlen;
                if (next_tx->service.IsIPv6()) {
                    sockaddr_in6* remoteaddr = (sockaddr_in6*)&ss;
                    remoteaddr->sin6_family = AF_INET6;
                    assert(next_tx->service.GetIn6Addr(&remoteaddr->sin6_addr));
                    remoteaddr->sin6_port = htons(next_tx->service.GetPort());
                    addrlen = sizeof(sockaddr_in6);
                } else {
                    sockaddr_in* remoteaddr = (sockaddr_in*)&ss;
                    remoteaddr->sin_family = AF_INET;
                    assert(next_tx->service.GetInAddr(&remoteaddr->sin_addr));
                    remoteaddr->sin_port = htons(next_tx->service.GetPort());
                    addrlen = sizeof(sockaddr_in);
                }

                // Try to transmit
                ssize_t res = sendto(udp_socks[group], &next_tx->msg, next_tx->length, 0, (sockaddr*)&ss, addrlen);
                if (res != next_tx->length) {
                    /* Likely EAGAIN/EWOULDBLOCK. Don't advance the buffer's
                     * read pointer and try again later */
                    if (errno == EWOULDBLOCK) {
                        wouldblock = true;
                    } else {
                        LogPrintf("UDP: sendto to group %zu failed: %s\n",
                                  group, NetworkErrorString(errno));
                    }
                    break;
                }
                consecutive_tx++;

                // Consume the transmission quota
                if (!queue.unlimited)
                    queue.ratelimiter.UseQuota(next_tx->length);

                // Advance to the highest-priority non-empty buffer in this
                // queue group
                rd_proxy.ConfirmRead(next_tx->length);
                if (buff->IsEmpty()) {
                    queue.NextBuff();
                    if (queue.buff_id != -1)
                        buff = &queue.buffs[queue.buff_id];
                }
            }

            // If the transmission loop stopped before filling the socket
            // buffer, it's likely that there is at least one non-full socket.
            if (!wouldblock)
                maybe_all_full = false;

            // If the transmission loop stopped before emptying this queue,
            // there is definitely at least one non-empty queue.
            if (queue.buff_id != -1)
                maybe_all_empty = false;

            // If this queue is empty, temporarily remove it from the polling
            // list so that we don't wait for output space on a queue that is
            // empty. Otherwise, the polling could return immediately, given
            // that the socket buffer is likely to have available space when the
            // corresponding queue is empty. Ultimately, the transmission loop
            // would keep spininning while searching for a non-empty queue
            // instead of properly blocking on the poll call.
            //
            // Nevertheless, note there is an important side-effect of this
            // approach. Suppose the empty queue is allocated externally with a
            // high capacity to transmit high-priority but sporadic data, like
            // new mined blocks. Suppose also this queue shares the network
            // interface with other slower queues that are constantly full, like
            // those transmitting historic blocks. In this case, the
            // fast/sporadic queue that is frequently empty won't have any
            // influence on the poll call. Instead, only the slow/full queues
            // will block on the poll, so the fast/sporadic queue will
            // eventually wait until the slower queues obtain output space. Once
            // the slower queues find space and return from the poll call, the
            // fast sporadic queue will carry on with its normal rate.
            pfds[map_pollfd[group]].fd = (queue.buff_id != -1) ? udp_socks[group] : -1;

            /* How long will it take until we have enough quota to send at least
             * one MTU?
             *
             * NOTE: A non rate-limited queue sleeps on calls to poll() instead
             * of sleeping based on the "queue.next_send" values. */
            const uint32_t wait_ms = (queue.unlimited) ? 0 :
                                                         queue.ratelimiter.EstimateWait(sizeof(UDPMessage));

            queue.next_send += std::chrono::milliseconds(wait_ms);
            t_next_tx = std::min(t_next_tx, queue.next_send);
        }

        // Make sure all messages are transmitted before terminating this loop,
        // unless a lossy exit is allowed for this queue. For instance, a
        // lossless exit ensures the transmission progress saved on the UDP
        // Multicast Tx db corresponds to the chunks actually transmitted by
        // this loop, i.e., no chunks skipped on program termination.
        if (send_messages_break) {
            if (maybe_all_empty)
                return;
            if (std::all_of(
                    mapTxQueues.cbegin(),
                    mapTxQueues.cend(),
                    [](const auto& q) { return q.second.buff_id == -1 || q.second.lossy_exit; }))
                return;
        }

        // Wait until at least one socket is writable
        if (maybe_all_full) {
            int n_ready = 0;
            bool retry_poll = true;
            while (retry_poll) {
                n_ready = poll(pfds, nfds, -1 /* Wait indefinitely */);
                retry_poll = (n_ready < 0) && (errno == EINTR);
            }
            if (n_ready == 0) {
                LogPrintf("UDP: unexpected poll timeout\n");
            } else if (n_ready < 0) {
                LogPrintf("UDP: unexpected poll error: %s\n", NetworkErrorString(errno));
            }
        }

        // Wait until at least one queue has messages to send
        if (maybe_all_empty) {
            std::unique_lock<std::mutex> lock(non_empty_queues_cv_mutex);
            if (!IsAnyQueueReady())
                non_empty_queues_cv.wait(lock);
        }

        // Wait until the earliest scheduled transmission comes
        //
        // NOTE: if we just slept waiting for any queue to become non-empty, do
        // not sleep now. There is a risk that "t_next_tx" was not set to a
        // value other than its initialization value (far into the future).
        std::chrono::steady_clock::time_point t_end(std::chrono::steady_clock::now());
        if (t_next_tx > t_end && !maybe_all_empty) {
            std::this_thread::sleep_until(t_next_tx);
        }
    }
}

UniValue TxQueueInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    for (auto& q : mapTxQueues) {
        UniValue q_info(UniValue::VOBJ);
        // Buffer-specific information
        for (int i = 0; i < 4; i++) {
            UniValue b_info(UniValue::VOBJ);
            auto stats = q.second.buffs[i].GetStats();
            b_info.pushKV("tx_bytes", stats.rd_bytes);
            b_info.pushKV("tx_pkts", stats.rd_count);
            q_info.pushKV("Buffer " + std::to_string(i), b_info);
        }
        ret.pushKV("Group " + std::to_string(q.first), q_info);
    }
    return ret;
}

std::map<std::pair<uint16_t, uint16_t>, std::shared_ptr<BackfillBlockWindow>> block_window_map;
std::map<std::pair<uint16_t, uint16_t>, BackfillTxnWindow> txn_window_map;

std::mutex block_window_map_mutex;
std::mutex txn_window_map_mutex;

typedef std::map<int, size_t> BlockProgressMap;
typedef BlockProgressMap::const_iterator BlockProgressMapIt;

static size_t AddBlocksFromProgressMapRange(BackfillBlockWindow* pblock_window,
                                            BlockProgressMapIt first,
                                            BlockProgressMapIt last,
                                            const std::pair<uint16_t, uint16_t>& tx_idx,
                                            const FecOverhead& overhead)
{
    const node::BlockManager& blockman = g_node_context->chainman->ActiveChainstate().m_blockman;

    const CBlockIndex* pindex;
    size_t n_success = 0;
    for (auto it = first; it != last; it++) {
        if (send_messages_break)
            break;
        {
            LOCK(cs_main);
            pindex = g_node_context->chainman->ActiveChain()[it->first];
        }
        if (pindex == nullptr) {
            LogPrintf("UDP: Multicast Tx %lu-%lu - Failed to restore block %d\n",
                      tx_idx.first, tx_idx.second, it->first);
            continue;
        }
        if (pblock_window->Add(blockman, pindex, overhead, it->second))
            n_success++;
    }
    return n_success;
}

static void AddBlocksFromProgressMap(BackfillBlockWindow* pblock_window,
                                     const BlockProgressMap& height_idx_map,
                                     const std::pair<uint16_t, uint16_t>& tx_idx,
                                     const FecOverhead& overhead)
{
    LogPrintf("UDP: Multicast Tx %lu-%lu - Restoring %lu blocks from the previous session\n",
              tx_idx.first, tx_idx.second, height_idx_map.size());

    // Divide the workload into parallel asynchronous workers
    unsigned int n_cores = std::max(std::thread::hardware_concurrency(), 1u);
    size_t n_elems_per_task = DIV_CEIL(height_idx_map.size(), n_cores);
    BlockProgressMapIt it = height_idx_map.begin();
    BlockProgressMapIt it_begin = it;
    BlockProgressMapIt it_end;
    std::vector<std::future<size_t>> futures;
    size_t n_elems = 0;
    while (true) {
        if (n_elems == n_elems_per_task || it == height_idx_map.end()) {
            it_end = it;
            futures.push_back(std::async(std::launch::async,
                                         AddBlocksFromProgressMapRange,
                                         pblock_window,
                                         it_begin,
                                         it_end,
                                         tx_idx,
                                         overhead));
            it_begin = it;
            n_elems = 0;
        }
        if (it == height_idx_map.end())
            break;
        n_elems++;
        it++;
    }

    size_t n_success = 0;
    for (auto& future : futures) {
        n_success += future.get();
    }
    LogPrintf("UDP: Multicast Tx %lu-%lu - Successfully restored %lu blocks\n",
              tx_idx.first, tx_idx.second, n_success);
}

static void AdvanceBlockIndex(const CBlockIndex*& pindex, int backfill_depth)
{
    LOCK(cs_main);
    int height = pindex->nHeight + 1;
    const int chain_height = g_node_context->chainman->ActiveHeight();

    if ((height < chain_height - backfill_depth + 1) && (backfill_depth > 0))
        height = chain_height - backfill_depth + 1;
    else if (height > chain_height) {
        if (backfill_depth == 0)
            height = 0;
        else
            height = chain_height - backfill_depth + 1;
    }

    pindex = g_node_context->chainman->ActiveChain()[height];
}

static void MulticastBackfillThread(const CService& mcastNode,
                                    const UDPMulticastInfo* info)
{

    const node::BlockManager& blockman = g_node_context->chainman->ActiveChainstate().m_blockman;

    /* Start only after the initial sync */
    while (g_node_context->chainman->ActiveChainstate().m_chainman.IsInitialBlockDownload() && !send_messages_break)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (send_messages_break) return;

    /* Define the initial block height */
    const int backfill_depth = info->depth;
    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = g_node_context->chainman->ActiveTip();
        assert(pindex);

        const int chain_height = g_node_context->chainman->ActiveHeight();
        LogDebug(BCLog::UDPMCAST, "UDP: Multicast Tx %lu-%lu - chain height: %d\n",
                 info->physical_idx, info->logical_idx, chain_height);

        /* The starting block height is the bottom height of the backfill window
         * plus a configurable offset */
        int height;
        if (backfill_depth == 0)
            height = info->offset % (chain_height + 1);
        else
            height = chain_height - backfill_depth + 1 + (info->offset % backfill_depth);

        LogDebug(BCLog::UDPMCAST, "UDP: Multicast Tx %lu-%lu - starting height: %d\n",
                 info->physical_idx, info->logical_idx, height);
        pindex = g_node_context->chainman->ActiveChain()[height];
        assert(pindex->nHeight == height);
    }

    /* Tx Queue */
    auto it = mapTxQueues.find(info->group);
    assert(it != mapTxQueues.end());
    PerGroupMessageQueue& queue = it->second;

    /* Block transmission window */
    const auto tx_idx_pair = std::make_pair(info->physical_idx, info->logical_idx);
    std::unique_lock<std::mutex> window_map_lock(block_window_map_mutex);
    const auto res = block_window_map.insert(
        std::make_pair(tx_idx_pair, std::make_shared<BackfillBlockWindow>(tx_idx_pair, info->save_tx_state)));
    window_map_lock.unlock();
    if (!res.second)
        throw std::runtime_error("Couldn't add new block window");
    const auto pblock_window = res.first->second;

    /* Recover the state left from the previous session */
    if (info->save_tx_state) {
        UdpMulticastTxDb mcast_tx_db(tx_idx_pair);
        const auto height_idx_map = mcast_tx_db.GetBlockProgressMap();
        AddBlocksFromProgressMap(pblock_window.get(), height_idx_map, tx_idx_pair, info->overhead_rep_blks);

        // If the previous session did not terminate gracefully, some restored
        // blocks can be in fully transmitted state but not yet removed from the
        // Tx window. Clean up those blocks now.
        pblock_window->Cleanup();

        // Override the starting CBlockIndex so that the main loop continues
        // from the block following the highest recovered height
        if (height_idx_map.size() > 0) {
            LOCK(cs_main);
            const auto last_height_idx_it = height_idx_map.rbegin();
            pindex = g_node_context->chainman->ActiveChain()[last_height_idx_it->first];
            AdvanceBlockIndex(pindex, backfill_depth);
        }
    }

    /* Main loop */
    while (!send_messages_break) {
        /* Fill blocks within the FEC chunk interleaving window */
        while ((pblock_window->Size() < info->interleave_len) && (!send_messages_break)) {
            pblock_window->Add(blockman, pindex, info->overhead_rep_blks);
            AdvanceBlockIndex(pindex, backfill_depth);
        }

        /* Send window of interleaved chunks */
        for (const auto& b : pblock_window->GetWindow()) {
            if (send_messages_break)
                break;

            const UDPMessage& msg = pblock_window->GetNextMsg(b.first, b.second);
            const unsigned int msg_len = sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH;
            SendMessage(msg, msg_len, queue, queue.buffs[3], mcastNode, multicast_checksum_magic);
        }

        /* Cleanup the blocks that have been fully transmitted */
        pblock_window->Cleanup();
    }
}

UniValue TxWindowInfoToJSON(int phy_idx, int log_idx)
{
    std::unique_lock<std::mutex> lock(block_window_map_mutex);
    if (phy_idx == -1 || log_idx == -1) {
        /* Print summarized information from all block windows */
        UniValue ret(UniValue::VOBJ);
        for (const auto& w : block_window_map) {
            const std::string key = std::to_string(w.first.first) + "-" +
                                    std::to_string(w.first.second);
            ret.pushKV(key, w.second->ShortInfoToJSON());
        }
        return ret;
    } else {
        /* Print full information from a specific block window */
        const auto tx_idx_pair = std::make_pair(phy_idx, log_idx);
        const auto it = block_window_map.find(tx_idx_pair);
        if (it == block_window_map.end()) return UniValue::VNULL;
        return it->second->FullInfoToJSON();
    }
}

static void MulticastTxnThread(const CService& mcastNode,
                               const UDPMulticastInfo* info)
{
    assert(info->txn_per_sec > 0);

    /* Start only after the initial sync */
    while (g_node_context->chainman->ActiveChainstate().m_chainman.IsInitialBlockDownload() && !send_messages_break)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (send_messages_break) return;

    /* Txn transmission stats */
    const auto tx_idx_pair = std::make_pair(info->physical_idx, info->logical_idx);
    std::unique_lock<std::mutex> window_map_lock(txn_window_map_mutex);
    auto& txn_window = txn_window_map[tx_idx_pair];
    window_map_lock.unlock();

    std::optional<CRollingBloomFilter> sent_txn_bloom;
    sent_txn_bloom.emplace(500000, 0.001); // same behavior as before

    auto it = mapTxQueues.find(info->group);
    assert(it != mapTxQueues.end());
    PerGroupMessageQueue& queue = it->second;

    /* Rate-limit the txn transmissions */
    Throttle throttle(info->txn_per_sec);
    throttle.SetMaxQuota(2 * info->txn_per_sec);

    while (!send_messages_break) {
        /* Txn transmission quota (number of txns to transmit now) */
        const uint32_t txn_tx_quota = throttle.GetQuota();

        // Sleep until we have at least one second of txns
        if (txn_tx_quota < info->txn_per_sec) {
            const uint32_t wait_ms = throttle.EstimateWait(info->txn_per_sec);
            std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
            continue;
        }

        /* Consume the quota. Not necessairly we will have this many txns to
         * send, but consume the full quota to avoid accumulation. */
        throttle.UseQuota(txn_tx_quota);

        /* Get mempool txns to send now */
        std::vector<CTransactionRef> txn_to_send;
        txn_to_send.reserve(txn_tx_quota);
        {
            std::set<uint256> txids_to_send;
            CTxMemPool& mempool = *g_node_context->mempool.get();
            LOCK(mempool.cs);
            for (const auto& iter : mempool.mapTx.get<ancestor_score>()) {
                if (txn_to_send.size() >= (unsigned int)txn_tx_quota)
                    break;
                if (txids_to_send.count(iter.GetTx().GetHash()) || sent_txn_bloom->contains(MakeUCharSpan(iter.GetTx().GetHash())))
                    continue;

                std::vector<CTransactionRef> to_add{iter.GetSharedTx()};
                while (!to_add.empty()) {
                    bool has_dep = false;
                    /* If any input of the transaction references a txn that
                     * is also in the mempool, and which has not been sent
                     * previously, then add this parent txn also to the list
                     * of txns to be sent over multicast */
                    for (const CTxIn& txin : to_add.back()->vin) {
                        CTxMemPool::txiter init = mempool.mapTx.find(txin.prevout.hash);
                        if (init != mempool.mapTx.end() && !txids_to_send.count(txin.prevout.hash) &&
                            !sent_txn_bloom->contains(MakeUCharSpan(txin.prevout.hash))) {
                            to_add.emplace_back(init->GetSharedTx());
                            has_dep = true;
                        }
                    }
                    if (!has_dep) {
                        if (txids_to_send.insert(to_add.back()->GetHash()).second) {
                            sent_txn_bloom->insert(MakeUCharSpan(to_add.back()->GetHash()));
                            txn_to_send.emplace_back(std::move(to_add.back()));
                        }
                        to_add.pop_back();
                    }
                }
            }
        }
        for (const CTransactionRef& tx : txn_to_send) {
            if (send_messages_break)
                break;

            std::vector<std::pair<UDPMessage, size_t>> msgs;
            UDPFillMessagesFromTx(*tx, msgs);
            for (const auto& msg_info : msgs) {
                if (send_messages_break)
                    break;
                const UDPMessage& msg = msg_info.first;
                const size_t msg_size = msg_info.second;
                SendMessage(msg, msg_size, queue, queue.buffs[2], mcastNode, multicast_checksum_magic);
            }

            std::unique_lock<std::mutex> lock(txn_window.m_mutex);
            txn_window.m_tx_count++;
        }
    }
}

UniValue TxnTxInfoToJSON()
{
    std::unique_lock<std::mutex> lock(txn_window_map_mutex);
    UniValue ret(UniValue::VOBJ);
    for (auto& w : txn_window_map) {
        const std::string key = std::to_string(w.first.first) + "-" +
                                std::to_string(w.first.second);
        UniValue info(UniValue::VOBJ);
        std::unique_lock<std::mutex> lock(w.second.m_mutex);
        info.pushKV("tx_count", w.second.m_tx_count);
        ret.pushKV(key, info);
    }
    return ret;
}

std::vector<std::string> mcast_tx_thread_names;

static void LaunchMulticastBackfillThreads()
{
    for (const auto& node : mapMulticastNodes) {
        auto& info = node.second;
        if (info.tx) {
            // Thread for transmission of repeated (old) FEC-coded blocks
            if (info.send_rep_blks) {
                std::stringstream ss;
                ss << "udpblkbackfill-" << info.physical_idx << "-" << info.logical_idx;
                mcast_tx_thread_names.emplace_back(ss.str());
                mcast_tx_threads.emplace_back(&util::TraceThread,
                                              mcast_tx_thread_names.back().c_str(),
                                              std::bind(MulticastBackfillThread, std::get<0>(node.first), &info)
                                            );
            }
        }
        // Thread for transmission of mempool txns
        if (info.txn_per_sec > 0) {
            std::stringstream ss;
            ss << "udptxnbackfill-" << info.physical_idx << "-" << info.logical_idx;
            mcast_tx_thread_names.emplace_back(ss.str());
            mcast_tx_threads.emplace_back(&util::TraceThread,
                                          mcast_tx_thread_names.back().c_str(),
                                          std::bind(MulticastTxnThread, std::get<0>(node.first), &info)
                                        );
        }
    }
}

/**
 * Send a specific block chosen by height over the UDP Multicast Tx streams
 *
 * Make sure to send different FEC chunks over each stream and send each chunk
 * through the best-effort queue (second highest in priority).
 *
 * This function is used by the "txblock" RPC call.
 *
 * @note: This function does not send the requested block over all multicasttx
 * instances. Instead, it sends only over the instances enabled for relaying of
 * new blocks (i.e., with relay_new_blks=true). The typical/expected multicast
 * tx setup uses several non-relaying udpmulticasttx instances (typically the
 * block repetition loops) and only one relaying instance for a given network
 * interface. The rationale if that this configuration avoids repeating new
 * blocks over multiple multicast tx instances that are going to the same
 * interface. Likewise, here, to avoid repeating the requested block over
 * multiple streams going to the same interface, send only though the
 * udpmulticasttx instances with relay_new_blks=true.
 */
void MulticastTxBlock(const int height, codec_version_t codec_version)
{
    const node::BlockManager& blockman = g_node_context->chainman->ActiveChainstate().m_blockman;

    const CBlockIndex* pindex;
    {
        LOCK(cs_main);
        pindex = g_node_context->chainman->ActiveChain()[height];
        assert(pindex->nHeight == height);
    }

    CBlock block;
    assert(blockman.ReadBlock(block, *pindex));

    for (const auto& node : multicast_nodes()) {
        // Send over the multicasttx instances enabled for block relaying
        if (!node.second.tx || !node.second.relay_new_blks)
            continue;

        LogPrintf("MulticastTxBlock: sending block %s over Tx %lu-%lu\n",
                  block.GetHash().ToString(), node.second.physical_idx, node.second.logical_idx);

        // Each node gets a different set of FEC chunks
        std::vector<UDPMessage> msgs;
        /* UDPFillMessagesFromBlock(block, msgs, pindex->nHeight,
                                 node.second.overhead_rep_blks, codec_version); */

        for (const auto& msg : msgs) {
            SendMessage(
                msg,
                sizeof(UDPMessageHeader) + sizeof(UDPFecMessage),
                false /* low priority */,
                std::get<0>(node.first),
                multicast_checksum_magic,
                node.second.group);
        }
    }
}

static std::map<size_t, PerGroupMessageQueue> InitTxQueues(const std::vector<std::pair<unsigned short, uint64_t>>& group_list,
                                                           const std::vector<UDPMulticastInfo>& multicast_list)
{
    std::map<size_t, PerGroupMessageQueue> mapQueues; // map group number to group queue

    /* Each unicast UDP group has one queue, defined in order */
    for (size_t group = 0; group < group_list.size(); group++) {
        auto res = mapQueues.emplace(std::piecewise_construct,
                                     std::forward_as_tuple(group),
                                     std::forward_as_tuple());
        LogPrintf("UDP: Set bw for group %zu: %d Mbps\n", group, group_list[group].second);
        assert(res.second);
        res.first->second.bw = group_list[group].second; // in Mbps
        res.first->second.multicast = false;
        res.first->second.unlimited = false; // rate-limit internally
        // Set the throttling rate in bytes per sec
        const double bytes_per_sec = static_cast<double>(group_list[group].second) * 1e6 / 8;
        res.first->second.ratelimiter.SetRate(bytes_per_sec);
        res.first->second.ratelimiter.SetMaxQuota(2 * bytes_per_sec);
    }

    /* Multicast Rx instances don't have any Tx queue. Only multicast Tx
     * instances do. */
    for (const auto& info : multicast_list) {
        if (info.tx) {
            LogPrintf("UDP: Set bw for group %zu: %d bps\n", info.group, info.bw);
            auto res = mapQueues.emplace(std::piecewise_construct,
                                         std::forward_as_tuple(info.group),
                                         std::forward_as_tuple(info.ringbuff_depth,
                                                               info.lossy_exit));
            assert(res.second);
            res.first->second.bw = info.bw; // in bps
            res.first->second.multicast = true;

            /* The multicast group can be rate-limited internally or externally
             * (via a blocking socket). When the BW parameter is set to 0, let
             * it be externally throttled. Otherwise, throttle internally. */
            if (info.bw == 0) {
                res.first->second.unlimited = true;
            } else {
                res.first->second.unlimited = false;
                const double bytes_per_sec = static_cast<double>(info.bw) / 8;
                res.first->second.ratelimiter.SetRate(bytes_per_sec);
                res.first->second.ratelimiter.SetMaxQuota(2 * bytes_per_sec);
            }
        }
    }

    return mapQueues;
}

static void send_messages_flush_and_break()
{
    send_messages_break = true;
    non_empty_queues_cv.notify_all();
    for (auto& q : mapTxQueues) {
        for (unsigned int i = 0; i < q.second.buffs.size(); i++) {
            q.second.buffs[i].AbortWrite();
        }
    }
}

/* Parse option read from udpmulticasttx configuration file */
static bool ParseUDPMulticastTxOpt(UDPMulticastInfo& info,
                                   const std::string& opt,
                                   const std::string& value)
{
    std::string error;
    if (opt == "ifname") {
        strncpy_wrapper(info.ifname, value.c_str(), IFNAMSIZ);
    } else if (opt == "dest_addr") {
        uint16_t port;
        std::string ip;
        SplitHostPort(value, port, ip);
        if (port == 0) {
            error = "invalid port";
        } else {
            strncpy_wrapper(info.mcast_ip, ip.c_str(), INET_ADDRSTRLEN);
            info.port = port;
        }
    } else if (opt == "bw") {
        info.bw = LocaleIndependentAtoi<uint64_t>(value);
    } else if (opt == "txn_per_sec") {
        info.txn_per_sec = LocaleIndependentAtoi<uint32_t>(value);
    } else if (opt == "ttl") {
        info.ttl = LocaleIndependentAtoi<uint8_t>(value);
    } else if (opt == "depth") {
        info.depth = LocaleIndependentAtoi<uint32_t>(value);
    } else if (opt == "offset") {
        info.offset = LocaleIndependentAtoi<uint32_t>(value);
    } else if (opt == "dscp") {
        info.dscp = LocaleIndependentAtoi<uint8_t>(value);
    } else if (opt == "interleave_len") {
        info.interleave_len = LocaleIndependentAtoi<uint32_t>(value);
    } else if (opt == "send_rep_blks") {
        info.send_rep_blks = (value == "true" || value == "1");
    } else if (opt == "relay_new_blks") {
        info.relay_new_blks = (value == "true" || value == "1");
    } else if (opt == "overhead_rep_blks") {
        const size_t pos = value.find(',');
        if (pos == std::string::npos)
            error = "overhead should be specified in \'fixed,variable\' format";
        else {
            // Assume the fixed overhead is given as an integer number, and that
            // the variable overhead is in "parts per thousand". With that,
            // avoid the locale dependent conversion provided by atof().
            info.overhead_rep_blks.fixed = LocaleIndependentAtoi<uint32_t>(value.substr(0, pos));
            info.overhead_rep_blks.variable = LocaleIndependentAtoi<uint32_t>(value.substr(pos + 1)) / 1000.0;
        }
    } else if (opt == "save_tx_state") {
        info.save_tx_state = (value == "true" || value == "1");
    } else if (opt == "ringbuff_depth") {
        info.ringbuff_depth = LocaleIndependentAtoi<uint32_t>(value);
        if (info.ringbuff_depth < MIN_BUFF_DEPTH || info.ringbuff_depth > MAX_BUFF_DEPTH)
            error = tfm::format("ringbuff_depth must be >= %d and <= %d", MIN_BUFF_DEPTH, MAX_BUFF_DEPTH);
    } else if (opt == "lossy_exit") {
        info.lossy_exit = (value == "true" || value == "1");
    } else {
        error = "unknown option";
    }

    if (!error.empty()) {
        LogPrintf("Failed to parse option %s on udpmulticasttx config: %s\n",
                  opt, error);
        return false;
    }
    return true;
}

/* Parse udpmulticasttx configuration file */
static bool ParseUDPMulticastTxInfo(const std::string& conf_file,
                                    UDPMulticastInfo& info)
{
    info.tx = true;

    /* Read configuration from file */
    std::ifstream stream(AbsPathForConfigVal(gArgs, fs::PathFromString(conf_file)));
    if (!stream.good()) {
        LogPrintf("Failed to open -udpmulticasttx config file: %s\n", conf_file);
        return false;
    }
    std::string str;
    while (getline(stream, str)) {
        const size_t pos = str.find('=');
        if (pos == std::string::npos)
            continue;

        const std::string name = str.substr(0, pos);
        const std::string value = str.substr(pos + 1);

        if (!ParseUDPMulticastTxOpt(info, name, value))
            return false;
    }

    /* Further validation */
    if (info.depth > 0 && info.offset > info.depth) {
        LogPrintf("Failed to parse -udpmulticasttx option, offset must be < depth\n");
        return false;
    }

    /* Check mandatory fields */
    if (strlen(info.ifname) == 0) {
        LogPrintf("Failed to parse -udpmulticasttx option, ifname is required\n");
        return false;
    }

    if (strlen(info.mcast_ip) == 0 || info.port == 0) {
        LogPrintf("Failed to parse -udpmulticasttx option, dest_addr is required\n");
        return false;
    }

    return true;
}

/* Parse udpmulticast configuration */
static bool ParseUDPMulticastInfo(const std::string& s, UDPMulticastInfo& info)
{
    /* Network interface */
    const size_t if_end = s.find(',');
    if (if_end == std::string::npos) {
        LogPrintf("Failed to parse -udpmulticast option, net interface not set\n");
        return false;
    }
    strncpy_wrapper(info.ifname, s.substr(0, if_end).c_str(), IFNAMSIZ);

    /* Multicast address */
    const size_t mcastaddr_end = s.find(',', if_end + 1);
    if (mcastaddr_end == std::string::npos) {
        LogPrintf("Failed to parse -udpmulticast option, missing required arguments\n");
        return false;
    }

    uint16_t port;
    std::string ip;
    const std::string mcast_ip_port = s.substr(if_end + 1, mcastaddr_end - if_end - 1);
    SplitHostPort(mcast_ip_port, port, ip);
    if (port == 0) {
        LogPrintf("Failed to parse -udpmulticast option, invalid port\n");
        return false;
    }
    info.port = port;
    strncpy_wrapper(info.mcast_ip, ip.c_str(), INET_ADDRSTRLEN);

    /* Source (Tx) IP address */
    const size_t tx_ip_end = s.find(',', mcastaddr_end + 1);
    std::string tx_ip;

    if (tx_ip_end == std::string::npos) {
        LogPrintf("Failed to parse -udpmulticast option, missing required arguments\n");
        return false;
    }

    tx_ip = s.substr(mcastaddr_end + 1, tx_ip_end - mcastaddr_end - 1);

    if (tx_ip.empty()) {
        LogPrintf("Failed to parse -udpmulticast option, source (tx) IP empty\n");
        return false;
    }
    strncpy_wrapper(info.tx_ip, tx_ip.c_str(), INET_ADDRSTRLEN);

    /* Trusted source flag and group name */
    const size_t trusted_end = s.find(',', tx_ip_end + 1);

    if (trusted_end == std::string::npos)
        info.trusted = (bool)LocaleIndependentAtoi<uint8_t>(s.substr(tx_ip_end + 1));
    else {
        info.trusted = (bool)LocaleIndependentAtoi<uint8_t>(s.substr(tx_ip_end + 1, trusted_end - tx_ip_end - 1));
        info.groupname = s.substr(trusted_end + 1);
    }

    return true;
}

static bool GetUDPMulticastInfo(std::vector<UDPMulticastInfo>& v)
{
    if (!gArgs.IsArgSet("-udpmulticast") && !gArgs.IsArgSet("-udpmulticasttx"))
        return false;

    for (const std::string& s : gArgs.GetArgs("-udpmulticast")) {
        UDPMulticastInfo info{};
        if (!ParseUDPMulticastInfo(s, info))
            return false;
        v.push_back(info);
    }

    for (const std::string& s : gArgs.GetArgs("-udpmulticasttx")) {
        UDPMulticastInfo info{};
        if (!ParseUDPMulticastTxInfo(s, info))
            return false;
        v.push_back(info);
    }

    return true;
}

static void OpenMulticastConnection(const CService& service, bool multicast_tx, size_t group, bool trusted)
{
    OpenPersistentUDPConnectionTo(service, multicast_magic, multicast_magic, trusted,
                                  multicast_tx ? UDP_CONNECTION_TYPE_OUTBOUND_ONLY : UDP_CONNECTION_TYPE_INBOUND_ONLY,
                                  group, udp_mode_t::multicast);
}

/**
 * Public API follows
 */

std::vector<std::pair<unsigned short, uint64_t>> GetUDPInboundPorts()
{
    if (!gArgs.IsArgSet("-udpport")) return std::vector<std::pair<unsigned short, uint64_t>>();

    std::map<size_t, std::pair<unsigned short, uint64_t>> res;
    for (const std::string& s : gArgs.GetArgs("-udpport")) {
        size_t port_end = s.find(',');
        size_t group_end = s.find(',', port_end + 1);
        size_t bw_end = s.find(',', group_end + 1);

        if (port_end == std::string::npos || (group_end != std::string::npos && bw_end != std::string::npos)) {
            LogPrintf("Failed to parse -udpport option, not starting Bitcoin Satellite\n");
            return std::vector<std::pair<unsigned short, uint64_t>>();
        }

        int64_t port = LocaleIndependentAtoi<int64_t>(s.substr(0, port_end));
        if (port != (unsigned short)port || port == 0) {
            LogPrintf("Failed to parse -udpport option, not starting Bitcoin Satellite\n");
            return std::vector<std::pair<unsigned short, uint64_t>>();
        }

        int64_t group = LocaleIndependentAtoi<int64_t>(s.substr(port_end + 1, group_end - port_end - 1));
        if (group < 0 || res.count(group)) {
            LogPrintf("Failed to parse -udpport option, not starting Bitcoin Satellite\n");
            return std::vector<std::pair<unsigned short, uint64_t>>();
        }

        int64_t bw = 1024;
        if (group_end != std::string::npos) {
            bw = LocaleIndependentAtoi<int64_t>(s.substr(group_end + 1));
            if (bw < 0) {
                LogPrintf("Failed to parse -udpport option, not starting Bitcoin Satellite\n");
                return std::vector<std::pair<unsigned short, uint64_t>>();
            }
        }

        res[group] = std::make_pair((unsigned short)port, uint64_t(bw));
    }

    std::vector<std::pair<unsigned short, uint64_t>> v;
    for (size_t i = 0; i < res.size(); i++) {
        if (!res.count(i)) {
            LogPrintf("Failed to parse -udpport option, not starting Bitcoin Satellite\n");
            return std::vector<std::pair<unsigned short, uint64_t>>();
        }
        v.push_back(res[i]);
    }

    return v;
}

void GetUDPConnectionList(std::vector<UDPConnectionStats>& connections_list)
{
    connections_list.clear();
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    connections_list.reserve(mapUDPNodes.size());
    for (const auto& node : mapUDPNodes) {
        if (node.second.connection.udp_mode == udp_mode_t::multicast)
            continue;
        connections_list.push_back({node.first, node.second.connection.group, node.second.connection.fTrusted, (node.second.state & STATE_GOT_SYN_ACK) ? node.second.lastRecvTime : 0, {}});
        for (size_t i = 0; i < sizeof(node.second.last_pings) / sizeof(double); i++)
            if (node.second.last_pings[i] != -1)
                connections_list.back().last_pings.push_back(node.second.last_pings[i]);
    }
}

static void OpenUDPConnectionTo(const CService& addr, const UDPConnectionInfo& info)
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    std::pair<std::map<CService, UDPConnectionState>::iterator, bool> res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    if (!res.second) {
        send_and_disconnect(res.first);
        res = mapUDPNodes.insert(std::make_pair(addr, UDPConnectionState()));
    }

    if (info.connection_type != UDP_CONNECTION_TYPE_INBOUND_ONLY)
        maybe_have_write_nodes = true;

    LogDebug(BCLog::UDPNET, "UDP: Initializing connection to %s...\n", addr.ToStringAddrPort());

    UDPConnectionState& state = res.first->second;
    state.connection = info;
    state.state = (info.udp_mode == udp_mode_t::multicast) ? STATE_INIT_COMPLETE : STATE_INIT;
    state.lastSendTime = 0;
    state.lastRecvTime = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now());;

    if (info.udp_mode == udp_mode_t::multicast) {
        for (size_t i = 0; i < sizeof(state.last_pings) / sizeof(double); i++) {
            state.last_pings[i] = 0;
        }
    }
}

void OpenUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group)
{
    OpenUDPConnectionTo(addr, {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type, udp_mode_t::unicast});
}

void OpenPersistentUDPConnectionTo(const CService& addr, uint64_t local_magic, uint64_t remote_magic, bool fUltimatelyTrusted, UDPConnectionType connection_type, size_t group, udp_mode_t udp_mode)
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);

    if (mapPersistentNodes.count(addr))
        return;
    /* NOTE: when multiple multicast services are defined on the same IP:port,
     * only one persistent node is created */

    UDPConnectionInfo info = {htole64(local_magic), htole64(remote_magic), group, fUltimatelyTrusted, connection_type, udp_mode};
    OpenUDPConnectionTo(addr, info);
    mapPersistentNodes[addr] = info;
}

void CloseUDPConnectionTo(const CService& addr)
{
    std::unique_lock<std::recursive_mutex> lock(cs_mapUDPNodes);
    auto it = mapPersistentNodes.find(addr);
    if (it != mapPersistentNodes.end())
        mapPersistentNodes.erase(it);

    auto it2 = mapUDPNodes.find(addr);
    if (it2 == mapUDPNodes.end())
        return;
    DisconnectNode(it2);
}


const std::map<std::tuple<CService, int, uint16_t>, UDPMulticastInfo>& multicast_nodes()
{
    return mapMulticastNodes;
}

bool IsMulticastRxNode(const CService& node)
{
    std::lock_guard<std::recursive_mutex> udpNodesLock(cs_mapUDPNodes);
    const auto it = mapUDPNodes.find(node);
    if (it == mapUDPNodes.end()) {
        return false;
    }

    UDPConnectionState& conn_state = it->second;
    const UDPConnectionInfo& conn_info = conn_state.connection;
    return (conn_info.udp_mode == udp_mode_t::multicast) && (conn_info.connection_type == UDP_CONNECTION_TYPE_INBOUND_ONLY);
}
