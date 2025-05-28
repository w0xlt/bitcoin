#include "udprelay.h>

#include <validation.h>               // For CBlock, ChainstateManager, Params()
#include <validationinterface.h>      // For CValidationInterface, RegisterValidationInterface
#include <chainparams.h>              // For Params() to get CChainParams
#include <logging.h>                  // For logging (LogPrintf, LogPrint)
#include <util/threadnames.h>         // For RenameThread

#include <atomic>
#include <thread>
#include <vector>
#include <cassert>

// Platform-specific includes for sockets:
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// Constants for the UDP relay (hardcoded ports and addresses)
static const uint16_t UDP_LISTEN_PORT = 12345;               // local UDP port to bind
static const char*    UDP_PEER_ADDRESS = "127.0.0.1";        // peer IP address
static const uint16_t UDP_PEER_PORT    = 12346;              // peer UDP port

// Module-internal globals:
static std::atomic<bool> g_udp_running{false};
static std::thread g_udp_thread;
static int g_udp_socket = -1;               // UDP socket file descriptor
static sockaddr_in g_peer_sockaddr;         // sockaddr for the peer

// Forward declaration of thread procedure
static void UDPRelayThreadFunc();

// Validation interface to catch new block events (NewPoWValidBlock)
namespace {
class UDPRelayValidationInterface final : public CValidationInterface {
public:
    void NewPoWValidBlock(const CBlockIndex* pindex, const std::shared_ptr<const CBlock>& block) override {
        // On each newly validated PoW block, serialize and send it via UDP
        UDPRelay::NotifyNewBlock(pindex, block);
    }
} g_udp_validation_interface;  // static instance
} // namespace

bool UDPRelay::StartUDPRelay() {
    assert(!g_udp_running.load());
    LogPrintf("UDPRelay: Starting UDP block relay thread...\n");

    // Create UDP socket
    #ifdef _WIN32
    // On Windows, ensure Winsock is initialized (Bitcoin Core does WSAStartup in net code)
    // but if needed, one could call WSAStartup here.
    #endif
    g_udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_socket < 0) {
        LogPrintf("UDPRelay: Failed to create UDP socket\n");
        return false;
    }

    // Allow address reuse (so we don't get "address already in use" on quick restarts)
    int optval = 1;
    setsockopt(g_udp_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

    // Bind the socket to the local address (127.0.0.1:12345)
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(UDP_LISTEN_PORT);
    inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr);
    if (bind(g_udp_socket, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        LogPrintf("UDPRelay: Failed to bind UDP socket on port %u\n", UDP_LISTEN_PORT);
        #ifndef _WIN32
        close(g_udp_socket);
        #else
        closesocket(g_udp_socket);
        #endif
        g_udp_socket = -1;
        return false;
    }

    // Prepare peer address structure for sending
    g_peer_sockaddr.sin_family = AF_INET;
    g_peer_sockaddr.sin_port = htons(UDP_PEER_PORT);
    inet_pton(AF_INET, UDP_PEER_ADDRESS, &g_peer_sockaddr.sin_addr);

    // Mark as running and launch the background thread
    g_udp_running.store(true);
    g_udp_thread = std::thread(&UDPRelayThreadFunc);
    return true;
}

void UDPRelay::StopUDPRelay() {
    if (!g_udp_running.load()) return;
    LogPrintf("UDPRelay: Stopping UDP block relay thread...\n");
    // Signal thread to stop
    g_udp_running.store(false);
    // Wake up the thread if it's blocking on recv
    if (g_udp_socket >= 0) {
        sockaddr_in self_addr = g_peer_sockaddr;
        self_addr.sin_port = htons(UDP_LISTEN_PORT);  // send to our own listen port
        char dummy[1] = {0};
        sendto(g_udp_socket, dummy, sizeof(dummy), 0, (struct sockaddr*)&self_addr, sizeof(self_addr));
    }
    // Join thread
    if (g_udp_thread.joinable()) {
        g_udp_thread.join();
    }
    // Close socket
    if (g_udp_socket >= 0) {
        #ifndef _WIN32
        close(g_udp_socket);
        #else
        closesocket(g_udp_socket);
        #endif
        g_udp_socket = -1;
    }
    LogPrintf("UDPRelay: UDP relay thread stopped.\n");
}

void UDPRelay::NotifyNewBlock(const CBlockIndex* pindex, const std::shared_ptr<const CBlock>& block) {
    if (g_udp_socket < 0) return;  // not running or socket closed
    // Serialize the block into a byte stream
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *block;
    const size_t msg_size = ss.size();
    // Send the raw block bytes via UDP to the peer
    ssize_t sent = sendto(g_udp_socket, ss.data(), msg_size, 0,
                          (struct sockaddr*)&g_peer_sockaddr, sizeof(g_peer_sockaddr));
    if (sent < 0 || static_cast<size_t>(sent) != msg_size) {
        LogPrint(BCLog::NET, "UDPRelay: Failed to send block (size=%u bytes)\n", msg_size);
    } else {
        LogPrint(BCLog::NET, "UDPRelay: Sent block %s (%u bytes) over UDP\n",
                 block->GetHash().ToString(), msg_size);
    }
}

// Internal thread function: listens for incoming UDP blocks and processes them
static void UDPRelayThreadFunc() {
    RenameThread("bitcoin-udp-relay");
    const unsigned int MAX_UDP_BLOCK_SIZE = 8 * 1024 * 1024;  // 8 MB buffer for block data
    std::vector<uint8_t> buf(MAX_UDP_BLOCK_SIZE);
    sockaddr_in src_addr{};
    socklen_t src_len = sizeof(src_addr);

    // Use select() to wait for data with a timeout, allowing periodic shutdown checks
    fd_set readfds;
    struct timeval timeout;
    while (g_udp_running.load()) {
        FD_ZERO(&readfds);
        FD_SET(g_udp_socket, &readfds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        int ret = select(g_udp_socket + 1, &readfds, nullptr, nullptr, &timeout);
        if (ret < 0) {
            if (g_udp_running.load()) {
                LogPrintf("UDPRelay: select() error, errno=%d\n", errno);
            }
            break;
        }
        if (!g_udp_running.load()) break;
        if (ret == 0) {
            continue; // timeout, loop again to check g_udp_running
        }
        if (!FD_ISSET(g_udp_socket, &readfds)) {
            continue;
        }
        // Data is available to read
        ssize_t len = recvfrom(g_udp_socket, buf.data(), buf.size(), 0,
                               (struct sockaddr*)&src_addr, &src_len);
        if (len <= 0) {
            if (len < 0) {
                LogPrintf("UDPRelay: recvfrom error, errno=%d\n", errno);
            }
            continue;
        }
        // Optionally filter by known peer (since we hardcoded one peer)
        if (src_addr.sin_addr.s_addr != g_peer_sockaddr.sin_addr.s_addr ||
            src_addr.sin_port != g_peer_sockaddr.sin_port) {
            // Ignore data from unexpected sources in this simple implementation
            continue;
        }
        // Deserialize the received bytes into a CBlock object
        CBlock block;
        try {
            DataStream ds(buf);
            ds >> block;
        } catch (const std::exception& e) {
            LogPrintf("UDPRelay: Failed to deserialize received block: %s\n", e.what());
            continue;
        }
        // Hand the block to Bitcoin Core's processing (validation) logic
        BlockValidationState state;
        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>(std::move(block));
        bool newBlock = false;
        bool accepted = false;
        // Use ChainstateManager::ProcessNewBlock to validate and process the block
        #ifdef ENABLE_CHAINMAN // (pseudo-flag: assume we can access global ChainstateManager)
        accepted = g_chainman.ProcessNewBlock(Params(), pblock, /*force_processing=*/true, &newBlock, state);
        #else
        accepted = ProcessNewBlock(Params(), pblock, /*force_processing=*/true, &newBlock, state);
        #endif
        if (!accepted) {
            LogPrintf("UDPRelay: Received block processing failed: %s\n", state.ToString());
        } else {
            LogPrintf("UDPRelay: Received block %s accepted (relayed via UDP)\n", pblock->GetHash().ToString());
        }
    }
    // Exiting thread...
    g_udp_running.store(false);
}
