#!/usr/bin/env bash
# Manual test script for wallet private broadcast feature
# This script sets up two regtest nodes to test the -privatebroadcast option
# Uses a mock SOCKS5 proxy (like the functional test) for reliable testing

set -e

# Configuration
BITCOIN_DIR="${BITCOIN_DIR:-$(pwd)}"
BITCOIND="${BITCOIND:-$BITCOIN_DIR/build/bin/bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-$BITCOIN_DIR/build/bin/bitcoin-cli}"
DATADIR_BASE="${DATADIR_BASE:-/tmp/private_broadcast_test}"
MOCK_PROXY_SCRIPT="${BITCOIN_DIR}/contrib/mock_socks5_proxy.py"

# Ports
NODE0_PORT=18444
NODE0_RPC=18443
NODE1_PORT=18544
NODE1_RPC=18543
NODE1_ONION_PORT=18545  # Port where node1 listens for "onion" connections
MOCK_SOCKS5_PORT=19150  # Mock SOCKS5 proxy port (avoid conflict with real Tor)

# PID for mock proxy
MOCK_PROXY_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

cleanup() {
    info "Cleaning up..."
    $BITCOIN_CLI -datadir="$DATADIR_BASE/node0" -rpcport=$NODE0_RPC stop 2>/dev/null || true
    $BITCOIN_CLI -datadir="$DATADIR_BASE/node1" -rpcport=$NODE1_RPC stop 2>/dev/null || true
    if [ -n "$MOCK_PROXY_PID" ]; then
        kill $MOCK_PROXY_PID 2>/dev/null || true
    fi
    sleep 2
}

trap cleanup EXIT

setup_directories() {
    info "Setting up data directories..."
    rm -rf "$DATADIR_BASE"
    mkdir -p "$DATADIR_BASE/node0"
    mkdir -p "$DATADIR_BASE/node1"
}

start_mock_socks5_proxy() {
    info "Starting mock SOCKS5 proxy on port $MOCK_SOCKS5_PORT..."
    info "  Redirecting all connections to 127.0.0.1:$NODE1_ONION_PORT"

    if [ ! -f "$MOCK_PROXY_SCRIPT" ]; then
        error "Mock proxy script not found: $MOCK_PROXY_SCRIPT"
        exit 1
    fi

    python3 "$MOCK_PROXY_SCRIPT" $MOCK_SOCKS5_PORT 127.0.0.1 $NODE1_ONION_PORT > "$DATADIR_BASE/mock_proxy.log" 2>&1 &
    MOCK_PROXY_PID=$!
    sleep 1

    # Verify it's running
    if ! kill -0 $MOCK_PROXY_PID 2>/dev/null; then
        error "Mock SOCKS5 proxy failed to start"
        cat "$DATADIR_BASE/mock_proxy.log"
        exit 1
    fi

    # Verify port is listening
    if nc -z 127.0.0.1 $MOCK_SOCKS5_PORT 2>/dev/null; then
        info "Mock SOCKS5 proxy is running"
    else
        error "Mock SOCKS5 proxy port not responding"
        exit 1
    fi
}

start_node1_receiver() {
    info "Starting Node 1 (receiver) - listening for connections..."

    cat > "$DATADIR_BASE/node1/bitcoin.conf" << EOF
# Global settings
regtest=1

[regtest]
server=1
rpcport=$NODE1_RPC
port=$NODE1_PORT
rpcuser=test
rpcpassword=test
listen=1
# Listen on a separate port that simulates the "onion" binding
# The mock SOCKS5 proxy will redirect connections here
bind=127.0.0.1:$NODE1_ONION_PORT=onion
# Don't connect to anyone automatically
connect=0
debug=net
debug=mempool
EOF

    $BITCOIND -datadir="$DATADIR_BASE/node1" -daemon
    sleep 3

    # Wait for node to be ready
    for i in {1..30}; do
        if $BITCOIN_CLI -datadir="$DATADIR_BASE/node1" -rpcport=$NODE1_RPC getblockchaininfo &>/dev/null; then
            info "Node 1 is ready"
            break
        fi
        sleep 1
    done
}

start_node0_sender() {
    info "Starting Node 0 (sender) - with -privatebroadcast enabled..."

    cat > "$DATADIR_BASE/node0/bitcoin.conf" << EOF
# Global settings
regtest=1

[regtest]
server=1
rpcport=$NODE0_RPC
port=$NODE0_PORT
rpcuser=test
rpcpassword=test
# Fallback fee for regtest (no fee estimation data available)
fallbackfee=0.0001
# Enable private broadcast - transactions go through proxy
privatebroadcast=1
# Use the mock SOCKS5 proxy (simulates Tor)
proxy=127.0.0.1:$MOCK_SOCKS5_PORT
# No Tor control needed with mock proxy
listen=0
debug=net
debug=mempool
debug=rpc
debug=privatebroadcast
EOF

    $BITCOIND -datadir="$DATADIR_BASE/node0" -daemon
    sleep 3

    # Wait for node to be ready
    for i in {1..30}; do
        if $BITCOIN_CLI -datadir="$DATADIR_BASE/node0" -rpcport=$NODE0_RPC getblockchaininfo &>/dev/null; then
            info "Node 0 is ready"
            break
        fi
        sleep 1
    done
}

cli0() {
    $BITCOIN_CLI -datadir="$DATADIR_BASE/node0" -rpcport=$NODE0_RPC "$@"
}

cli1() {
    $BITCOIN_CLI -datadir="$DATADIR_BASE/node1" -rpcport=$NODE1_RPC "$@"
}

add_fake_onion_to_node0_addrman() {
    info "Adding fake .onion addresses to Node 0's address manager..."

    # Add several fake .onion addresses - the mock proxy will redirect all of them
    # to Node 1's local port
    local addresses=(
        "testonlyad777777777777777777777777777777777777777775b6qd.onion"
        "testonlyah77777777777777777777777777777777777777777z7ayd.onion"
        "testonlyal77777777777777777777777777777777777777777vp6qd.onion"
        "testonlyap77777777777777777777777777777777777777777r5qad.onion"
        "testonlyat77777777777777777777777777777777777777777udsid.onion"
    )

    for addr in "${addresses[@]}"; do
        local result=$(cli0 addpeeraddress "$addr" 8333 true 2>/dev/null || echo '{"success":false}')
        if echo "$result" | grep -q '"success": *true'; then
            info "  Added $addr"
        fi
    done

    # Verify the addresses were added
    local addrman_count=$(cli0 getaddrmaninfo | jq '.all_networks.total')
    info "Node 0 addrman total addresses: $addrman_count"
}

create_wallet_and_fund() {
    info "Creating wallet on Node 0 and mining blocks..."

    # Create wallet
    cli0 createwallet "test_wallet"

    # Get address and mine blocks
    local address=$(cli0 -rpcwallet=test_wallet getnewaddress)
    info "Mining 101 blocks to address: $address"
    cli0 generatetoaddress 101 "$address"

    local balance=$(cli0 -rpcwallet=test_wallet getbalance)
    info "Wallet balance: $balance BTC"
}

test_private_broadcast() {
    info "=== Testing Private Broadcast ==="

    # Get destination address from Node 1
    cli1 createwallet "receiver_wallet" 2>/dev/null || true
    local dest_address=$(cli1 -rpcwallet=receiver_wallet getnewaddress)
    info "Destination address on Node 1: $dest_address"

    # Check network info
    info "Node 0 network info:"
    cli0 getnetworkinfo | jq '{version, localservices, networks: [.networks[] | {name, reachable}]}'

    info "Attempting to send 1 BTC via private broadcast..."

    if txid=$(cli0 -rpcwallet=test_wallet sendtoaddress "$dest_address" 1 2>&1); then
        info "Transaction sent successfully!"
        info "TXID: $txid"

        # CRITICAL CHECK: With private broadcast, transaction should NOT be in
        # node0's mempool immediately - it's sent directly through the proxy and
        # only enters the local mempool when it comes back via network propagation
        if cli0 getmempoolentry "$txid" &>/dev/null; then
            error "FAIL: Transaction IS in Node 0's mempool immediately"
            error "Expected: tx should skip local mempool and be broadcast privately"
            return 1
        else
            info "PASS: Transaction NOT in Node 0's mempool (expected for private broadcast)"
        fi

        # Step 1: Verify Node 0 sent the private broadcast (check debug.log)
        info ""
        info "Step 1: Verifying Node 0 sent private broadcast..."
        local max_wait=15
        local waited=0
        while [ $waited -lt $max_wait ]; do
            if grep -q "P2P handshake completed, sending INV for txid=$txid" "$DATADIR_BASE/node0/regtest/debug.log" 2>/dev/null; then
                info "PASS: Node 0 sent INV via private broadcast"
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done
        if [ $waited -ge $max_wait ]; then
            error "FAIL: Node 0 did not send private broadcast INV"
            error "Check: grep 'privatebroadcast' $DATADIR_BASE/node0/regtest/debug.log"
            return 1
        fi

        # Step 2: Verify Node 1 received the transaction in its mempool
        info ""
        info "Step 2: Waiting for Node 1 to receive the transaction..."
        max_wait=30
        waited=0
        while [ $waited -lt $max_wait ]; do
            if cli1 getmempoolentry "$txid" &>/dev/null; then
                info "PASS: Node 1 received the transaction in mempool after ${waited}s"
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done
        if [ $waited -ge $max_wait ]; then
            warn "Transaction not in Node 1's mempool after ${max_wait}s"
            # Check logs for more info
            if grep -q "$txid" "$DATADIR_BASE/node1/regtest/debug.log" 2>/dev/null; then
                info "  (Transaction was seen in Node 1's debug log)"
            fi
        fi

        # Step 3: Verify Node 0 received its tx back from the network
        info ""
        info "Step 3: Waiting for Node 0 to receive tx back from network..."
        max_wait=30
        waited=0
        while [ $waited -lt $max_wait ]; do
            if grep -q "Received our privately broadcast transaction (txid=$txid)" "$DATADIR_BASE/node0/regtest/debug.log" 2>/dev/null; then
                info "PASS: Node 0 received its transaction back from network after ${waited}s"
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done
        if [ $waited -ge $max_wait ]; then
            warn "Node 0 did not receive its tx back within ${max_wait}s"
        fi

        # Final verification: tx should now be in Node 0's mempool
        info ""
        info "Step 4: Verifying transaction is now in Node 0's mempool..."
        if cli0 getmempoolentry "$txid" &>/dev/null; then
            info "PASS: Transaction is now in Node 0's mempool (received back from network)"
        else
            warn "Transaction still not in Node 0's mempool"
        fi

        # Summary
        info ""
        info "=== Private Broadcast Verification Summary ==="
        local all_pass=true

        if grep -q "P2P handshake completed, sending INV for txid=$txid" "$DATADIR_BASE/node0/regtest/debug.log" 2>/dev/null; then
            info "1. Node 0 sent private broadcast: YES"
        else
            error "1. Node 0 sent private broadcast: NO"
            all_pass=false
        fi

        if cli1 getmempoolentry "$txid" &>/dev/null; then
            info "2. Node 1 has tx in mempool: YES"
        else
            warn "2. Node 1 has tx in mempool: NO"
            all_pass=false
        fi

        if grep -q "Received our privately broadcast transaction (txid=$txid)" "$DATADIR_BASE/node0/regtest/debug.log" 2>/dev/null; then
            info "3. Node 0 received back from network: YES"
        else
            warn "3. Node 0 received back from network: NO"
            all_pass=false
        fi

        if cli0 getmempoolentry "$txid" &>/dev/null; then
            info "4. Node 0 now has tx in mempool: YES"
        else
            warn "4. Node 0 now has tx in mempool: NO"
        fi

        info ""
        if [ "$all_pass" = true ]; then
            info "=== PRIVATE BROADCAST TEST PASSED ==="
        else
            warn "=== PRIVATE BROADCAST PARTIAL SUCCESS ==="
            warn "Core functionality (tx NOT in local mempool, sent via proxy) verified."
        fi
    else
        error "Transaction failed: $txid"
        if echo "$txid" | grep -q "Tor or I2P"; then
            error "Private broadcast requires Tor/I2P network to be reachable"
            error "The mock SOCKS5 proxy should provide this - check configuration"
        fi
        return 1
    fi
}

test_normal_broadcast() {
    info "=== Testing Normal Broadcast (for comparison) ==="

    # Restart Node 0 without -privatebroadcast
    info "Restarting Node 0 without -privatebroadcast..."
    cli0 stop
    sleep 2

    # Update config - no proxy needed for normal broadcast
    cat > "$DATADIR_BASE/node0/bitcoin.conf" << EOF
# Global settings
regtest=1

[regtest]
server=1
rpcport=$NODE0_RPC
port=$NODE0_PORT
rpcuser=test
rpcpassword=test
# Fallback fee for regtest (no fee estimation data available)
fallbackfee=0.0001
# privatebroadcast disabled
listen=1
debug=net
debug=mempool
EOF

    $BITCOIND -datadir="$DATADIR_BASE/node0" -daemon
    sleep 3

    # Wait for ready
    for i in {1..30}; do
        if cli0 getblockchaininfo &>/dev/null; then
            break
        fi
        sleep 1
    done

    # Load wallet
    cli0 loadwallet "test_wallet"

    # Connect to Node 1
    info "Connecting Node 0 to Node 1..."
    cli0 addnode "127.0.0.1:$NODE1_PORT" "onetry"

    # Wait for peer connection
    local conn_wait=0
    while [ $conn_wait -lt 10 ]; do
        local peer_count=$(cli0 getconnectioncount 2>/dev/null || echo "0")
        if [ "$peer_count" -gt 0 ]; then
            info "Connection established (peers: $peer_count)"
            break
        fi
        sleep 1
        conn_wait=$((conn_wait + 1))
    done

    # Send transaction
    local dest_address=$(cli1 -rpcwallet=receiver_wallet getnewaddress)
    info "Sending 0.5 BTC via normal broadcast..."

    if txid=$(cli0 -rpcwallet=test_wallet sendtoaddress "$dest_address" 0.5 2>&1); then
        info "Transaction sent: $txid"

        # With normal broadcast, tx SHOULD be in node0's mempool immediately
        if cli0 getmempoolentry "$txid" &>/dev/null; then
            info "PASS: Transaction IS in Node 0's mempool (expected for normal broadcast)"
        else
            warn "Transaction NOT in Node 0's mempool - unexpected for normal broadcast"
        fi

        # Wait for transaction to reach Node 1
        local max_wait=15
        local waited=0
        while [ $waited -lt $max_wait ]; do
            if cli1 getmempoolentry "$txid" &>/dev/null; then
                info "SUCCESS: Transaction received by Node 1 via normal broadcast after ${waited}s!"
                break
            fi
            sleep 1
            waited=$((waited + 1))
        done

        if [ $waited -ge $max_wait ]; then
            warn "Transaction not in Node 1's mempool after ${max_wait}s"
        fi
    else
        error "Normal broadcast failed: $txid"
    fi
}

show_help() {
    cat << EOF
Manual Test Script for Wallet Private Broadcast Feature
========================================================

This script tests the -privatebroadcast option which routes wallet transactions
through a SOCKS5 proxy (simulating Tor/I2P) instead of normal P2P broadcast.

WHAT THIS TESTS:
  1. With -privatebroadcast: Transaction is NOT added to local mempool
  2. Transaction is sent via SOCKS5 proxy to a remote node
  3. Transaction only enters local mempool when received back from network
  4. Comparison with normal broadcast behavior

HOW IT WORKS:
  - Uses a mock SOCKS5 proxy (like the functional test) for reliability
  - No real Tor installation required
  - The mock proxy redirects all connections to Node 1's local port

QUICK START:
  ./contrib/test_private_broadcast_manual.sh

ENVIRONMENT VARIABLES:
  BITCOIN_DIR   - Path to Bitcoin Core directory (default: current dir)
  BITCOIND      - Path to bitcoind binary
  BITCOIN_CLI   - Path to bitcoin-cli binary
  DATADIR_BASE  - Base directory for test data (default: /tmp/private_broadcast_test)

EOF
}

main() {
    if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
        show_help
        exit 0
    fi

    echo "=============================================="
    echo "  Private Broadcast Manual Test"
    echo "=============================================="
    echo ""

    setup_directories
    start_node1_receiver
    start_mock_socks5_proxy
    start_node0_sender
    add_fake_onion_to_node0_addrman
    create_wallet_and_fund
    test_private_broadcast
    test_normal_broadcast

    echo ""
    info "Test completed. Check the output above for results."
    info "Data directories are at: $DATADIR_BASE"
    info "Nodes will be stopped on script exit."
}

main "$@"
