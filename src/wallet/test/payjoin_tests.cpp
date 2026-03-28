// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/payjoin.h>

#include <netbase.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(wallet_payjoin_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(harden_payjoin_transport_proxy_enables_stream_isolation)
{
    const CService proxy_addr{LookupNumeric("127.0.0.1", 9050)};
    BOOST_REQUIRE(proxy_addr.IsValid());

    Proxy proxy{proxy_addr, /*tor_stream_isolation=*/false};
    const Proxy hardened{HardenPayjoinTransportProxy(proxy)};

    BOOST_CHECK(!proxy.m_tor_stream_isolation);
    BOOST_CHECK(hardened.m_tor_stream_isolation);
    BOOST_CHECK_EQUAL(hardened.ToString(), proxy.ToString());
    BOOST_CHECK_EQUAL(hardened.GetFamily(), proxy.GetFamily());
}

BOOST_AUTO_TEST_CASE(harden_payjoin_transport_proxy_preserves_unix_socket_proxy)
{
    Proxy proxy{std::string{"/tmp/payjoin-tor.sock"}, /*tor_stream_isolation=*/false};
    const Proxy hardened{HardenPayjoinTransportProxy(proxy)};

    BOOST_CHECK(proxy.m_is_unix_socket);
    BOOST_CHECK(hardened.m_is_unix_socket);
    BOOST_CHECK_EQUAL(hardened.m_unix_socket_path, proxy.m_unix_socket_path);
    BOOST_CHECK(hardened.m_tor_stream_isolation);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
