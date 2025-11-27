// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * @file test_main.cpp
 * @brief Boost.Test main entry point for libbitcoincoinselection tests
 *
 * Uses header-only Boost.Test (no library linking required).
 * BOOST_TEST_MODULE must be defined before including the header.
 */

#define BOOST_TEST_MODULE CoinSelection_Tests
#include <boost/test/included/unit_test.hpp>
