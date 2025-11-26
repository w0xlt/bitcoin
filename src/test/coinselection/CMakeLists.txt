# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_executable(test_coinselection
  test_main.cpp
  coinselection_c_api_tests.cpp
  coinselection_wrapper_tests.cpp
)

target_link_libraries(test_coinselection
  PRIVATE
    core_interface
    bitcoincoinselection
    Boost::headers
)

add_test(NAME test_coinselection COMMAND test_coinselection)