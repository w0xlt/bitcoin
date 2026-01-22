# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

add_library(bitcoin_utreexo STATIC EXCLUDE_FROM_ALL
  utreexo.cpp
)

target_link_libraries(bitcoin_utreexo
  PRIVATE
    core_interface
    bitcoin_crypto
)
