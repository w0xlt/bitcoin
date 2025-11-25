# Copyright (c) 2024-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(GNUInstallDirs)

# libbitcoincoinselection - A library for Bitcoin coin selection algorithms
#
# This library exposes Bitcoin Core's coin selection algorithms (BnB, SRD,
# CoinGrinder, Knapsack) through both C and C++ APIs.
#
# The C++ API (bitcoincoinselection_wrapper.h) directly uses Bitcoin Core
# types (wallet::OutputGroup, wallet::SelectionResult) for zero-overhead
# integration with C++ projects.
#
# The C API (bitcoincoinselection.h) provides language-agnostic bindings
# for FFI integration with other languages.

add_library(bitcoincoinselection
  bitcoincoinselection.cpp
  # Core wallet coin selection implementation
  ../wallet/coinselection.cpp
  # Required Bitcoin Core dependencies
  ../arith_uint256.cpp
  ../hash.cpp
  ../logging.cpp
  ../policy/feerate.cpp
  ../primitives/transaction.cpp
  ../pubkey.cpp
  ../random.cpp
  ../randomenv.cpp
  ../script/script.cpp
  ../streams.cpp
  ../support/lockedpool.cpp
  ../sync.cpp
  ../uint256.cpp
  ../util/check.cpp
  ../util/fs.cpp
  ../util/fs_helpers.cpp
  ../util/hasher.cpp
  ../util/moneystr.cpp
  ../util/strencodings.cpp
  ../util/string.cpp
  ../util/syserror.cpp
  ../util/threadnames.cpp
  ../util/time.cpp
  $<TARGET_OBJECTS:bitcoin_clientversion>
  $<TARGET_OBJECTS:bitcoin_crypto>
)

target_link_libraries(bitcoincoinselection
  PRIVATE
    core_interface
    secp256k1_objs
    $<$<PLATFORM_ID:Windows>:bcrypt>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
  PUBLIC
    Boost::headers
)

target_include_directories(bitcoincoinselection
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/coinselection>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Convenience target
add_custom_target(libbitcoincoinselection)
add_dependencies(libbitcoincoinselection bitcoincoinselection)

# Library version
set_target_properties(bitcoincoinselection PROPERTIES
  VERSION 0.2.0
  SOVERSION 0
)

# Static library definition
get_target_property(bitcoincoinselection_type bitcoincoinselection TYPE)
if(bitcoincoinselection_type STREQUAL "STATIC_LIBRARY")
  target_compile_definitions(bitcoincoinselection PUBLIC BITCOINCOINSELECTION_STATIC)
endif()

# pkg-config
configure_file(
  ${PROJECT_SOURCE_DIR}/libbitcoincoinselection.pc.in
  ${PROJECT_BINARY_DIR}/libbitcoincoinselection.pc
  @ONLY
)

install(FILES ${PROJECT_BINARY_DIR}/libbitcoincoinselection.pc
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
  COMPONENT libbitcoincoinselection
)

# Install library
install(TARGETS bitcoincoinselection
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT libbitcoincoinselection
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libbitcoincoinselection
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libbitcoincoinselection
)

# Install headers
install(FILES
  bitcoincoinselection.h
  bitcoincoinselection_wrapper.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  COMPONENT libbitcoincoinselection
)
