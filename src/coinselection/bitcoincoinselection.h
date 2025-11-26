// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H
#define BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H

/**
 * @file bitcoincoinselection.h
 * @brief C API for Bitcoin Core coin selection algorithms
 *
 * This header provides a C-compatible interface for external language bindings.
 * For C++ users, prefer using bitcoincoinselection_wrapper.h which provides
 * direct access to Bitcoin Core types with RAII wrappers.
 */

#ifndef __cplusplus
#include <stddef.h>
#include <stdint.h>
#else
#include <cstddef>
#include <cstdint>
#endif

#ifndef BITCOINCOINSELECTION_API
    #ifdef BITCOINCOINSELECTION_BUILD
        #if defined(_WIN32)
            #define BITCOINCOINSELECTION_API __declspec(dllexport)
        #else
            #define BITCOINCOINSELECTION_API __attribute__((visibility("default")))
        #endif
    #else
        #if defined(_WIN32) && !defined(BITCOINCOINSELECTION_STATIC)
            #define BITCOINCOINSELECTION_API __declspec(dllimport)
        #else
            #define BITCOINCOINSELECTION_API
        #endif
    #endif
#endif

#if defined(__GNUC__)
    #define BITCOINCOINSELECTION_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
    #define BITCOINCOINSELECTION_ARG_NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define BITCOINCOINSELECTION_WARN_UNUSED_RESULT
    #define BITCOINCOINSELECTION_ARG_NONNULL(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*                              Type Definitions                               */
/* ========================================================================== */

/** Bitcoin amount in satoshis (signed 64-bit) */
typedef int64_t btccs_Amount;

/** Opaque handle to a UTXO pool (vector of OutputGroups) */
typedef struct btccs_UtxoPool btccs_UtxoPool;

/** Opaque handle to a selection result */
typedef struct btccs_SelectionResult btccs_SelectionResult;

/** Opaque handle to a random context */
typedef struct btccs_RandomContext btccs_RandomContext;

/* ========================================================================== */
/*                              Enumerations                                   */
/* ========================================================================== */

typedef uint8_t btccs_SelectionStatus;
#define btccs_SelectionStatus_SUCCESS              ((btccs_SelectionStatus)0)
#define btccs_SelectionStatus_INSUFFICIENT_FUNDS   ((btccs_SelectionStatus)1)
#define btccs_SelectionStatus_MAX_WEIGHT_EXCEEDED  ((btccs_SelectionStatus)2)
#define btccs_SelectionStatus_NO_SOLUTION_FOUND    ((btccs_SelectionStatus)3)
#define btccs_SelectionStatus_INVALID_PARAMETER    ((btccs_SelectionStatus)4)
#define btccs_SelectionStatus_INTERNAL_ERROR       ((btccs_SelectionStatus)5)

typedef uint8_t btccs_SelectionAlgorithm;
#define btccs_SelectionAlgorithm_BNB         ((btccs_SelectionAlgorithm)0)
#define btccs_SelectionAlgorithm_SRD         ((btccs_SelectionAlgorithm)1)
#define btccs_SelectionAlgorithm_COINGRINDER ((btccs_SelectionAlgorithm)2)
#define btccs_SelectionAlgorithm_KNAPSACK    ((btccs_SelectionAlgorithm)3)
#define btccs_SelectionAlgorithm_MANUAL      ((btccs_SelectionAlgorithm)4)

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BITCOIN_COINSELECTION_BITCOINCOINSELECTION_H