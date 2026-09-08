// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_LOGGING_H
#define BITCOIN_TEST_UTIL_LOGGING_H

#include <logging.h>
#include <util/macros.h>

#include <string>

class DebugLogHelper
{
public:
    explicit DebugLogHelper(std::string message);

    DebugLogHelper(const DebugLogHelper&) = delete;
    DebugLogHelper& operator=(const DebugLogHelper&) = delete;

    ~DebugLogHelper();

    //! Count matching messages captured so far. Fails if the capture buffer overflowed.
    size_t Count();

private:
    const std::string m_message;
    BCLog::LogBuffer m_buffer;
    size_t m_count{0};
};

#define ASSERT_DEBUG_LOG(message) DebugLogHelper BITCOIN_UNIQUE_NAME(debugloghelper)(message)

#endif // BITCOIN_TEST_UTIL_LOGGING_H
