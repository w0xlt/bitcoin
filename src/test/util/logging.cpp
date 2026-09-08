// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/logging.h>

#include <logging.h>
#include <noui.h>
#include <tinyformat.h>

#include <cstdlib>
#include <iostream>

DebugLogHelper::DebugLogHelper(std::string message)
    : m_message{std::move(message)}, m_buffer{LogInstance(), BCLog::DEFAULT_MAX_LOG_BUFFER}
{
    noui_test_redirect();
}

DebugLogHelper::~DebugLogHelper()
{
    noui_reconnect();
    m_buffer.Interrupt();
    if (Count() == 0) {
        tfm::format(std::cerr, "Fatal error: expected message not found in the debug log: '%s'\n", m_message);
        std::abort();
    }
}

size_t DebugLogHelper::Count()
{
    while (auto message = m_buffer.TryRead()) {
        if (message->discarded > 0) {
            tfm::format(std::cerr, "Fatal error: %d messages discarded while capturing the debug log for '%s'\n", message->discarded, m_message);
            std::abort();
        }
        if (message->message.find(m_message) != std::string::npos) ++m_count;
    }
    return m_count;
}
