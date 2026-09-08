// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <init/common.h>
#include <logging.h>
#include <logging/timer.h>
#include <scheduler.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/string.h>

#include <array>
#include <chrono>
#include <fstream>
#include <future>
#include <ios>
#include <iostream>
#include <source_location>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

using util::SplitString;
using util::TrimString;

BOOST_FIXTURE_TEST_SUITE(logging_tests, BasicTestingSetup)

static void ResetLogger()
{
    LogInstance().SetLogLevel(BCLog::DEFAULT_LOG_LEVEL);
    LogInstance().SetCategoryLogLevel({});
}

static std::vector<std::string> ReadDebugLogLines()
{
    std::vector<std::string> lines;
    std::ifstream ifs{LogInstance().m_file_path.std_path()};
    for (std::string line; std::getline(ifs, line);) {
        lines.push_back(std::move(line));
    }
    return lines;
}

struct LogSetup : public BasicTestingSetup {
    fs::path prev_log_path;
    fs::path tmp_log_path;
    bool prev_reopen_file;
    bool prev_print_to_file;
    bool prev_log_timestamps;
    bool prev_log_threadnames;
    bool prev_log_sourcelocations;
    std::unordered_map<BCLog::LogFlags, BCLog::Level> prev_category_levels;
    BCLog::Level prev_log_level;
    BCLog::CategoryMask prev_category_mask;

    LogSetup() : prev_log_path{LogInstance().m_file_path},
                 tmp_log_path{m_args.GetDataDirBase() / "tmp_debug.log"},
                 prev_reopen_file{LogInstance().m_reopen_file},
                 prev_print_to_file{LogInstance().m_print_to_file},
                 prev_log_timestamps{LogInstance().m_log_timestamps},
                 prev_log_threadnames{LogInstance().m_log_threadnames},
                 prev_log_sourcelocations{LogInstance().m_log_sourcelocations},
                 prev_category_levels{LogInstance().CategoryLevels()},
                 prev_log_level{LogInstance().LogLevel()},
                 prev_category_mask{LogInstance().GetCategoryMask()}
    {
        LogInstance().m_file_path = tmp_log_path;
        LogInstance().m_reopen_file = true;
        LogInstance().m_print_to_file = true;
        LogInstance().m_log_timestamps = false;
        LogInstance().m_log_threadnames = false;

        // Prevent tests from failing when the line number of the logs changes.
        LogInstance().m_log_sourcelocations = false;

        LogInstance().SetLogLevel(BCLog::Level::Debug);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().SetCategoryLogLevel({});
        LogInstance().SetRateLimiting(nullptr);
    }

    ~LogSetup()
    {
        LogInstance().m_file_path = prev_log_path;
        LogInfo("Sentinel log to reopen log file");
        LogInstance().m_print_to_file = prev_print_to_file;
        LogInstance().m_reopen_file = prev_reopen_file;
        LogInstance().m_log_timestamps = prev_log_timestamps;
        LogInstance().m_log_threadnames = prev_log_threadnames;
        LogInstance().m_log_sourcelocations = prev_log_sourcelocations;
        LogInstance().SetLogLevel(prev_log_level);
        LogInstance().SetCategoryLogLevel(prev_category_levels);
        LogInstance().SetRateLimiting(nullptr);
        LogInstance().DisableCategory(BCLog::LogFlags::ALL);
        LogInstance().EnableCategory(BCLog::LogFlags{prev_category_mask});
    }
};

BOOST_AUTO_TEST_CASE(logging_timer)
{
    auto micro_timer = BCLog::Timer<std::chrono::microseconds>("tests", "end_msg");
    const std::string_view result_prefix{"tests: msg ("};
    BOOST_CHECK_EQUAL(micro_timer.LogMsg("msg").substr(0, result_prefix.size()), result_prefix);
}

static void LogTo(BCLog::Logger& logger, std::string message)
{
    logger.LogPrint({.category = BCLog::ALL, .level = BCLog::Level::Info, .should_ratelimit = false,
                     .source_loc = SourceLocation{__func__}, .message = std::move(message)});
}

BOOST_AUTO_TEST_CASE(logging_buffer_capture)
{
    BCLog::Logger logger;
    logger.m_log_timestamps = false;
    LogTo(logger, "before start");
    std::optional<BCLog::LogMessage> owned;
    {
        BCLog::LogBuffer first{logger, 100};
        BOOST_CHECK(!first.TryRead());
        BOOST_REQUIRE(logger.StartLogging());
        auto early{first.TryRead()};
        BOOST_REQUIRE(early);
        BOOST_CHECK_EQUAL(early->message, "before start\n");
        BOOST_CHECK_EQUAL(early->discarded, 0);
        BOOST_CHECK(logger.Enabled());
        {
            BCLog::LogBuffer second{logger, 100};
            BOOST_CHECK_EQUAL(logger.NumConnections(), 2);
            BOOST_CHECK(!second.TryRead());
            LogTo(logger, "captured\x01");
            // Pending messages keep their formatting even if options change before reading.
            logger.m_always_print_category_level = true;
            owned = first.TryRead();
            auto other{second.TryRead()};
            BOOST_REQUIRE(owned);
            BOOST_REQUIRE(other);
            BOOST_CHECK_EQUAL(owned->message, "captured\\x01\n");
            BOOST_CHECK_EQUAL(other->message, owned->message);
            BOOST_CHECK_EQUAL(other->discarded, 0);
            BOOST_CHECK(!first.TryRead());
            BOOST_CHECK(!second.TryRead());
        }
        BOOST_CHECK_EQUAL(logger.NumConnections(), 1);
        logger.m_always_print_category_level = false;
        LogTo(logger, "after disconnect");
        auto remaining{first.TryRead()};
        BOOST_REQUIRE(remaining);
        BOOST_CHECK_EQUAL(remaining->message, "after disconnect\n");
    }
    BOOST_CHECK_EQUAL(logger.NumConnections(), 0);
    BOOST_CHECK(!logger.Enabled());
    // Reading transfers ownership; destroying the buffer does not invalidate the message.
    BOOST_CHECK_EQUAL(owned->message, "captured\\x01\n");
}

BOOST_AUTO_TEST_CASE(logging_buffer_limits)
{
    BCLog::Logger logger;
    logger.m_log_timestamps = false;
    BCLog::LogBuffer buffer{logger, 6};
    BOOST_REQUIRE(logger.StartLogging());
    LogTo(logger, "aa");
    LogTo(logger, "bb"); // The two formatted messages exactly fill the buffer.
    LogTo(logger, "c"); // Drop the oldest message to make room.
    auto message{buffer.TryRead()};
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "bb\n");
    BOOST_CHECK_EQUAL(message->discarded, 1);

    LogTo(logger, "ddd"); // A read made room for this message.
    message = buffer.TryRead();
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "c\n");
    BOOST_CHECK_EQUAL(message->discarded, 0);
    message = buffer.TryRead();
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "ddd\n");
    BOOST_CHECK_EQUAL(message->discarded, 0);
    BOOST_CHECK(!buffer.TryRead());

    LogTo(logger, "z");
    LogTo(logger, "123456"); // Oversized messages do not evict the pending message.
    message = buffer.TryRead();
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "z\n");
    BOOST_CHECK_EQUAL(message->discarded, 1);
    BOOST_CHECK(!buffer.TryRead());

    LogTo(logger, "a");
    LogTo(logger, "b");
    LogTo(logger, "ccccc"); // Making room can discard more than one message.
    message = buffer.TryRead();
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "ccccc\n");
    BOOST_CHECK_EQUAL(message->discarded, 2);
    BOOST_CHECK(!buffer.TryRead());
}

BOOST_AUTO_TEST_CASE(logging_buffer_loss_only)
{
    BCLog::Logger logger;
    logger.m_log_timestamps = false;
    BCLog::LogBuffer zero{logger, 0};
    BCLog::LogBuffer small{logger, 1};
    BOOST_REQUIRE(logger.StartLogging());
    LogTo(logger, "oversized");
    LogTo(logger, "also oversized");
    for (auto* buffer : {&zero, &small}) {
        auto message{buffer->TryRead()};
        BOOST_REQUIRE(message);
        BOOST_CHECK(message->message.empty());
        BOOST_CHECK_EQUAL(message->discarded, 2);
        BOOST_CHECK(!buffer->TryRead());
    }
    LogTo(logger, ""); // Even an empty log entry contains its terminating newline.
    auto message{zero.TryRead()};
    BOOST_REQUIRE(message);
    BOOST_CHECK(message->message.empty());
    BOOST_CHECK_EQUAL(message->discarded, 1);
    message = small.TryRead();
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "\n");
    BOOST_CHECK_EQUAL(message->discarded, 0);
}

BOOST_AUTO_TEST_CASE(logging_buffer_wait)
{
    for (size_t capacity : {0, 100}) {
        BCLog::Logger logger;
        logger.m_log_timestamps = false;
        BCLog::LogBuffer buffer{logger, capacity};
        BOOST_REQUIRE(logger.StartLogging());
        std::promise<void> started;
        auto reader{std::async(std::launch::async, [&] {
            started.set_value();
            return buffer.Read();
        })};
        started.get_future().wait();
        const auto before{reader.wait_for(0s)};
        LogTo(logger, "wake");
        const auto after{reader.wait_for(5s)};
        buffer.Interrupt(); // Also release the reader if the wakeup failed.
        auto message{reader.get()};
        BOOST_CHECK(before == std::future_status::timeout);
        BOOST_CHECK(after == std::future_status::ready);
        BOOST_REQUIRE(message);
        BOOST_CHECK_EQUAL(message->message, capacity == 0 ? "" : "wake\n");
        BOOST_CHECK_EQUAL(message->discarded, capacity == 0 ? 1 : 0);
        BOOST_CHECK(!buffer.Read());
    }
}

BOOST_AUTO_TEST_CASE(logging_buffer_interrupt)
{
    BCLog::Logger logger;
    logger.m_log_timestamps = false;
    BCLog::LogBuffer empty{logger, 6};
    BCLog::LogBuffer queued{logger, 6};
    BCLog::LogBuffer losses{logger, 0};
    BOOST_REQUIRE(logger.StartLogging());
    empty.Interrupt(); // Interruption before reading must not be missed.
    BOOST_CHECK(!empty.Read());
    LogTo(logger, "a");
    LogTo(logger, "b");
    LogTo(logger, "ccccc");
    queued.Interrupt();
    losses.Interrupt();
    LogTo(logger, "ignored");
    auto message{queued.Read()};
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "ccccc\n");
    BOOST_CHECK_EQUAL(message->discarded, 2);
    message = losses.Read();
    BOOST_REQUIRE(message);
    BOOST_CHECK(message->message.empty());
    BOOST_CHECK_EQUAL(message->discarded, 3);
    for (auto* buffer : {&empty, &queued, &losses}) {
        buffer->Interrupt(); // Repeated interruption is harmless.
        BOOST_CHECK(!buffer->Read());
        BOOST_CHECK(!buffer->TryRead());
    }
}

BOOST_AUTO_TEST_CASE(logging_buffer_interrupt_readers)
{
    BCLog::Logger logger;
    BCLog::LogBuffer buffer{logger, 100};
    BOOST_REQUIRE(logger.StartLogging());
    std::array<std::promise<void>, 2> started;
    std::vector<std::future<std::optional<BCLog::LogMessage>>> readers;
    for (auto& promise : started) {
        readers.push_back(std::async(std::launch::async, [&buffer, &promise] {
            promise.set_value();
            return buffer.Read();
        }));
    }
    for (auto& promise : started) promise.get_future().wait();
    buffer.Interrupt();
    const auto first_status{readers[0].wait_for(5s)};
    const auto second_status{readers[1].wait_for(5s)};
    // Repeat the notification to allow cleanup if only one waiter was woken.
    buffer.Interrupt();
    auto first{readers[0].get()};
    auto second{readers[1].get()};
    BOOST_CHECK(first_status == std::future_status::ready);
    BOOST_CHECK(second_status == std::future_status::ready);
    BOOST_CHECK(!first);
    BOOST_CHECK(!second);
}

BOOST_AUTO_TEST_CASE(logging_buffer_slow_reader)
{
    BCLog::Logger logger;
    logger.m_log_timestamps = false;
    BCLog::LogBuffer buffer{logger, 100};
    BOOST_REQUIRE(logger.StartLogging());
    LogTo(logger, "first");
    std::promise<void> received;
    std::promise<void> resume;
    auto resume_future{resume.get_future()};
    auto reader{std::async(std::launch::async, [&] {
        auto message{buffer.Read()};
        received.set_value();
        resume_future.wait(); // Simulate application code that takes time to handle the message.
        return message;
    })};
    const auto read_status{received.get_future().wait_for(5s)};
    auto producer{std::async(std::launch::async, [&] {
        for (int i{0}; i < 1000; ++i) LogTo(logger, "next");
    })};
    const auto write_status{producer.wait_for(5s)};
    resume.set_value();
    buffer.Interrupt();
    producer.get();
    auto message{reader.get()};
    BOOST_CHECK(read_status == std::future_status::ready);
    BOOST_CHECK(write_status == std::future_status::ready);
    BOOST_REQUIRE(message);
    BOOST_CHECK_EQUAL(message->message, "first\n");
    size_t accounted{0};
    while ((message = buffer.Read())) {
        BOOST_CHECK_EQUAL(message->message, "next\n");
        accounted += 1 + message->discarded;
    }
    BOOST_CHECK_EQUAL(accounted, 1000);
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrint, LogSetup)
{
    LogInstance().m_log_sourcelocations = true;

    struct Case {
        std::string msg;
        BCLog::LogFlags category;
        BCLog::Level level;
        std::string prefix;
        SourceLocation loc;
    };

    std::vector<Case> cases = {
        {"foo1: bar1", BCLog::NET, BCLog::Level::Debug, "[net] ", SourceLocation{__func__}},
        {"foo2: bar2", BCLog::NET, BCLog::Level::Info, "[net:info] ", SourceLocation{__func__}},
        {"foo3: bar3", BCLog::ALL, BCLog::Level::Debug, "[debug] ", SourceLocation{__func__}},
        {"foo4: bar4", BCLog::ALL, BCLog::Level::Info, "", SourceLocation{__func__}},
        {"foo5: bar5", BCLog::NONE, BCLog::Level::Debug, "[debug] ", SourceLocation{__func__}},
        {"foo6: bar6", BCLog::NONE, BCLog::Level::Info, "", SourceLocation{__func__}},
    };

    std::vector<std::string> expected;
    for (auto& [msg, category, level, prefix, loc] : cases) {
        expected.push_back(tfm::format("[%s:%s] [%s] %s%s", util::RemovePrefix(loc.file_name(), "./"), loc.line(), loc.function_name_short(), prefix, msg));
        LogInstance().LogPrint({.category = category, .level = level, .should_ratelimit = false, .source_loc = std::move(loc), .message = msg});
    }
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros, LogSetup)
{
    LogInstance().EnableCategory(BCLog::NET);
    LogTrace(BCLog::NET, "foo6: %s", "bar6"); // not logged
    LogDebug(BCLog::NET, "foo7: %s", "bar7");
    LogInfo("foo8: %s", "bar8");
    LogWarning("foo9: %s", "bar9");
    LogError("foo10: %s", "bar10");
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    std::vector<std::string> expected = {
        "[net] foo7: bar7",
        "foo8: bar8",
        "[warning] foo9: bar9",
        "[error] foo10: bar10",
    };
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_LogPrintMacros_CategoryName, LogSetup)
{
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    const auto concatenated_category_names = LogInstance().LogCategoriesString();
    std::vector<std::pair<BCLog::LogFlags, std::string>> expected_category_names;
    const auto category_names = SplitString(concatenated_category_names, ',');
    for (const auto& category_name : category_names) {
        const auto trimmed_category_name = TrimString(category_name);
        const auto category{*Assert(BCLog::Logger::GetLogCategory(trimmed_category_name))};
        expected_category_names.emplace_back(category, trimmed_category_name);
    }

    std::vector<std::string> expected;
    for (const auto& [category, name] : expected_category_names) {
        LogDebug(category, "foo: %s\n", "bar");
        std::string expected_log = "[";
        expected_log += name;
        expected_log += "] foo: bar";
        expected.push_back(expected_log);
    }

    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_SeverityLevels, LogSetup)
{
    LogInstance().SetLogLevel(BCLog::Level::Debug);
    LogInstance().EnableCategory(BCLog::LogFlags::ALL);
    LogInstance().SetCategoryLogLevel(/*category_str=*/"net", /*level_str=*/"info");

    // Global log level
    LogInfo("info_%s", 1);
    LogTrace(BCLog::HTTP, "trace_%s. This log level is lower than the global one.", 2);
    LogDebug(BCLog::HTTP, "debug_%s", 3);
    LogWarning("warn_%s", 4);
    LogError("err_%s", 5);

    // Category-specific log level
    LogDebug(BCLog::NET, "debug_%s. This log level is the same as the global one but lower than the category-specific one, which takes precedence.", 6);

    std::vector<std::string> expected = {
        "info_1",
        "[http] debug_3",
        "[warning] warn_4",
        "[error] err_5",
    };
    std::vector<std::string> log_lines{ReadDebugLogLines()};
    BOOST_CHECK_EQUAL_COLLECTIONS(log_lines.begin(), log_lines.end(), expected.begin(), expected.end());
}

BOOST_FIXTURE_TEST_CASE(logging_Conf, LogSetup)
{
    // Set global log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-loglevel=debug"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);
    }

    // Set category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-loglevel=net:trace"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(2, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::DEFAULT_LOG_LEVEL);

        const auto& category_levels{LogInstance().CategoryLevels()};
        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_REQUIRE(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);
    }

    // Set both global log level and category-specific log level
    {
        ResetLogger();
        ArgsManager args;
        args.AddArg("-loglevel", "...", ArgsManager::ALLOW_ANY, OptionsCategory::DEBUG_TEST);
        const char* argv_test[] = {"bitcoind", "-loglevel=debug", "-loglevel=net:trace", "-loglevel=http:info"};
        std::string err;
        BOOST_REQUIRE(args.ParseParameters(4, argv_test, err));

        auto result = init::SetLoggingLevel(args);
        BOOST_REQUIRE(result);
        BOOST_CHECK_EQUAL(LogInstance().LogLevel(), BCLog::Level::Debug);

        const auto& category_levels{LogInstance().CategoryLevels()};
        BOOST_CHECK_EQUAL(category_levels.size(), 2);

        const auto net_it{category_levels.find(BCLog::LogFlags::NET)};
        BOOST_CHECK(net_it != category_levels.end());
        BOOST_CHECK_EQUAL(net_it->second, BCLog::Level::Trace);

        const auto http_it{category_levels.find(BCLog::LogFlags::HTTP)};
        BOOST_CHECK(http_it != category_levels.end());
        BOOST_CHECK_EQUAL(http_it->second, BCLog::Level::Info);
    }

    // Removed categories (like "libevent") should not store a category-specific level
    {
        ResetLogger();
        BOOST_CHECK(LogInstance().SetCategoryLogLevel(/*category_str=*/"libevent", /*level_str=*/"trace"));
        BOOST_CHECK(LogInstance().CategoryLevels().empty());
    }
}

struct ScopedScheduler {
    CScheduler scheduler{};

    ScopedScheduler()
    {
        scheduler.m_service_thread = std::thread([this] { scheduler.serviceQueue(); });
    }
    ~ScopedScheduler()
    {
        scheduler.stop();
    }
    void MockForwardAndSync(std::chrono::seconds duration)
    {
        scheduler.MockForward(duration);
        std::promise<void> promise;
        scheduler.scheduleFromNow([&promise] { promise.set_value(); }, 0ms);
        promise.get_future().wait();
    }
    std::shared_ptr<BCLog::LogRateLimiter> GetLimiter(size_t max_bytes, std::chrono::seconds window)
    {
        auto sched_func = [this](auto func, auto w) {
            scheduler.scheduleEvery(std::move(func), w);
        };
        return BCLog::LogRateLimiter::Create(sched_func, max_bytes, window);
    }
};

BOOST_AUTO_TEST_CASE(logging_log_rate_limiter)
{
    uint64_t max_bytes{1024};
    auto reset_window{1min};
    ScopedScheduler scheduler{};
    auto limiter_{scheduler.GetLimiter(max_bytes, reset_window)};
    auto& limiter{*Assert(limiter_)};

    using Status = BCLog::LogRateLimiter::Status;
    auto source_loc_1{SourceLocation{__func__}};
    auto source_loc_2{SourceLocation{__func__}};

    // A fresh limiter should not have any suppressions
    BOOST_CHECK(!limiter.SuppressionsActive());

    // Resetting an unused limiter is fine
    limiter.Reset();
    BOOST_CHECK(!limiter.SuppressionsActive());

    // No suppression should happen until more than max_bytes have been consumed
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, std::string(max_bytes - 1, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::UNSUPPRESSED);
    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, "a"), Status::STILL_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // Location 2  should not be affected by location 1's suppression
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, "a"), Status::NEWLY_SUPPRESSED);
    BOOST_CHECK(limiter.SuppressionsActive());

    // After reset_window time has passed, all suppressions should be cleared.
    scheduler.MockForwardAndSync(reset_window);

    BOOST_CHECK(!limiter.SuppressionsActive());
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_1, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
    BOOST_CHECK_EQUAL(limiter.Consume(source_loc_2, std::string(max_bytes, 'a')), Status::UNSUPPRESSED);
}

BOOST_AUTO_TEST_CASE(logging_log_limit_stats)
{
    BCLog::LogRateLimiter::Stats stats(BCLog::RATELIMIT_MAX_BYTES);

    // Check that stats gets initialized correctly.
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    const uint64_t MESSAGE_SIZE{BCLog::RATELIMIT_MAX_BYTES / 2};
    BOOST_CHECK(stats.Consume(MESSAGE_SIZE));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES - MESSAGE_SIZE);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    BOOST_CHECK(stats.Consume(MESSAGE_SIZE));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, BCLog::RATELIMIT_MAX_BYTES - MESSAGE_SIZE * 2);
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{0});

    // Consuming more bytes after already having consumed RATELIMIT_MAX_BYTES should fail.
    BOOST_CHECK(!stats.Consume(500));
    BOOST_CHECK_EQUAL(stats.m_available_bytes, uint64_t{0});
    BOOST_CHECK_EQUAL(stats.m_dropped_bytes, uint64_t{500});
}

namespace {

enum class Location {
    INFO_1,
    INFO_2,
    DEBUG_LOG,
    INFO_NOLIMIT,
};

void LogFromLocation(Location location, const std::string& message) {
    switch (location) {
    case Location::INFO_1:
        LogInfo("%s\n", message);
        return;
    case Location::INFO_2:
        LogInfo("%s\n", message);
        return;
    case Location::DEBUG_LOG:
        LogDebug(BCLog::LogFlags::HTTP, "%s\n", message);
        return;
    case Location::INFO_NOLIMIT:
        LogInfo(util::log::NO_RATE_LIMIT, "%s\n", message);
        return;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

/**
 * For a given `location` and `message`, ensure that the on-disk debug log behaviour resembles what
 * we'd expect it to be for `status` and `suppressions_active`.
 */
void TestLogFromLocation(Location location, const std::string& message,
                         BCLog::LogRateLimiter::Status status, bool suppressions_active,
                         std::source_location source = std::source_location::current())
{
    BOOST_TEST_INFO_SCOPE("TestLogFromLocation called from " << source.file_name() << ":" << source.line());
    using Status = BCLog::LogRateLimiter::Status;
    if (!suppressions_active) assert(status == Status::UNSUPPRESSED); // developer error

    std::ofstream ofs(LogInstance().m_file_path.std_path(), std::ios::out | std::ios::trunc); // clear debug log
    LogFromLocation(location, message);
    auto log_lines{ReadDebugLogLines()};
    BOOST_TEST_INFO_SCOPE(log_lines.size() << " log_lines read: \n" << util::Join(log_lines, "\n"));

    if (status == Status::STILL_SUPPRESSED) {
        BOOST_CHECK_EQUAL(log_lines.size(), 0);
        return;
    }

    if (status == Status::NEWLY_SUPPRESSED) {
        BOOST_REQUIRE_EQUAL(log_lines.size(), 2);
        BOOST_CHECK(log_lines[0].starts_with("[*] [warning] Excessive logging detected"));
        log_lines.erase(log_lines.begin());
    }
    BOOST_REQUIRE_EQUAL(log_lines.size(), 1);
    auto& payload{log_lines.back()};
    BOOST_CHECK_EQUAL(suppressions_active, payload.starts_with("[*]"));
    BOOST_CHECK(payload.ends_with(message));
}

} // namespace

BOOST_FIXTURE_TEST_CASE(logging_filesize_rate_limit, LogSetup)
{
    using Status = BCLog::LogRateLimiter::Status;
    LogInstance().m_log_timestamps = false;
    LogInstance().m_log_sourcelocations = false;
    LogInstance().m_log_threadnames = false;
    LogInstance().EnableCategory(BCLog::LogFlags::HTTP);

    constexpr int64_t line_length{1024};
    constexpr int64_t num_lines{10};
    constexpr int64_t bytes_quota{line_length * num_lines};
    constexpr auto time_window{1h};

    ScopedScheduler scheduler{};
    auto limiter{scheduler.GetLimiter(bytes_quota, time_window)};
    LogInstance().SetRateLimiting(limiter);

    const std::string log_message(line_length - 1, 'a'); // subtract one for newline

    for (int i = 0; i < num_lines; ++i) {
        TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
    }
    TestLogFromLocation(Location::INFO_1, "a", Status::NEWLY_SUPPRESSED, /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_1, "b", Status::STILL_SUPPRESSED, /*suppressions_active=*/true);
    TestLogFromLocation(Location::INFO_2, "c", Status::UNSUPPRESSED, /*suppressions_active=*/true);
    {
        scheduler.MockForwardAndSync(time_window);
        BOOST_CHECK(ReadDebugLogLines().back().starts_with("[warning] Restarting logging"));
    }
    // Check that logging from previously suppressed location is unsuppressed again.
    TestLogFromLocation(Location::INFO_1, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
    // Check that conditional logging, and unconditional logging with should_ratelimit=false is
    // not being ratelimited.
    for (Location location : {Location::DEBUG_LOG, Location::INFO_NOLIMIT}) {
        for (int i = 0; i < num_lines + 2; ++i) {
            TestLogFromLocation(location, log_message, Status::UNSUPPRESSED, /*suppressions_active=*/false);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
