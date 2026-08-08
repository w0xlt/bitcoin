// Copyright (c) 2021-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_TEST_UTIL_H
#define BITCOIN_WALLET_TEST_UTIL_H

#include <addresstype.h>
#include <wallet/db.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/sqlite.h>

#include <cstddef>
#include <memory>
#include <optional>

class ArgsManager;
class CChain;
class CKey;
enum class OutputType;
namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {
class CWallet;
class WalletDatabase;
struct WalletContext;

static const DatabaseFormat DATABASE_FORMATS[] = {
       DatabaseFormat::SQLITE,
};

const std::string ADDRESS_BCRT1_UNSPENDABLE = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj";

std::unique_ptr<CWallet> CreateSyncedWallet(interfaces::Chain& chain, CChain& cchain, const CKey& key);

std::shared_ptr<CWallet> TestCreateWallet(WalletContext& context);
std::shared_ptr<CWallet> TestCreateWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context, uint64_t create_flags);
std::shared_ptr<CWallet> TestLoadWallet(WalletContext& context);
std::shared_ptr<CWallet> TestLoadWallet(std::unique_ptr<WalletDatabase> database, WalletContext& context);
void TestUnloadWallet(std::shared_ptr<CWallet>&& wallet);

/** Returns a new encoded destination from the wallet (hardcoded to BECH32) */
std::string getnewaddress(CWallet& w);
/** Returns a new destination, of an specific type, from the wallet */
CTxDestination getNewDestination(CWallet& w, OutputType output_type);

using MockableData = std::map<SerializeData, SerializeData, std::less<>>;


class MockableSQLiteBatch : public SQLiteBatch
{
private:
    const bool& m_fail_writes;
    const std::optional<size_t>& m_fail_write;
    const bool& m_fail_erases;
    const bool& m_fail_commit;
    size_t& m_write_count;

public:
    MockableSQLiteBatch(SQLiteDatabase& database, const bool& fail_writes,
                        const std::optional<size_t>& fail_write, const bool& fail_erases,
                        const bool& fail_commit, size_t& write_count);
    bool WriteKey(DataStream&& key, DataStream&& value, bool overwrite = true) override;
    bool EraseKey(DataStream&& key) override;
    bool TxnCommit() override;
};

/** A WalletDatabase whose contents and return values can be modified as needed for testing
 **/
class MockableSQLiteDatabase : public InMemoryWalletDatabase
{
private:
    bool m_fail_writes{false};
    std::optional<size_t> m_fail_write;
    bool m_fail_erases{false};
    bool m_fail_commit{false};
    size_t m_write_count{0};

public:
    MockableSQLiteDatabase();

    bool Backup(const std::string& strDest) const override { return true; }

    std::string Filename() override { return "mockable"; }
    std::string Format() override { return "sqlite-mock"; }
    std::unique_ptr<DatabaseBatch> MakeBatch() override
    {
        return std::make_unique<MockableSQLiteBatch>(
            *this, m_fail_writes, m_fail_write, m_fail_erases, m_fail_commit, m_write_count);
    }

    void SetFailWrites(bool fail_writes)
    {
        m_fail_writes = fail_writes;
        m_fail_write.reset();
        m_fail_erases = false;
        m_fail_commit = false;
        m_write_count = 0;
    }
    void SetFailWrite(size_t write_number)
    {
        m_fail_writes = false;
        m_fail_write = write_number;
        m_fail_erases = false;
        m_fail_commit = false;
        m_write_count = 0;
    }
    void SetFailErases(bool fail_erases)
    {
        m_fail_writes = false;
        m_fail_write.reset();
        m_fail_erases = fail_erases;
        m_fail_commit = false;
        m_write_count = 0;
    }
    void SetFailCommit(bool fail_commit)
    {
        m_fail_writes = false;
        m_fail_write.reset();
        m_fail_erases = false;
        m_fail_commit = fail_commit;
        m_write_count = 0;
    }
};

std::unique_ptr<WalletDatabase> CreateMockableWalletDatabase();
MockableSQLiteDatabase& GetMockableDatabase(CWallet& wallet);

DescriptorScriptPubKeyMan* CreateDescriptor(CWallet& keystore, const std::string& desc_str, bool success);
} // namespace wallet

#endif // BITCOIN_WALLET_TEST_UTIL_H
