// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <wallet/rpc/wallet.h>

#include <coins.h>
#include <core_io.h>
#include <key_io.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <util/bip32.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>


namespace wallet {

static const std::map<uint64_t, std::string> WALLET_FLAG_CAVEATS{
    {WALLET_FLAG_AVOID_REUSE,
     "You need to rescan the blockchain in order to correctly mark used "
     "destinations in the past. Until this is done, some destinations may "
     "be considered unused, even if the opposite is the case."},
};

static RPCMethod getwalletinfo()
{
    return RPCMethod{"getwalletinfo",
                "Returns an object containing various wallet state info.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                        {RPCResult::Type::NUM, "walletversion", "(DEPRECATED) only related to unsupported legacy wallet, returns the latest version 169900 for backwards compatibility"},
                        {RPCResult::Type::STR, "format", "the database format (only sqlite)"},
                        {RPCResult::Type::NUM, "txcount", "the total number of transactions in the wallet"},
                        {RPCResult::Type::NUM, "keypoolsize", "how many new keys are pre-generated (only counts external keys)"},
                        {RPCResult::Type::NUM, "keypoolsize_hd_internal", /*optional=*/true, "how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)"},
                        {RPCResult::Type::NUM_TIME, "unlocked_until", /*optional=*/true, "the " + UNIX_EPOCH_TIME + " until which the wallet is unlocked for transfers, or 0 if the wallet is locked (only present for passphrase-encrypted wallets)"},
                        {RPCResult::Type::BOOL, "private_keys_enabled", "false if privatekeys are disabled for this wallet (enforced watch-only wallet)"},
                        {RPCResult::Type::BOOL, "avoid_reuse", "whether this wallet tracks clean/dirty coins in terms of reuse"},
                        {RPCResult::Type::OBJ, "scanning", "current scanning details, or false if no scan is in progress",
                        {
                            {RPCResult::Type::NUM, "duration", "elapsed seconds since scan start"},
                            {RPCResult::Type::NUM, "progress", "scanning progress percentage [0.0, 1.0]"},
                        }, {.skip_type_check=true}, },
                        {RPCResult::Type::BOOL, "descriptors", "whether this wallet uses descriptors for output script management"},
                        {RPCResult::Type::BOOL, "external_signer", "whether this wallet is configured to use an external signer such as a hardware wallet"},
                        {RPCResult::Type::BOOL, "blank", "Whether this wallet intentionally does not contain any keys, scripts, or descriptors"},
                        {RPCResult::Type::NUM_TIME, "birthtime", /*optional=*/true, "The start time for blocks scanning. It could be modified by (re)importing any descriptor with an earlier timestamp."},
                        {RPCResult::Type::ARR, "flags", "The flags currently set on the wallet",
                        {
                            {RPCResult::Type::STR, "flag", "The name of the flag"},
                        }},
                        RESULT_LAST_PROCESSED_BLOCK,
                    }},
                },
                RPCExamples{
                    HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK(pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    const int latest_legacy_wallet_minversion{169900};

    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.pushKV("walletname", pwallet->GetName());
    obj.pushKV("walletversion", latest_legacy_wallet_minversion);
    obj.pushKV("format", pwallet->GetDatabase().Format());
    obj.pushKV("txcount", pwallet->mapWallet.size());
    obj.pushKV("keypoolsize", kpExternalSize);
    obj.pushKV("keypoolsize_hd_internal", pwallet->GetKeyPoolSize() - kpExternalSize);

    if (pwallet->HasEncryptionKeys()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("private_keys_enabled", !pwallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    obj.pushKV("avoid_reuse", pwallet->IsWalletFlagSet(WALLET_FLAG_AVOID_REUSE));
    if (pwallet->IsScanning()) {
        UniValue scanning(UniValue::VOBJ);
        scanning.pushKV("duration", Ticks<std::chrono::seconds>(pwallet->ScanningDuration()));
        scanning.pushKV("progress", pwallet->ScanningProgress());
        obj.pushKV("scanning", std::move(scanning));
    } else {
        obj.pushKV("scanning", false);
    }
    obj.pushKV("descriptors", pwallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
    obj.pushKV("external_signer", pwallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));
    obj.pushKV("blank", pwallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    if (int64_t birthtime = pwallet->GetBirthTime(); birthtime != UNKNOWN_TIME) {
        obj.pushKV("birthtime", birthtime);
    }

    // Push known flags
    UniValue flags(UniValue::VARR);
    uint64_t wallet_flags = pwallet->GetWalletFlags();
    for (uint64_t i = 0; i < 64; ++i) {
        uint64_t flag = uint64_t{1} << i;
        if (flag & wallet_flags) {
            if (flag & KNOWN_WALLET_FLAGS) {
                flags.push_back(WALLET_FLAG_TO_STRING.at(WalletFlags{flag}));
            } else {
                flags.push_back(strprintf("unknown_flag_%u", i));
            }
        }
    }
    obj.pushKV("flags", flags);

    AppendLastProcessedBlock(obj, *pwallet);
    return obj;
},
    };
}

static RPCMethod listwalletdir()
{
    return RPCMethod{"listwalletdir",
                "Returns a list of wallets in the wallet directory.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "wallets", "",
                        {
                            {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR, "name", "The wallet name"},
                                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to loading the wallet.",
                                {
                                    {RPCResult::Type::STR, "", ""},
                                }},
                            }},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwalletdir", "")
            + HelpExampleRpc("listwalletdir", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue wallets(UniValue::VARR);
    for (const auto& [path, db_type] : ListDatabases(GetWalletDir())) {
        UniValue wallet(UniValue::VOBJ);
        wallet.pushKV("name", path.utf8string());
                UniValue warnings(UniValue::VARR);
        if (db_type == "bdb") {
            warnings.push_back("This wallet is a legacy wallet and will need to be migrated with migratewallet before it can be loaded");
        }
        wallet.pushKV("warnings", warnings);
        wallets.push_back(std::move(wallet));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("wallets", std::move(wallets));
    return result;
},
    };
}

static RPCMethod listwallets()
{
    return RPCMethod{"listwallets",
                "Returns a list of currently loaded wallets.\n"
                "For full information on the wallet, use \"getwalletinfo\"\n",
                {},
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::STR, "walletname", "the wallet name"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    UniValue obj(UniValue::VARR);

    WalletContext& context = EnsureWalletContext(request.context);
    for (const std::shared_ptr<CWallet>& wallet : GetWallets(context)) {
        LOCK(wallet->cs_wallet);
        obj.push_back(wallet->GetName());
    }

    return obj;
},
    };
}

static RPCMethod loadwallet()
{
    return RPCMethod{
        "loadwallet",
        "Loads a wallet from a wallet file or directory."
                "\nNote that all wallet command-line options used when starting bitcoind will be"
                "\napplied to the new wallet.\n",
                {
                    {"filename", RPCArg::Type::STR, RPCArg::Optional::NO, "The path to the directory of the wallet to be loaded, either absolute or relative to the \"wallets\" directory. The \"wallets\" directory is set by the -walletdir option and defaults to the \"wallets\" folder within the data directory."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "name", "The wallet name if loaded successfully."},
                        {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to loading the wallet.",
                        {
                            {RPCResult::Type::STR, "", ""},
                        }},
                    }
                },
                RPCExamples{
                    "\nLoad wallet from the wallet dir:\n"
                    + HelpExampleCli("loadwallet", "\"walletname\"")
                    + HelpExampleRpc("loadwallet", "\"walletname\"")
                    + "\nLoad wallet using absolute path (Unix):\n"
                    + HelpExampleCli("loadwallet", "\"/path/to/walletname/\"")
                    + HelpExampleRpc("loadwallet", "\"/path/to/walletname/\"")
                    + "\nLoad wallet using absolute path (Windows):\n"
                    + HelpExampleCli("loadwallet", "\"DriveLetter:\\path\\to\\walletname\\\"")
                    + HelpExampleRpc("loadwallet", "\"DriveLetter:\\path\\to\\walletname\\\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    const std::string name(request.params[0].get_str());

    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_existing = true;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    std::optional<bool> load_on_start = request.params[1].isNull() ? std::nullopt : std::optional<bool>(request.params[1].get_bool());

    {
        LOCK(context.wallets_mutex);
        if (std::any_of(context.wallets.begin(), context.wallets.end(), [&name](const auto& wallet) { return wallet->GetName() == name; })) {
            throw JSONRPCError(RPC_WALLET_ALREADY_LOADED, "Wallet \"" + name + "\" is already loaded.");
        }
    }

    std::shared_ptr<CWallet> const wallet = LoadWallet(context, name, load_on_start, options, status, error, warnings);

    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;
},
    };
}

static RPCMethod setwalletflag()
{
            std::string flags;
            for (auto& it : STRING_TO_WALLET_FLAG)
                if (it.second & MUTABLE_WALLET_FLAGS)
                    flags += (flags == "" ? "" : ", ") + it.first;

    return RPCMethod{
        "setwalletflag",
        "Change the state of the given wallet flag for a wallet.\n",
                {
                    {"flag", RPCArg::Type::STR, RPCArg::Optional::NO, "The name of the flag to change. Current available flags: " + flags},
                    {"value", RPCArg::Type::BOOL, RPCArg::Default{true}, "The new state."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "flag_name", "The name of the flag that was modified"},
                        {RPCResult::Type::BOOL, "flag_state", "The new state of the flag"},
                        {RPCResult::Type::STR, "warnings", /*optional=*/true, "Any warnings associated with the change"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("setwalletflag", "avoid_reuse")
                  + HelpExampleRpc("setwalletflag", "\"avoid_reuse\"")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return UniValue::VNULL;

    std::string flag_str = request.params[0].get_str();
    bool value = request.params[1].isNull() || request.params[1].get_bool();

    if (!STRING_TO_WALLET_FLAG.contains(flag_str)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Unknown wallet flag: %s", flag_str));
    }

    auto flag = STRING_TO_WALLET_FLAG.at(flag_str);

    if (!(flag & MUTABLE_WALLET_FLAGS)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is immutable: %s", flag_str));
    }

    UniValue res(UniValue::VOBJ);

    if (pwallet->IsWalletFlagSet(flag) == value) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Wallet flag is already set to %s: %s", value ? "true" : "false", flag_str));
    }

    res.pushKV("flag_name", flag_str);
    res.pushKV("flag_state", value);

    if (value) {
        pwallet->SetWalletFlag(flag);
    } else {
        pwallet->UnsetWalletFlag(flag);
    }

    if (flag && value && WALLET_FLAG_CAVEATS.contains(flag)) {
        res.pushKV("warnings", WALLET_FLAG_CAVEATS.at(flag));
    }

    return res;
},
    };
}

static RPCMethod createwallet()
{
    return RPCMethod{
        "createwallet",
        "Creates and loads a new wallet.\n",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::Optional::NO, "The name for the new wallet. If this is a path, the wallet will be created at the path location."},
            {"disable_private_keys", RPCArg::Type::BOOL, RPCArg::Default{false}, "Disable the possibility of private keys (only watchonlys are possible in this mode)."},
            {"blank", RPCArg::Type::BOOL, RPCArg::Default{false}, "Create a blank wallet. A blank wallet has no keys."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Encrypt the wallet with this passphrase."},
            {"avoid_reuse", RPCArg::Type::BOOL, RPCArg::Default{false}, "Keep track of coin reuse, and treat dirty and clean coins differently with privacy considerations in mind."},
            {"descriptors", RPCArg::Type::BOOL, RPCArg::Default{true}, "If set, must be \"true\""},
            {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
            {"external_signer", RPCArg::Type::BOOL, RPCArg::Default{false}, "Use an external signer such as a hardware wallet. Requires -signer to be configured. Wallet creation will fail if keys cannot be fetched. Requires disable_private_keys and descriptors set to true."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "name", "The wallet name if created successfully. If the wallet was created using a full path, the wallet_name will be the full path."},
                {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to creating and loading the wallet.",
                {
                    {RPCResult::Type::STR, "", ""},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("createwallet", "\"testwallet\"")
            + HelpExampleRpc("createwallet", "\"testwallet\"")
            + HelpExampleCliNamed("createwallet", {{"wallet_name", "descriptors"}, {"avoid_reuse", true}, {"load_on_startup", true}})
            + HelpExampleRpcNamed("createwallet", {{"wallet_name", "descriptors"}, {"avoid_reuse", true}, {"load_on_startup", true}})
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    WalletContext& context = EnsureWalletContext(request.context);
    uint64_t flags = 0;
    if (!request.params[1].isNull() && request.params[1].get_bool()) {
        flags |= WALLET_FLAG_DISABLE_PRIVATE_KEYS;
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        flags |= WALLET_FLAG_BLANK_WALLET;
    }
    SecureString passphrase;
    passphrase.reserve(100);
    std::vector<bilingual_str> warnings;
    if (!request.params[3].isNull()) {
        passphrase = std::string_view{request.params[3].get_str()};
        if (passphrase.empty()) {
            // Empty string means unencrypted
            warnings.emplace_back(Untranslated("Empty string given as passphrase, wallet will not be encrypted."));
        }
    }

    if (!request.params[4].isNull() && request.params[4].get_bool()) {
        flags |= WALLET_FLAG_AVOID_REUSE;
    }
    flags |= WALLET_FLAG_DESCRIPTORS;
    if (!self.Arg<bool>("descriptors")) {
        throw JSONRPCError(RPC_WALLET_ERROR, "descriptors argument must be set to \"true\"; it is no longer possible to create a legacy wallet.");
    }
    if (!request.params[7].isNull() && request.params[7].get_bool()) {
#ifdef ENABLE_EXTERNAL_SIGNER
        flags |= WALLET_FLAG_EXTERNAL_SIGNER;
#else
        throw JSONRPCError(RPC_WALLET_ERROR, "Compiled without external signing support (required for external signing)");
#endif
    }

    DatabaseOptions options;
    DatabaseStatus status;
    ReadDatabaseArgs(*context.args, options);
    options.require_create = true;
    options.create_flags = flags;
    options.create_passphrase = passphrase;
    bilingual_str error;
    std::optional<bool> load_on_start = request.params[6].isNull() ? std::nullopt : std::optional<bool>(request.params[6].get_bool());
    const std::shared_ptr<CWallet> wallet = CreateWallet(context, request.params[0].get_str(), load_on_start, options, status, error, warnings);
    HandleWalletError(wallet, status, error);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("name", wallet->GetName());
    PushWarnings(warnings, obj);

    return obj;
},
    };
}

static RPCMethod unloadwallet()
{
    return RPCMethod{"unloadwallet",
                "Unloads the wallet referenced by the request endpoint or the wallet_name argument.\n"
                "If both are specified, they must be identical.",
                {
                    {"wallet_name", RPCArg::Type::STR, RPCArg::DefaultHint{"the wallet name from the RPC endpoint"}, "The name of the wallet to unload. If provided both here and in the RPC endpoint, the two must be identical."},
                    {"load_on_startup", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Save wallet name to persistent settings and load on startup. True to add wallet to startup list, false to remove, null to leave unchanged."},
                },
                RPCResult{RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::ARR, "warnings", /*optional=*/true, "Warning messages, if any, related to unloading the wallet.",
                    {
                        {RPCResult::Type::STR, "", ""},
                    }},
                }},
                RPCExamples{
                    HelpExampleCli("unloadwallet", "wallet_name")
            + HelpExampleRpc("unloadwallet", "wallet_name")
                },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::string wallet_name{EnsureUniqueWalletName(request, self.MaybeArg<std::string_view>("wallet_name"))};

    WalletContext& context = EnsureWalletContext(request.context);
    std::shared_ptr<CWallet> wallet = GetWallet(context, wallet_name);
    if (!wallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }

    std::vector<bilingual_str> warnings;
    {
        WalletRescanReserver reserver(*wallet);
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
        }

        // Release the "main" shared pointer and prevent further notifications.
        // Note that any attempt to load the same wallet would fail until the wallet
        // is destroyed (see CheckUniqueFileid).
        std::optional<bool> load_on_start{self.MaybeArg<bool>("load_on_startup")};
        if (!RemoveWallet(context, wallet, load_on_start, warnings)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Requested wallet already unloaded");
        }
    }

    WaitForDeleteWallet(std::move(wallet));

    UniValue result(UniValue::VOBJ);
    PushWarnings(warnings, result);

    return result;
},
    };
}

RPCMethod simulaterawtransaction()
{
    return RPCMethod{
        "simulaterawtransaction",
        "Calculate the balance change resulting in the signing and broadcasting of the given transaction(s).\n",
        {
            {"rawtxs", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "An array of hex strings of raw transactions.\n",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "",
                {
                    {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false}, "(DEPRECATED) No longer used"},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance_change", "The wallet balance change (negative means decrease)."},
            }
        },
        RPCExamples{
            HelpExampleCli("simulaterawtransaction", "[\"myhex\"]")
            + HelpExampleRpc("simulaterawtransaction", "[\"myhex\"]")
        },
    [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
{
    const std::shared_ptr<const CWallet> rpc_wallet = GetWalletForJSONRPCRequest(request);
    if (!rpc_wallet) return UniValue::VNULL;
    const CWallet& wallet = *rpc_wallet;

    LOCK(wallet.cs_wallet);

    const auto& txs = request.params[0].get_array();
    CAmount changes{0};
    std::map<COutPoint, CAmount> new_utxos; // UTXO:s that were made available in transaction array
    std::set<COutPoint> spent;

    for (size_t i = 0; i < txs.size(); ++i) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, txs[i].get_str(), /*try_no_witness=*/ true, /*try_witness=*/ true)) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Transaction hex string decoding failure.");
        }

        // Fetch previous transactions (inputs)
        std::map<COutPoint, Coin> coins;
        for (const CTxIn& txin : mtx.vin) {
            coins[txin.prevout]; // Create empty map entry keyed by prevout.
        }
        wallet.chain().findCoins(coins);

        // Fetch debit; we are *spending* these; if the transaction is signed and
        // broadcast, we will lose everything in these
        for (const auto& txin : mtx.vin) {
            const auto& outpoint = txin.prevout;
            if (spent.contains(outpoint)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction(s) are spending the same output more than once");
            }
            if (new_utxos.contains(outpoint)) {
                changes -= new_utxos.at(outpoint);
                new_utxos.erase(outpoint);
            } else {
                if (coins.at(outpoint).IsSpent()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "One or more transaction inputs are missing or have been spent already");
                }
                changes -= wallet.GetDebit(txin);
            }
            spent.insert(outpoint);
        }

        // Iterate over outputs; we are *receiving* these, if the wallet considers
        // them "mine"; if the transaction is signed and broadcast, we will receive
        // everything in these
        // Also populate new_utxos in case these are spent in later transactions

        const auto& hash = mtx.GetHash();
        for (size_t i = 0; i < mtx.vout.size(); ++i) {
            const auto& txout = mtx.vout[i];
            bool is_mine = wallet.IsMine(txout);
            changes += new_utxos[COutPoint(hash, i)] = is_mine ? txout.nValue : 0;
        }
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("balance_change", ValueFromAmount(changes));

    return result;
}
    };
}

static RPCMethod migratewallet()
{
    return RPCMethod{
        "migratewallet",
        "Migrate the wallet to a descriptor wallet.\n"
        "A new wallet backup will need to be made.\n"
        "\nThe migration process will create a backup of the wallet before migrating. This backup\n"
        "file will be named <wallet name>-<timestamp>.legacy.bak and can be found in the directory\n"
        "for this wallet. In the event of an incorrect migration, the backup can be restored using restorewallet."
        "\nEncrypted wallets must have the passphrase provided as an argument to this call.\n"
        "\nThis RPC may take a long time to complete. Increasing the RPC client timeout is recommended.",
        {
            {"wallet_name", RPCArg::Type::STR, RPCArg::DefaultHint{"the wallet name from the RPC endpoint"}, "The name of the wallet to migrate. If provided both here and in the RPC endpoint, the two must be identical."},
            {"passphrase", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The wallet passphrase"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "wallet_name", "The name of the primary migrated wallet"},
                {RPCResult::Type::STR, "watchonly_name", /*optional=*/true, "The name of the migrated wallet containing the watchonly scripts"},
                {RPCResult::Type::STR, "solvables_name", /*optional=*/true, "The name of the migrated wallet containing solvable but not watched scripts"},
                {RPCResult::Type::STR, "backup_path", "The location of the backup of the original wallet"},
            }
        },
        RPCExamples{
            HelpExampleCli("migratewallet", "")
            + HelpExampleRpc("migratewallet", "")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::string wallet_name{EnsureUniqueWalletName(request, self.MaybeArg<std::string_view>("wallet_name"))};

            SecureString wallet_pass;
            wallet_pass.reserve(100);
            if (!request.params[1].isNull()) {
                wallet_pass = std::string_view{request.params[1].get_str()};
            }

            WalletContext& context = EnsureWalletContext(request.context);
            util::Result<MigrationResult> res = MigrateLegacyToDescriptor(wallet_name, wallet_pass, context);
            if (!res) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(res).original);
            }

            UniValue r{UniValue::VOBJ};
            r.pushKV("wallet_name", res->wallet_name);
            if (res->watchonly_wallet) {
                r.pushKV("watchonly_name", res->watchonly_wallet->GetName());
            }
            if (res->solvables_wallet) {
                r.pushKV("solvables_name", res->solvables_wallet->GetName());
            }
            r.pushKV("backup_path", res->backup_path.utf8string());

            return r;
        },
    };
}

RPCMethod gethdkeys()
{
    return RPCMethod{
        "gethdkeys",
        "List all BIP 32 HD keys in the wallet and which descriptors use them.\n",
        {
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"active_only", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show the keys for only active descriptors"},
                {"private", RPCArg::Type::BOOL, RPCArg::Default{false}, "Show private keys"}
            }},
        },
        RPCResult{RPCResult::Type::ARR, "", "", {
            {
                {RPCResult::Type::OBJ, "", "", {
                    {RPCResult::Type::STR, "xpub", "The extended public key"},
                    {RPCResult::Type::BOOL, "has_private", "Whether the wallet has the private key for this xpub"},
                    {RPCResult::Type::STR, "xprv", /*optional=*/true, "The extended private key if \"private\" is true"},
                    {RPCResult::Type::ARR, "descriptors", "Array of descriptor objects that use this HD key",
                    {
                        {RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::STR, "desc", "Descriptor string public representation"},
                            {RPCResult::Type::BOOL, "active", "Whether this descriptor is currently used to generate new addresses"},
                        }},
                    }},
                }},
            }
        }},
        RPCExamples{
            HelpExampleCli("gethdkeys", "") + HelpExampleRpc("gethdkeys", "")
            + HelpExampleCliNamed("gethdkeys", {{"active_only", "true"}, {"private", "true"}}) + HelpExampleRpcNamed("gethdkeys", {{"active_only", "true"}, {"private", "true"}})
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            const std::shared_ptr<const CWallet> wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            LOCK(wallet->cs_wallet);

            UniValue options{request.params[0].isNull() ? UniValue::VOBJ : request.params[0]};
            const bool active_only{options.exists("active_only") ? options["active_only"].get_bool() : false};
            const bool priv{options.exists("private") ? options["private"].get_bool() : false};
            if (priv) {
                EnsureWalletIsUnlocked(*wallet);
            }


            std::set<ScriptPubKeyMan*> spkms;
            if (active_only) {
                spkms = wallet->GetActiveScriptPubKeyMans();
            } else {
                spkms = wallet->GetAllScriptPubKeyMans();
            }

            std::map<CExtPubKey, std::set<std::tuple<std::string, bool, bool>>> wallet_xpubs;
            std::map<CExtPubKey, CExtKey> wallet_xprvs;
            for (auto* spkm : spkms) {
                auto* desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)};
                CHECK_NONFATAL(desc_spkm);
                LOCK(desc_spkm->cs_desc_man);
                WalletDescriptor w_desc = desc_spkm->GetWalletDescriptor();

                // Retrieve the pubkeys from the descriptor
                std::set<CPubKey> desc_pubkeys;
                std::set<CExtPubKey> desc_xpubs;
                w_desc.descriptor->GetPubKeys(desc_pubkeys, desc_xpubs);
                for (const CExtPubKey& xpub : desc_xpubs) {
                    std::string desc_str;
                    bool ok = desc_spkm->GetDescriptorString(desc_str, /*priv=*/false);
                    CHECK_NONFATAL(ok);
                    wallet_xpubs[xpub].emplace(desc_str, wallet->IsActiveScriptPubKeyMan(*spkm), desc_spkm->HasPrivKey(xpub.pubkey.GetID()));
                    if (std::optional<CKey> key = priv ? desc_spkm->GetKey(xpub.pubkey.GetID()) : std::nullopt) {
                        wallet_xprvs[xpub] = CExtKey(xpub, *key);
                    }
                }
            }

            UniValue response(UniValue::VARR);
            for (const auto& [xpub, descs] : wallet_xpubs) {
                bool has_xprv = false;
                UniValue descriptors(UniValue::VARR);
                for (const auto& [desc, active, has_priv] : descs) {
                    UniValue d(UniValue::VOBJ);
                    d.pushKV("desc", desc);
                    d.pushKV("active", active);
                    has_xprv |= has_priv;

                    descriptors.push_back(std::move(d));
                }
                UniValue xpub_info(UniValue::VOBJ);
                xpub_info.pushKV("xpub", EncodeExtPubKey(xpub));
                xpub_info.pushKV("has_private", has_xprv);
                if (priv && has_xprv) {
                    xpub_info.pushKV("xprv", EncodeExtKey(wallet_xprvs.at(xpub)));
                }
                xpub_info.pushKV("descriptors", std::move(descriptors));

                response.push_back(std::move(xpub_info));
            }

            return response;
        },
    };
}

struct DescriptorOwnershipSummary {
    bool any{false};
    bool all{false};
    bool unknown_due_to_locked_wallet{false};
};

struct WalletExtKeyInfo {
    CExtPubKey xpub;
    bool has_private{false};
    std::optional<CExtKey> xprv;
};

struct WalletKeyMatch {
    bool has_private{false};
    bool unknown_due_to_locked_wallet{false};
    std::string type{"none"};
};

static std::string KeyOriginString(const KeyOriginInfo& origin)
{
    return HexStr(origin.fingerprint) + FormatHDKeypath(origin.path);
}

static bool ExtPubKeyMatchesOriginFingerprint(const CExtPubKey& xpub, const KeyOriginInfo& origin)
{
    const CKeyID id{xpub.pubkey.GetID()};
    return std::equal(id.begin(), id.begin() + sizeof(origin.fingerprint), origin.fingerprint);
}

static std::vector<WalletExtKeyInfo> GetWalletExtKeyInfo(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    std::vector<WalletExtKeyInfo> keys;
    for (auto* spkm : wallet.GetAllScriptPubKeyMans()) {
        auto* desc_spkm{dynamic_cast<DescriptorScriptPubKeyMan*>(spkm)};
        CHECK_NONFATAL(desc_spkm);
        LOCK(desc_spkm->cs_desc_man);

        std::set<CPubKey> desc_pubkeys;
        std::set<CExtPubKey> desc_xpubs;
        desc_spkm->GetWalletDescriptor().descriptor->GetPubKeys(desc_pubkeys, desc_xpubs);
        for (const CExtPubKey& xpub : desc_xpubs) {
            WalletExtKeyInfo info;
            info.xpub = xpub;
            info.has_private = desc_spkm->HasPrivKey(xpub.pubkey.GetID());
            if (std::optional<CKey> key = desc_spkm->GetKey(xpub.pubkey.GetID())) {
                info.xprv = CExtKey{xpub, *key};
            }
            keys.push_back(std::move(info));
        }
    }
    return keys;
}

static bool ProviderHasPrivateKeyForAnalysisKey(const FlatSigningProvider& provider, const DescriptorAnalysisKey& key)
{
    if (!key.private_key_slot) return false;
    if (key.root_ext_pubkey && provider.HaveKey(key.root_ext_pubkey->pubkey.GetID())) return true;
    if (key.root_pubkey && provider.HaveKey(key.root_pubkey->GetID())) return true;
    return false;
}

static bool DeriveExtKey(const CExtKey& root, const KeyOriginInfo& origin, CExtKey& out)
{
    out = root;
    for (const auto& path_index : origin.path) {
        if (!out.Derive(out, path_index)) return false;
    }
    return true;
}

static WalletKeyMatch MatchWalletKey(const CWallet& wallet, const DescriptorAnalysisKey& key, const std::vector<WalletExtKeyInfo>& wallet_ext_keys)
{
    if (!key.private_key_slot) return {};
    if (key.root_ext_pubkey && wallet.HasPrivKey(key.root_ext_pubkey->pubkey.GetID())) return {true, false, "exact_xprv"};
    if (key.root_pubkey && wallet.HasPrivKey(key.root_pubkey->GetID())) return {true, false, "exact_private_key"};

    if (!key.origin) return {};

    bool locked_candidate{false};
    for (const auto& wallet_key : wallet_ext_keys) {
        if (!wallet_key.has_private || !ExtPubKeyMatchesOriginFingerprint(wallet_key.xpub, *key.origin)) continue;
        if (!wallet_key.xprv) {
            locked_candidate = true;
            continue;
        }

        CExtKey derived;
        if (!DeriveExtKey(*wallet_key.xprv, *key.origin, derived)) continue;
        if (key.root_ext_pubkey && derived.Neuter() == *key.root_ext_pubkey) return {true, false, "derived_xprv"};
        if (key.root_pubkey && derived.key.GetPubKey() == *key.root_pubkey) return {true, false, "derived_private_key"};
    }

    if (locked_candidate && wallet.HasEncryptionKeys() && wallet.IsLocked()) return {false, true, "unknown_locked"};
    return {};
}

static bool AddWalletPrivateKeyForAnalysisKey(const CWallet& wallet, const DescriptorAnalysisKey& key, const std::vector<WalletExtKeyInfo>& wallet_ext_keys, FlatSigningProvider& provider) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    if (!key.private_key_slot) return false;

    bool locked_candidate{false};
    if (key.root_ext_pubkey) {
        const CKeyID id{key.root_ext_pubkey->pubkey.GetID()};
        if (std::optional<CKey> wallet_key = wallet.GetKey(id)) {
            provider.keys.emplace(id, *wallet_key);
        } else if (wallet.HasPrivKey(id)) {
            locked_candidate = true;
        }
    }
    if (key.root_pubkey) {
        const CKeyID id{key.root_pubkey->GetID()};
        if (std::optional<CKey> wallet_key = wallet.GetKey(id)) {
            provider.keys.emplace(id, *wallet_key);
        } else if (wallet.HasPrivKey(id)) {
            locked_candidate = true;
        }
    }

    if (key.origin) {
        for (const auto& wallet_key : wallet_ext_keys) {
            if (!wallet_key.has_private || !ExtPubKeyMatchesOriginFingerprint(wallet_key.xpub, *key.origin)) continue;
            if (!wallet_key.xprv) {
                locked_candidate = true;
                continue;
            }

            CExtKey derived;
            if (!DeriveExtKey(*wallet_key.xprv, *key.origin, derived)) continue;
            if (key.root_ext_pubkey && derived.Neuter() == *key.root_ext_pubkey) {
                provider.keys.emplace(derived.key.GetPubKey().GetID(), derived.key);
            }
            if (key.root_pubkey && derived.key.GetPubKey() == *key.root_pubkey) {
                provider.keys.emplace(derived.key.GetPubKey().GetID(), derived.key);
            }
        }
    }

    return locked_candidate && wallet.HasEncryptionKeys() && wallet.IsLocked();
}

static bool AddWalletPrivateKeysForAnalysis(const CWallet& wallet, const DescriptorAnalysis& analysis, const std::vector<WalletExtKeyInfo>& wallet_ext_keys, FlatSigningProvider& provider) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    bool unknown_due_to_locked_wallet{false};
    for (const auto& key : analysis.keys) {
        unknown_due_to_locked_wallet |= AddWalletPrivateKeyForAnalysisKey(wallet, key, wallet_ext_keys, provider);
    }
    return unknown_due_to_locked_wallet;
}

static UniValue DescriptorAnalysisKeysToUniValue(const DescriptorAnalysis& analysis, const FlatSigningProvider& input_provider, const CWallet& wallet, const std::vector<WalletExtKeyInfo>& wallet_ext_keys, DescriptorOwnershipSummary& summary)
{
    UniValue keys{UniValue::VARR};
    summary.all = std::any_of(analysis.keys.begin(), analysis.keys.end(), [](const auto& key) { return key.private_key_slot; });

    for (const auto& key : analysis.keys) {
        const bool input_has_private{ProviderHasPrivateKeyForAnalysisKey(input_provider, key)};
        const WalletKeyMatch wallet_match{MatchWalletKey(wallet, key, wallet_ext_keys)};
        const bool wallet_has_private{wallet_match.has_private};
        if (key.private_key_slot) {
            summary.any |= wallet_has_private;
            summary.all &= wallet_has_private;
            summary.unknown_due_to_locked_wallet |= wallet_match.unknown_due_to_locked_wallet;
        }

        UniValue key_obj{UniValue::VOBJ};
        key_obj.pushKV("index", static_cast<int64_t>(key.index));
        key_obj.pushKV("type", key.type);
        key_obj.pushKV("expression", key.expression);
        key_obj.pushKV("isrange", key.is_range);
        key_obj.pushKV("isbip32", key.is_bip32);
        key_obj.pushKV("private_key_slot", key.private_key_slot);
        key_obj.pushKV("key_count", static_cast<int64_t>(key.key_count));
        key_obj.pushKV("input_has_private_key", input_has_private);
        key_obj.pushKV("wallet_has_private_key", wallet_has_private);
        key_obj.pushKV("unknown_due_to_locked_wallet", wallet_match.unknown_due_to_locked_wallet);
        key_obj.pushKV("wallet_match_type", wallet_match.type);
        UniValue children{UniValue::VARR};
        for (uint32_t child : key.children) {
            children.push_back(static_cast<int64_t>(child));
        }
        key_obj.pushKV("children", std::move(children));
        if (key.origin) {
            key_obj.pushKV("origin", KeyOriginString(*key.origin));
        }
        if (key.root_pubkey) {
            key_obj.pushKV("root_pubkey", HexStr(*key.root_pubkey));
        }
        if (key.root_ext_pubkey) {
            key_obj.pushKV("root_xpub", EncodeExtPubKey(*key.root_ext_pubkey));
        }
        keys.push_back(std::move(key_obj));
    }

    return keys;
}

static UniValue DescriptorAnalysisTreeToUniValue(const DescriptorAnalysis& analysis)
{
    UniValue tree{UniValue::VOBJ};
    tree.pushKV("root", static_cast<int64_t>(analysis.root_index));

    UniValue nodes{UniValue::VARR};
    for (const auto& node : analysis.nodes) {
        UniValue node_obj{UniValue::VOBJ};
        node_obj.pushKV("id", static_cast<int64_t>(node.id));
        node_obj.pushKV("type", node.type);
        node_obj.pushKV("expression", node.expression);
        if (node.threshold) node_obj.pushKV("threshold", *node.threshold);
        if (node.value) node_obj.pushKV("value", *node.value);
        if (node.data) node_obj.pushKV("data", *node.data);
        if (node.taproot_depth) node_obj.pushKV("taproot_depth", *node.taproot_depth);

        UniValue key_indices{UniValue::VARR};
        for (uint32_t key_index : node.key_indices) {
            key_indices.push_back(static_cast<int64_t>(key_index));
        }
        node_obj.pushKV("key_indices", std::move(key_indices));

        UniValue children{UniValue::VARR};
        for (size_t child : node.children) {
            children.push_back(static_cast<int64_t>(child));
        }
        node_obj.pushKV("children", std::move(children));
        nodes.push_back(std::move(node_obj));
    }
    tree.pushKV("nodes", std::move(nodes));
    return tree;
}

static UniValue DescriptorScriptsToUniValue(const Descriptor& desc, int range, const FlatSigningProvider& input_provider, const CWallet& wallet, const DescriptorAnalysis& analysis, const std::vector<WalletExtKeyInfo>& wallet_ext_keys, bool& unknown_due_to_locked_wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    UniValue script{UniValue::VOBJ};
    FlatSigningProvider expanded_provider;
    std::vector<CScript> script_pubkeys;
    bool used_wallet_private_keys{false};

    if (!desc.Expand(range, input_provider, script_pubkeys, expanded_provider)) {
        FlatSigningProvider wallet_provider{input_provider};
        unknown_due_to_locked_wallet = AddWalletPrivateKeysForAnalysis(wallet, analysis, wallet_ext_keys, wallet_provider);
        expanded_provider = {};
        script_pubkeys.clear();
        used_wallet_private_keys = desc.Expand(range, wallet_provider, script_pubkeys, expanded_provider);
        if (!used_wallet_private_keys) {
            script.pushKV("used_wallet_private_keys", false);
            script.pushKV("unknown_due_to_locked_wallet", unknown_due_to_locked_wallet);
            script.pushKV("error", unknown_due_to_locked_wallet ?
                "Cannot expand descriptor at the requested index. Unlock the wallet to use wallet private keys for hardened derivation." :
                "Cannot expand descriptor at the requested index. This may require private keys for hardened derivation.");
            return script;
        }
    }

    script.pushKV("used_wallet_private_keys", used_wallet_private_keys);
    script.pushKV("unknown_due_to_locked_wallet", unknown_due_to_locked_wallet);

    UniValue spks{UniValue::VARR};
    for (const auto& spk : script_pubkeys) {
        spks.push_back(HexStr(spk));
    }
    script.pushKV("scriptPubKeys", std::move(spks));

    UniValue solving_scripts{UniValue::VARR};
    for (const auto& [_, solving_script] : expanded_provider.scripts) {
        solving_scripts.push_back(HexStr(solving_script));
    }
    script.pushKV("solving_scripts", std::move(solving_scripts));
    return script;
}

static UniValue DescriptorAnalysisToUniValue(const Descriptor& desc, int range, const FlatSigningProvider& input_provider, const CWallet& wallet, const std::vector<WalletExtKeyInfo>& wallet_ext_keys, DescriptorOwnershipSummary& summary) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const DescriptorAnalysis analysis{desc.GetAnalysis()};
    UniValue obj{UniValue::VOBJ};
    obj.pushKV("descriptor", desc.ToString());
    obj.pushKV("isrange", desc.IsRange());
    obj.pushKV("issolvable", desc.IsSolvable());
    UniValue keys{DescriptorAnalysisKeysToUniValue(analysis, input_provider, wallet, wallet_ext_keys, summary)};
    obj.pushKV("wallet_has_any_private_key", summary.any);
    obj.pushKV("wallet_has_all_private_keys", summary.all);

    UniValue warnings{UniValue::VARR};
    for (const auto& warning : desc.Warnings()) {
        warnings.push_back(warning);
    }
    obj.pushKV("warnings", std::move(warnings));

    bool script_unknown_due_to_locked_wallet{false};
    UniValue script{DescriptorScriptsToUniValue(desc, range, input_provider, wallet, analysis, wallet_ext_keys, script_unknown_due_to_locked_wallet)};
    summary.unknown_due_to_locked_wallet |= script_unknown_due_to_locked_wallet;
    obj.pushKV("unknown_due_to_locked_wallet", summary.unknown_due_to_locked_wallet);
    obj.pushKV("keys", std::move(keys));
    obj.pushKV("tree", DescriptorAnalysisTreeToUniValue(analysis));
    obj.pushKV("script", std::move(script));
    return obj;
}

RPCMethod analyzedescriptor()
{
    return RPCMethod{
        "analyzedescriptor",
        "Analyze a descriptor in the context of this wallet without importing it.\n"
        "The result contains public descriptor structure, representative scripts, and whether this wallet stores private key material for descriptor key slots.\n"
        "Private key material is never returned.\n",
        {
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to analyze."},
            {"range", RPCArg::Type::NUM, RPCArg::Default{0}, "Derivation index used for ranged descriptor script preview."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "checksum", "The checksum for the input descriptor."},
                {RPCResult::Type::BOOL, "input_has_private_keys", "Whether the input descriptor contained any private keys."},
                {RPCResult::Type::BOOL, "wallet_has_any_private_key", "Whether the wallet stores private key material for at least one descriptor key slot."},
                {RPCResult::Type::BOOL, "wallet_has_all_private_keys", "Whether the wallet stores private key material for every descriptor key slot."},
                {RPCResult::Type::BOOL, "unknown_due_to_locked_wallet", "Whether the wallet is locked and some private-key status or script expansion could not be determined."},
                {RPCResult::Type::ARR, "descriptors", "Analysis for each multipath descriptor expansion.",
                {
                    {RPCResult::Type::OBJ, "", "", {
                        {RPCResult::Type::STR, "descriptor", "Canonical public descriptor."},
                        {RPCResult::Type::BOOL, "isrange", "Whether the descriptor is ranged."},
                        {RPCResult::Type::BOOL, "issolvable", "Whether the descriptor is solvable."},
                        {RPCResult::Type::BOOL, "wallet_has_any_private_key", "Whether the wallet has private key material for at least one key in this expansion."},
                        {RPCResult::Type::BOOL, "wallet_has_all_private_keys", "Whether the wallet has private key material for every key in this expansion."},
                        {RPCResult::Type::BOOL, "unknown_due_to_locked_wallet", "Whether the wallet is locked and some private-key status or script expansion could not be determined for this expansion."},
                        {RPCResult::Type::ARR, "warnings", "Descriptor warnings.", {{RPCResult::Type::STR, "", ""}}},
                        {RPCResult::Type::ARR, "keys", "Key expression analysis.", {{RPCResult::Type::OBJ, "", "", {
                            {RPCResult::Type::NUM, "index", "Descriptor key expression index."},
                            {RPCResult::Type::STR, "type", "Key expression type."},
                            {RPCResult::Type::STR, "expression", "Public key expression."},
                            {RPCResult::Type::BOOL, "isrange", "Whether this key expression is ranged."},
                            {RPCResult::Type::BOOL, "isbip32", "Whether this key expression is BIP32."},
                            {RPCResult::Type::BOOL, "private_key_slot", "Whether this key entry represents private key material that can be held by the wallet."},
                            {RPCResult::Type::NUM, "key_count", "Number of keys represented by this expression."},
                            {RPCResult::Type::BOOL, "input_has_private_key", "Whether the input descriptor provided this private key."},
                            {RPCResult::Type::BOOL, "wallet_has_private_key", "Whether the wallet stores matching private key material."},
                            {RPCResult::Type::BOOL, "unknown_due_to_locked_wallet", "Whether a locked wallet prevented determining this key's private-key status."},
                            {RPCResult::Type::STR, "wallet_match_type", "How wallet key material matched this expression."},
                            {RPCResult::Type::ARR, "children", "Nested key expression indexes, such as MuSig participants.", {{RPCResult::Type::NUM, "", ""}}},
                            {RPCResult::Type::STR, "origin", /*optional=*/true, "Key origin information, if present."},
                            {RPCResult::Type::STR_HEX, "root_pubkey", /*optional=*/true, "Root public key for non-extended key expressions."},
                            {RPCResult::Type::STR, "root_xpub", /*optional=*/true, "Root extended public key for BIP32 key expressions."},
                        }}}},
                        {RPCResult::Type::OBJ, "tree", "Descriptor node table.", {
                            {RPCResult::Type::NUM, "root", "Root node id."},
                            {RPCResult::Type::ARR, "nodes", "Descriptor nodes.", {{RPCResult::Type::OBJ, "", "", {
                                {RPCResult::Type::NUM, "id", "Node id."},
                                {RPCResult::Type::STR, "type", "Descriptor node type."},
                                {RPCResult::Type::STR, "expression", "Public descriptor expression for this node."},
                                {RPCResult::Type::NUM, "threshold", /*optional=*/true, "Multisig threshold."},
                                {RPCResult::Type::NUM, "value", /*optional=*/true, "Numeric node value, such as a miniscript threshold or timelock."},
                                {RPCResult::Type::STR_HEX, "data", /*optional=*/true, "Hex-encoded data carried by this node."},
                                {RPCResult::Type::NUM, "taproot_depth", /*optional=*/true, "Taproot leaf depth for this node."},
                                {RPCResult::Type::ARR, "key_indices", "Key expression indexes used directly by this node.", {{RPCResult::Type::NUM, "", ""}}},
                                {RPCResult::Type::ARR, "children", "Child node ids.", {{RPCResult::Type::NUM, "", ""}}},
                            }}}},
                        }},
                        {RPCResult::Type::OBJ, "script", "Representative script expansion.", {
                            {RPCResult::Type::BOOL, "used_wallet_private_keys", "Whether wallet private keys were used internally to expand the descriptor preview."},
                            {RPCResult::Type::BOOL, "unknown_due_to_locked_wallet", "Whether a locked wallet prevented script preview expansion."},
                            {RPCResult::Type::ARR, "scriptPubKeys", /*optional=*/true, "Expanded scriptPubKeys.", {{RPCResult::Type::STR_HEX, "", ""}}},
                            {RPCResult::Type::ARR, "solving_scripts", /*optional=*/true, "Redeem/witness scripts produced during expansion.", {{RPCResult::Type::STR_HEX, "", ""}}},
                            {RPCResult::Type::STR, "error", /*optional=*/true, "Expansion error."},
                        }},
                    }},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("analyzedescriptor", "\"wpkh([d34db33f/84h/0h/0h]xpub.../0/*)#checksum\" 0")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<const CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;
            if (!wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "analyzedescriptor is only available for descriptor wallets");
            }

            const std::string descriptor{request.params[0].get_str()};
            const int range{request.params.size() > 1 && !request.params[1].isNull() ? request.params[1].getInt<int>() : 0};
            if (range < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Range index must be non-negative");
            }

            FlatSigningProvider input_provider;
            std::string error;
            auto descs = Parse(descriptor, input_provider, error);
            if (descs.empty()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
            }

            UniValue response{UniValue::VOBJ};
            response.pushKV("checksum", GetDescriptorChecksum(descriptor));
            response.pushKV("input_has_private_keys", !input_provider.keys.empty());

            bool wallet_has_any_private_key{false};
            bool wallet_has_all_private_keys{true};
            bool unknown_due_to_locked_wallet{false};
            UniValue descriptor_results{UniValue::VARR};
            {
                LOCK(wallet->cs_wallet);
                const std::vector<WalletExtKeyInfo> wallet_ext_keys{GetWalletExtKeyInfo(*wallet)};
                for (const auto& desc : descs) {
                    DescriptorOwnershipSummary summary;
                    descriptor_results.push_back(DescriptorAnalysisToUniValue(*desc, range, input_provider, *wallet, wallet_ext_keys, summary));
                    wallet_has_any_private_key |= summary.any;
                    wallet_has_all_private_keys &= summary.all;
                    unknown_due_to_locked_wallet |= summary.unknown_due_to_locked_wallet;
                }
            }

            response.pushKV("wallet_has_any_private_key", wallet_has_any_private_key);
            response.pushKV("wallet_has_all_private_keys", wallet_has_all_private_keys);
            response.pushKV("unknown_due_to_locked_wallet", unknown_due_to_locked_wallet);
            response.pushKV("descriptors", std::move(descriptor_results));
            return response;
        },
    };
}

static RPCMethod createwalletdescriptor()
{
    return RPCMethod{"createwalletdescriptor",
        "Creates the wallet's descriptor for the given address type. "
        "The address type must be one that the wallet does not already have a descriptor for."
        + HELP_REQUIRING_PASSPHRASE,
        {
            {"type", RPCArg::Type::STR, RPCArg::Optional::NO, "The address type the descriptor will produce. Options are " + FormatAllOutputTypes() + "."},
            {"options", RPCArg::Type::OBJ_NAMED_PARAMS, RPCArg::Optional::OMITTED, "", {
                {"internal", RPCArg::Type::BOOL, RPCArg::DefaultHint{"Both external and internal will be generated unless this parameter is specified"}, "Whether to only make one descriptor that is internal (if parameter is true) or external (if parameter is false)"},
                {"hdkey", RPCArg::Type::STR, RPCArg::DefaultHint{"The HD key used by all other active descriptors"}, "The HD key that the wallet knows the private key of, listed using 'gethdkeys', to use for this descriptor's key"},
            }},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::ARR, "descs", "The public descriptors that were added to the wallet",
                    {{RPCResult::Type::STR, "", ""}}
                }
            },
        },
        RPCExamples{
            HelpExampleCli("createwalletdescriptor", "bech32m")
            + HelpExampleRpc("createwalletdescriptor", "bech32m")
        },
        [](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            std::optional<OutputType> output_type = ParseOutputType(request.params[0].get_str());
            if (!output_type) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[0].get_str()));
            }

            UniValue options{request.params[1].isNull() ? UniValue::VOBJ : request.params[1]};
            UniValue internal_only{options["internal"]};
            UniValue hdkey{options["hdkey"]};

            std::vector<bool> internals;
            if (internal_only.isNull()) {
                internals.push_back(false);
                internals.push_back(true);
            } else {
                internals.push_back(internal_only.get_bool());
            }

            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(*pwallet);

            CExtPubKey xpub;
            if (hdkey.isNull()) {
                std::set<CExtPubKey> active_xpubs = pwallet->GetActiveHDPubKeys();
                if (active_xpubs.size() != 1) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to determine which HD key to use from active descriptors. Please specify with 'hdkey'");
                }
                xpub = *active_xpubs.begin();
            } else {
                xpub = DecodeExtPubKey(hdkey.get_str());
                if (!xpub.pubkey.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to parse HD key. Please provide a valid xpub");
                }
            }

            std::optional<CKey> key = pwallet->GetKey(xpub.pubkey.GetID());
            if (!key) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Private key for %s is not known", EncodeExtPubKey(xpub)));
            }
            CExtKey active_hdkey(xpub, *key);

            std::vector<std::reference_wrapper<DescriptorScriptPubKeyMan>> spkms;
            WalletBatch batch{pwallet->GetDatabase()};
            for (bool internal : internals) {
                WalletDescriptor w_desc = GenerateWalletDescriptor(xpub, *output_type, internal);
                uint256 w_id = DescriptorID(*w_desc.descriptor);
                if (!pwallet->GetScriptPubKeyMan(w_id)) {
                    spkms.emplace_back(pwallet->SetupDescriptorScriptPubKeyMan(batch, active_hdkey, *output_type, internal));
                }
            }
            if (spkms.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Descriptor already exists");
            }

            // Fetch each descspkm from the wallet in order to get the descriptor strings
            UniValue descs{UniValue::VARR};
            for (const auto& spkm : spkms) {
                std::string desc_str;
                bool ok = spkm.get().GetDescriptorString(desc_str, false);
                CHECK_NONFATAL(ok);
                descs.push_back(desc_str);
            }
            UniValue out{UniValue::VOBJ};
            out.pushKV("descs", std::move(descs));
            return out;
        }
    };
}

RPCMethod addhdkey()
{
    return RPCMethod{
        "addhdkey",
        "Add a BIP 32 HD key to the wallet that can be used with 'createwalletdescriptor'\n",
        {
            {"hdkey", RPCArg::Type::STR, RPCArg::DefaultHint{"Automatically generated new key"}, "The BIP 32 extended private key to add. If none is provided, a randomly generated one will be added."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "xpub", "The xpub of the HD key that was added to the wallet"}
            },
        },
        RPCExamples{
            HelpExampleCli("addhdkey", "xprv") + HelpExampleRpc("addhdkey", "xprv")
        },
        [&](const RPCMethod& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
            if (!wallet) return UniValue::VNULL;

            if (wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "addhdkey is not available for wallets without private keys");
            }

            EnsureWalletIsUnlocked(*wallet);

            CExtKey hdkey;
            if (request.params[0].isNull()) {
                CKey seed_key = GenerateRandomKey();
                hdkey.SetSeed(seed_key);
            } else {
                hdkey = DecodeExtKey(request.params[0].get_str());
                if (!hdkey.key.IsValid()) {
                    // Check if the user gave us an xpub and give a more descriptive error if so
                    CExtPubKey xpub = DecodeExtPubKey(request.params[0].get_str());
                    if (xpub.pubkey.IsValid()) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Extended public key (xpub) provided, but extended private key (xprv) is required");
                    } else {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Could not parse HD key");
                    }
                }
            }

            LOCK(wallet->cs_wallet);
            std::string desc_str = "unused(" + EncodeExtKey(hdkey) + ")";
            FlatSigningProvider keys;
            std::string error;
            std::vector<std::unique_ptr<Descriptor>> descs = Parse(desc_str, keys, error, false);
            CHECK_NONFATAL(!descs.empty());
            WalletDescriptor w_desc(std::move(descs.at(0)), GetTime(), 0, 0, 0);
            if (wallet->GetDescriptorScriptPubKeyMan(w_desc) != nullptr) {
                throw JSONRPCError(RPC_WALLET_ERROR, "HD key already exists");
            }

            auto spkm = wallet->AddWalletDescriptor(w_desc, keys, /*label=*/"", /*internal=*/false);
            if (!spkm) {
                throw JSONRPCError(RPC_WALLET_ERROR, util::ErrorString(spkm).original);
            }

            UniValue response(UniValue::VOBJ);
            const DescriptorScriptPubKeyMan& desc_spkm = spkm->get();
            LOCK(desc_spkm.cs_desc_man);
            std::set<CPubKey> pubkeys;
            std::set<CExtPubKey> extpubs;
            desc_spkm.GetWalletDescriptor().descriptor->GetPubKeys(pubkeys, extpubs);
            CHECK_NONFATAL(pubkeys.size() == 0);
            CHECK_NONFATAL(extpubs.size() == 1);
            response.pushKV("xpub", EncodeExtPubKey(*extpubs.begin()));

            return response;
        },
    };
}

// addresses
RPCMethod getaddressinfo();
RPCMethod getnewaddress();
RPCMethod getrawchangeaddress();
RPCMethod setlabel();
RPCMethod listaddressgroupings();
RPCMethod keypoolrefill();
RPCMethod getaddressesbylabel();
RPCMethod listlabels();
#ifdef ENABLE_EXTERNAL_SIGNER
RPCMethod walletdisplayaddress();
#endif // ENABLE_EXTERNAL_SIGNER

// backup
RPCMethod importprunedfunds();
RPCMethod removeprunedfunds();
RPCMethod importdescriptors();
RPCMethod listdescriptors();
RPCMethod backupwallet();
RPCMethod restorewallet();

// coins
RPCMethod getreceivedbyaddress();
RPCMethod getreceivedbylabel();
RPCMethod getbalance();
RPCMethod lockunspent();
RPCMethod listlockunspent();
RPCMethod getbalances();
RPCMethod listunspent();

// encryption
RPCMethod walletpassphrase();
RPCMethod walletpassphrasechange();
RPCMethod walletlock();
RPCMethod encryptwallet();

// spend
RPCMethod sendtoaddress();
RPCMethod sendmany();
RPCMethod fundrawtransaction();
RPCMethod bumpfee();
RPCMethod psbtbumpfee();
RPCMethod send();
RPCMethod sendall();
RPCMethod walletprocesspsbt();
RPCMethod walletcreatefundedpsbt();
RPCMethod signrawtransactionwithwallet();

// signmessage
RPCMethod signmessage();

// transactions
RPCMethod listreceivedbyaddress();
RPCMethod listreceivedbylabel();
RPCMethod listtransactions();
RPCMethod listsinceblock();
RPCMethod gettransaction();
RPCMethod abandontransaction();
RPCMethod rescanblockchain();
RPCMethod abortrescan();

std::span<const CRPCCommand> GetWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"rawtransactions", &fundrawtransaction},
        {"wallet", &abandontransaction},
        {"wallet", &abortrescan},
        {"wallet", &addhdkey},
        {"wallet", &analyzedescriptor},
        {"wallet", &backupwallet},
        {"wallet", &bumpfee},
        {"wallet", &psbtbumpfee},
        {"wallet", &createwallet},
        {"wallet", &createwalletdescriptor},
        {"wallet", &restorewallet},
        {"wallet", &encryptwallet},
        {"wallet", &getaddressesbylabel},
        {"wallet", &getaddressinfo},
        {"wallet", &getbalance},
        {"wallet", &gethdkeys},
        {"wallet", &getnewaddress},
        {"wallet", &getrawchangeaddress},
        {"wallet", &getreceivedbyaddress},
        {"wallet", &getreceivedbylabel},
        {"wallet", &gettransaction},
        {"wallet", &getbalances},
        {"wallet", &getwalletinfo},
        {"wallet", &importdescriptors},
        {"wallet", &importprunedfunds},
        {"wallet", &keypoolrefill},
        {"wallet", &listaddressgroupings},
        {"wallet", &listdescriptors},
        {"wallet", &listlabels},
        {"wallet", &listlockunspent},
        {"wallet", &listreceivedbyaddress},
        {"wallet", &listreceivedbylabel},
        {"wallet", &listsinceblock},
        {"wallet", &listtransactions},
        {"wallet", &listunspent},
        {"wallet", &listwalletdir},
        {"wallet", &listwallets},
        {"wallet", &loadwallet},
        {"wallet", &lockunspent},
        {"wallet", &migratewallet},
        {"wallet", &removeprunedfunds},
        {"wallet", &rescanblockchain},
        {"wallet", &send},
        {"wallet", &sendmany},
        {"wallet", &sendtoaddress},
        {"wallet", &setlabel},
        {"wallet", &setwalletflag},
        {"wallet", &signmessage},
        {"wallet", &signrawtransactionwithwallet},
        {"wallet", &simulaterawtransaction},
        {"wallet", &sendall},
        {"wallet", &unloadwallet},
        {"wallet", &walletcreatefundedpsbt},
#ifdef ENABLE_EXTERNAL_SIGNER
        {"wallet", &walletdisplayaddress},
#endif // ENABLE_EXTERNAL_SIGNER
        {"wallet", &walletlock},
        {"wallet", &walletpassphrase},
        {"wallet", &walletpassphrasechange},
        {"wallet", &walletprocesspsbt},
    };
    return commands;
}
} // namespace wallet
