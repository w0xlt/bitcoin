#ifndef BITCOIN_UDPRELAY_H
#define BITCOIN_UDPRELAY_H

#include <memory>
class CBlock;
class CBlockIndex;

namespace UDPRelay {
    //! Start the UDP relay subsystem (call during node startup).
    bool StartUDPRelay();
    //! Stop the UDP relay subsystem (call during shutdown to clean up).
    void StopUDPRelay();
    //! Notify the UDP relay about a newly validated block (to send it).
    void NotifyNewBlock(const CBlockIndex* pindex, const std::shared_ptr<const CBlock>& block);
} // namespace UDPRelay

#endif // BITCOIN_UDPRELAY_H
