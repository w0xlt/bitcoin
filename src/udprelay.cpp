#include <udprelay.h>

void UDPRelayBlock(const CBlock& block) {

}

void BlockRecvInit() {

}

void BlockRecvShutdown() {

}

bool HandleBlockTxMessage(UDPMessage& msg, size_t length, const CService& node, UDPConnectionState& state, const std::chrono::steady_clock::time_point& packet_process_start) {
    return false;
}

void ProcessDownloadTimerEvents() {

}

// Each UDPMessage must be of sizeof(UDPMessageHeader) + MAX_UDP_MESSAGE_LENGTH in length!
void UDPFillMessagesFromBlock(const CBlock& block, std::vector<UDPMessage>& msgs) {

}

void UDPFillMessagesFromTx(const CTransaction& tx, std::vector<UDPMessage>& msgs) {
    
}