#pragma once

#include "iap2/wireless_client.h"
#include "port/tcp.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace core::airplay {

class IapPackageFramer {
public:
    bool feed(const uint8_t* data, size_t size);
    bool next(std::vector<uint8_t>* message);
    bool failed() const { return failed_; }
private:
    std::vector<uint8_t> buffer_;
    bool failed_ = false;
};

class IapTunnel {
public:
    using Send = std::function<bool(const std::vector<uint8_t>&)>;
    IapTunnel(std::unique_ptr<core::ITcpListener> listener,
              const std::vector<uint8_t>& sharedSecret, uint64_t seed,
              core::iap2::WirelessTriggerConfig config, Send send);
    ~IapTunnel();
    void stop();
    uint16_t port() const { return port_; }
private:
    void run();
    std::unique_ptr<core::ITcpListener> listener_;
    std::vector<uint8_t> readKey_;
    core::iap2::WirelessTriggerConfig config_;
    Send send_;
    uint16_t port_ = 0;
    std::atomic<bool> stopped_{false};
    std::mutex mutex_;
    std::shared_ptr<core::ITcpStream> peer_;
    std::thread thread_;
};

}