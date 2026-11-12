#include "airplay/iap_tunnel.h"

#include "airplay/control_cipher.h"
#include "common/log.h"
#include "crypto/hkdf.h"

#include <algorithm>
#include <cstring>

namespace core::airplay {
namespace {
constexpr size_t kPackageHeader = 32;
constexpr size_t kMaxPackage = 4 * 1024 * 1024;

uint32_t readBigEndian(const uint8_t* bytes)
{
    return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
           (uint32_t(bytes[2]) << 8) | bytes[3];
}

const char* framingKind(const std::vector<uint8_t>& bytes)
{
    if (bytes.size() >= 2 && bytes[0] == 0xff && bytes[1] == 0x55) return "marker";
    if (bytes.size() >= 2 && bytes[0] == 0xff && bytes[1] == 0x5a) return "link";
    if (bytes.size() >= 2 && bytes[0] == 0x40 && bytes[1] == 0x40) return "csm";
    return "fragment_or_other";
}

class TunnelByteStream : public core::IByteStream {
public:
    TunnelByteStream(std::shared_ptr<core::ITcpStream> peer, const std::vector<uint8_t>& key,
                     IapTunnel::Send send, const std::atomic<bool>& stopped)
        : peer_(std::move(peer)), cipher_(key.data(), key.data()), send_(std::move(send)), stopped_(stopped) {}
    int read(uint8_t* bytes, size_t size, int timeoutMs) override
    {
        if (stopped_.load()) return -1;
        if (pending_.empty()) {
            uint8_t encrypted[16384];
            const int received = peer_->read(encrypted, sizeof encrypted, timeoutMs);
            if (received <= 0) return received;
            if (!receivedData_) {
                receivedData_ = true;
                LOG_INFO("[TBT] runtime encrypted data received bytes=%d", received);
            }
            cipher_.feed(encrypted, size_t(received));
            std::vector<uint8_t> plaintext;
            while (cipher_.next(&plaintext)) {
                if (!packages_.feed(plaintext.data(), plaintext.size())) return -1;
                std::vector<uint8_t> message;
                while (packages_.next(&message)) {
                    if (packageCount_++ < 8) {
                        LOG_INFO("[TBT] runtime comm packet=%zu framing=%s bytes=%zu",
                                 packageCount_, framingKind(message), message.size());
                    }
                    if (!receivedMessage_) {
                        receivedMessage_ = true;
                        LOG_INFO("[TBT] runtime comm package received bytes=%zu", message.size());
                    }
                    if (pending_.size() + message.size() > kMaxPackage) return -1;
                    pending_.insert(pending_.end(), message.begin(), message.end());
                }
                plaintext.clear();
            }
            if (cipher_.failed() || packages_.failed()) {
                LOG_WARN("[TBT] runtime decode failed: cipher=%d package=%d", cipher_.failed(), packages_.failed());
                return -1;
            }
        }
        const size_t count = std::min(size, pending_.size());
        if (count) std::memcpy(bytes, pending_.data(), count);
        pending_.erase(pending_.begin(), pending_.begin() + count);
        return int(count);
    }
    bool writeAll(const uint8_t* bytes, size_t size) override
    {
        if (stopped_.load()) return false;
        const std::vector<uint8_t> message(bytes, bytes + size);
        const bool sent = send_(message);
        if (sendCount_++ < 8 || !sent) {
            LOG_INFO("[TBT] runtime event write packet=%zu framing=%s bytes=%zu sent=%d",
                     sendCount_, framingKind(message), size, sent);
        }
        return sent;
    }
private:
    std::shared_ptr<core::ITcpStream> peer_;
    ControlCipher cipher_;
    IapPackageFramer packages_;
    IapTunnel::Send send_;
    const std::atomic<bool>& stopped_;
    std::vector<uint8_t> pending_;
    bool receivedData_ = false;
    bool receivedMessage_ = false;
    size_t packageCount_ = 0;
    size_t sendCount_ = 0;
};

}

bool IapPackageFramer::feed(const uint8_t* data, size_t size)
{
    if (failed_ || size > kMaxPackage - buffer_.size()) { failed_ = true; return false; }
    if (size) buffer_.insert(buffer_.end(), data, data + size);
    return true;
}

bool IapPackageFramer::next(std::vector<uint8_t>* message)
{
    while (!failed_ && buffer_.size() >= kPackageHeader) {
        const uint32_t size = readBigEndian(buffer_.data());
        if (size < kPackageHeader || size > kMaxPackage) { failed_ = true; return false; }
        if (buffer_.size() < size) return false;
        const bool communication = readBigEndian(buffer_.data() + 16) == 0x636f6d6d;
        if (communication) message->assign(buffer_.begin() + kPackageHeader, buffer_.begin() + size);
        buffer_.erase(buffer_.begin(), buffer_.begin() + size);
        if (communication) return true;
    }
    return false;
}

IapTunnel::IapTunnel(std::unique_ptr<core::ITcpListener> listener,
                     const std::vector<uint8_t>& sharedSecret, uint64_t seed,
                     core::iap2::WirelessTriggerConfig config, Send send)
    : listener_(std::move(listener)), config_(std::move(config)), send_(std::move(send))
{
    port_ = listener_->port();
    config_.runtimeTunnel = true;
    readKey_ = crypto::hkdfSha512(sharedSecret, "DataStream-Salt" + std::to_string(seed),
                                 "DataStream-Output-Encryption-Key", 32);
    thread_ = std::thread([this] { run(); });
    LOG_INFO("[TBT] Runtime iAP tunnel listening port=%u", port_);
}

IapTunnel::~IapTunnel() { stop(); }

void IapTunnel::stop()
{
    if (stopped_.exchange(true)) return;
    listener_->stop();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (peer_) peer_->close();
    }
    if (thread_.joinable()) thread_.join();
}

void IapTunnel::run()
{
    while (!stopped_.load()) {
        auto accepted = listener_->accept(200);
        if (!accepted) continue;
        auto peer = std::shared_ptr<core::ITcpStream>(std::move(accepted));
        {
            std::lock_guard<std::mutex> lock(mutex_);
            peer_ = peer;
        }
        LOG_INFO("[TBT] Runtime iAP tunnel connected");
        TunnelByteStream stream(peer, readKey_, send_, stopped_);
        core::iap2::WirelessTrigger runtime(&stream, config_);
        runtime.run();
        peer->close();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            peer_.reset();
        }
        if (!stopped_.load()) LOG_WARN("[TBT] Runtime iAP tunnel ended: %s", runtime.error().c_str());
    }
}

}