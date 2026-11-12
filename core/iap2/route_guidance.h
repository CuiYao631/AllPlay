#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace core::iap2 {

struct TurnByTurn {
    uint16_t maneuverId = 0;
    uint8_t appleType = 0;
    uint8_t drivingSide = 0;
    std::string action;
    std::string road;
    std::optional<uint32_t> distanceMeters;
    std::optional<uint32_t> remainingMeters;
    std::optional<uint64_t> remainingSeconds;
};

class RouteGuidance {
public:
    bool accept(uint16_t messageId, const std::vector<uint8_t>& body);
    std::optional<TurnByTurn> current() const;
    static std::string actionName(uint8_t appleType);

private:
    std::optional<TurnByTurn> snapshot() const;
    mutable std::mutex mutex_;
    std::map<uint16_t, TurnByTurn> maneuvers_;
    std::optional<uint16_t> activeId_;
    bool active_ = false;
    std::string currentRoad_;
    std::optional<uint32_t> distanceMeters_;
    std::optional<uint32_t> remainingMeters_;
    std::optional<uint64_t> remainingSeconds_;
    std::string lastLog_;
};

}