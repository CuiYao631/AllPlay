#include "iap2/route_guidance.h"

#include "common/log.h"
#include "iap2/wire.h"

#include <sstream>

namespace core::iap2 {
namespace {

std::string logText(std::string text)
{
    for (char& character : text) {
        if (static_cast<unsigned char>(character) < 32 || character == '"' || character == '\\')
            character = ' ';
    }
    return text;
}

uint64_t unsignedValue(const Param& param)
{
    uint64_t value = 0;
    for (uint8_t byte : param.payload) value = (value << 8) | byte;
    return value;
}

}

std::string RouteGuidance::actionName(uint8_t type)
{
    if (type >= 28 && type <= 46) return "roundabout_exit_" + std::to_string(type - 27);
    switch (type) {
    case 1: case 20: return "left";
    case 2: case 21: return "right";
    case 47: return "sharp_left";
    case 48: return "sharp_right";
    case 13: case 22: case 49: case 52: return "slight_left";
    case 14: case 23: case 50: case 53: return "slight_right";
    case 4: case 18: case 19: case 26: return "u_turn";
    case 6: return "enter_roundabout";
    case 7: return "exit_roundabout";
    case 10: case 12: case 24: case 25: case 27: return "destination";
    case 3: case 5: case 8: case 9: case 11: case 51: return "straight";
    default: return "unknown";
    }
}

std::optional<TurnByTurn> RouteGuidance::snapshot() const
{
    if (!active_ || !activeId_) return {};
    const auto found = maneuvers_.find(*activeId_);
    if (found == maneuvers_.end()) return {};
    auto value = found->second;
    if (value.road.empty()) value.road = currentRoad_;
    value.distanceMeters = distanceMeters_;
    value.remainingMeters = remainingMeters_;
    value.remainingSeconds = remainingSeconds_;
    return value;
}

std::optional<TurnByTurn> RouteGuidance::current() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot();
}

bool RouteGuidance::accept(uint16_t messageId, const std::vector<uint8_t>& body)
{
    if (messageId != 0x5201 && messageId != 0x5202) return false;
    std::vector<Param> params;
    if (!parseParams(body.data(), body.size(), &params)) {
        LOG_WARN("[TBT] malformed message=0x%04x bytes=%zu", messageId, body.size());
        return false;
    }
    for (const auto& param : params) {
        size_t expected = 0;
        bool text = false;
        if (messageId == 0x5201) {
            if (param.id == 1) expected = 1;
            if (param.id == 5 || param.id == 6) expected = 8;
            if (param.id == 7 || param.id == 0x0a) expected = 4;
            text = param.id == 3 || param.id == 0x13;
            if (param.id == 0x0d && param.payload.size() % 2 != 0) return false;
        } else {
            if (param.id == 1) expected = 2;
            if (param.id == 3 || param.id == 8) expected = 1;
            text = param.id == 4;
        }
        if (expected && param.payload.size() != expected) return false;
        if (text) {
            bool valid = false;
            paramString(param, &valid);
            if (!valid || param.payload.size() > 1024) return false;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (messageId == 0x5202) {
        const auto index = findParam(params, 1);
        const auto type = findParam(params, 3);
        if (!index || !type) return false;
        TurnByTurn value;
        value.maneuverId = paramU16(*index);
        value.appleType = paramU8(*type);
        value.action = actionName(value.appleType);
        if (const auto side = findParam(params, 8)) value.drivingSide = paramU8(*side);
        if (const auto road = findParam(params, 4)) value.road = logText(paramString(*road));
        if (maneuvers_.size() >= 128 && maneuvers_.find(value.maneuverId) == maneuvers_.end())
            maneuvers_.erase(maneuvers_.begin());
        maneuvers_[value.maneuverId] = value;
        LOG_INFO("[TBT] maneuver id=%u action=%s appleType=%u drivingSide=%u road=\"%s\"",
                 value.maneuverId, value.action.c_str(), value.appleType, value.drivingSide, value.road.c_str());
    } else {
        const auto state = findParam(params, 1);
        if (state && (paramU8(*state) == 0 || paramU8(*state) == 2)) {
            active_ = false;
            activeId_.reset();
            maneuvers_.clear();
            currentRoad_.clear();
            distanceMeters_.reset();
            remainingMeters_.reset();
            remainingSeconds_.reset();
            lastLog_.clear();
            LOG_INFO("[TBT] route state=%s", paramU8(*state) == 2 ? "arrived" : "no_route");
            return true;
        }
        if (state) active_ = true;
        if (const auto road = findParam(params, 3)) currentRoad_ = logText(paramString(*road));
        if (const auto distance = findParam(params, 0x0a)) distanceMeters_ = paramU32(*distance);
        if (const auto remaining = findParam(params, 7)) remainingMeters_ = paramU32(*remaining);
        if (const auto duration = findParam(params, 6)) remainingSeconds_ = unsignedValue(*duration);
        if (const auto indexes = findParam(params, 0x0d)) {
            if (indexes->payload.empty()) activeId_.reset();
            else {
                activeId_ = uint16_t((uint16_t(indexes->payload[0]) << 8) | indexes->payload[1]);
                active_ = true;
            }
        }
    }
    if (const auto guidance = snapshot()) {
        std::ostringstream text;
        text << "[TBT] next id=" << guidance->maneuverId << " action=" << guidance->action
             << " appleType=" << unsigned(guidance->appleType) << " road=\"" << guidance->road << '"';
        if (guidance->distanceMeters) text << " distance_m=" << *guidance->distanceMeters;
        if (guidance->remainingMeters) text << " remaining_m=" << *guidance->remainingMeters;
        if (guidance->remainingSeconds) text << " remaining_s=" << *guidance->remainingSeconds;
        if (text.str() != lastLog_) {
            lastLog_ = text.str();
            LOG_INFO("%s", lastLog_.c_str());
        }
    }
    return true;
}

}