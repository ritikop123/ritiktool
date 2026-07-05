#pragma once

#include "attack_engine.h"
#include <vector>
#include <string>

namespace laitoxx {

// ============================================================================
// L2 Data Link Layer Attacks (Phase 3)
// ============================================================================

// ARP Flood / MAC Table Overflow
class ARPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_arp_request(const std::string& target_ip, const std::string& fake_mac);
    std::vector<char> build_arp_reply(const std::string& target_ip, const std::string& fake_mac);
    std::string random_mac();
};

// VLAN Hopping (Double-Tagging)
class VLANHopping : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_double_tagged_frame(uint16_t outer_vlan, uint16_t inner_vlan);
    std::vector<char> build_dtp_frame(); // Dynamic Trunking Protocol
};

} // namespace laitoxx
