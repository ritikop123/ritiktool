#pragma once

#include "attack_engine.h"
#include <vector>

namespace laitoxx {

// ============================================================================
// L3 Network Layer Attacks (Phase 2)
// ============================================================================

// Smurf Attack - ICMP broadcast amplification
class SmurfAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_icmp_broadcast_packet(const std::string& broadcast_addr);
};

// Fraggle Attack - UDP broadcast amplification
class FraggleAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_udp_broadcast_packet(const std::string& broadcast_addr);
};

// Ping of Death - Oversized/fragmented ICMP
class PingOfDeath : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<std::vector<char>> build_fragmented_ping(size_t total_size);
};

// IPv6 NDP Flood - Neighbor Discovery Protocol flood
class IPv6NDPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_ndp_neighbor_solicitation();
    std::vector<char> build_ndp_router_advertisement();
};

// BGP Hijacking Simulation - Theoretical BGP attack
class BGPHijacking : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_bgp_update_message(const std::string& prefix);
    // Note: This is for educational/testing purposes only
    // Real BGP hijacking requires router access and is highly illegal
};

} // namespace laitoxx
