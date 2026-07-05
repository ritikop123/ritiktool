#pragma once

#include "attack_engine.h"
#include <string>
#include <vector>

namespace laitoxx {

// ============================================================================
// L7 Application-Specific Attacks (Phase 3)
// ============================================================================

// WordPress XML-RPC Pingback Flood
class WordPressXMLRPC : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string build_xmlrpc_pingback(const std::string& target_url);
    std::string build_xmlrpc_multicall();
};

// Apache Range Header Exploit (CVE-2011-3192)
class ApacheRangeExploit : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string build_range_request(int num_ranges);
};

// TOR Routing Stress (Circuit Creation Flood)
class TORFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_tor_cell(uint8_t command);
    std::vector<char> build_create_circuit();
    bool perform_tor_handshake(int sock);
};

// Slowloris variant - Slow HTTP Headers
class SlowHeaders : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void send_partial_header(int sock);
};

// Slow HTTP POST (R-U-Dead-Yet / RUDY)
class SlowPOST : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void send_slow_post(int sock);
};

} // namespace laitoxx
