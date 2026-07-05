#pragma once

#include "attack_engine.h"
#include <map>

namespace laitoxx {

// ============================================================================
// L7 Advanced Bypass Attacks
// ============================================================================

// Cloudflare Bypass - Direct to origin IP
class CloudflareBypass : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_cf_headers();
};

// Cloudflare UAM Bypass - JavaScript challenge solver
class CloudflareUAM : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    bool solve_js_challenge(const std::string& page_content, std::string& clearance_token);
};

// DDoS-Guard Bypass
class DDoSGuardBypass : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_ddg_headers();
};

// ArvanCloud Bypass
class ArvanCloudBypass : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// Google Bot impersonation
class GoogleBotAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string get_googlebot_ua();
};

// Google Project Shield Bypass
class GoogleShieldBypass : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::map<std::string, std::string> generate_legitimate_patterns();
};

// Combined Bypass - Rotates multiple techniques
class BYPASSCombined : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    int current_technique_;
};

// KILLER - Multi-method attack
class KILLERAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void slow_worker();
    void fast_worker();
    void post_worker();
};

} // namespace laitoxx
