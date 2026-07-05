#pragma once

#include "attack_engine.h"

namespace laitoxx {

// ============================================================================
// L7 HTTP Advanced Attacks
// ============================================================================

// GET Flood - Mass HTTP GET requests
class HTTPGetFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// POST Flood - Mass HTTP POST with body
class HTTPPostFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_post_data();
};

// HEAD Flood - HTTP HEAD method flood
class HTTPHeadFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// OVH Bypass - Mimic legitimate traffic patterns
class OVHBypass : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_random_path();
    std::string generate_realistic_headers();
};

// RHEX - Random HEX strings in URLs and cookies
class RHEXAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_hex_string(size_t length);
};

// STOMP - Slow, malformed HTTP requests
class STOMPAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void send_slow_headers(int sock);
};

// STRESS - Huge HTTP bodies
class STRESSAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// DYN - Random subdomain flood
class DYNAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_random_subdomain();
};

// NULL - Minimal HTTP requests without standard headers
class NULLAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// COOKIE - Huge/many cookies attack
class COOKIEAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_cookies();
};

// PPS - Packets Per Second optimized
class PPSAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// EVEN - Many custom headers
class EVENAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_many_headers();
};

// DOWNLOADER - Slow read attack
class DOWNLOADERAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

} // namespace laitoxx
