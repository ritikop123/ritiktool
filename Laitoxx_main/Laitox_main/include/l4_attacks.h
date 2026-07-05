#pragma once

#include "attack_engine.h"
#include <mutex>

namespace laitoxx {

// ============================================================================
// L4 Advanced TCP/UDP Attacks
// ============================================================================

// ACK Flood - Flood with TCP ACK packets
class ACKFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// SYN-ACK Flood - Flood with TCP SYN-ACK packets
class SYNACKFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// RST Flood - Flood with TCP RST packets
class RSTFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// FIN Flood - Flood with TCP FIN packets
class FINFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// ICMP Flood - ICMP Echo Request flood
class ICMPFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// ICMP Redirect Flood
class ICMPRedirect : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// CPS (Connections Per Second) - Rapid connect/disconnect
class CPSFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// CONNECTION - Hold many connections open
class CONNECTIONFlood : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    void keep_alive_worker();
    std::vector<int> active_sockets_;
    std::mutex sockets_mutex_;
};

// ============================================================================
// L4 Additional Amplification Attacks
// ============================================================================

// SNMP Amplification
class SNMPAmp : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_snmp_packet();
};

// Chargen Amplification
class ChargenAmp : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// CLDAP Amplification
class CLDAPAmp : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<char> build_cldap_packet();
};

// RDP Amplification
class RDPAmp : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// NetBIOS Amplification
class NetBIOSAmp : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

} // namespace laitoxx
