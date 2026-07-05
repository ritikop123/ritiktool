#include "header_manager.h"
#include <filesystem>
#include <iostream>
#include <ctime>
#include <cstring>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
#endif

namespace laitoxx {

// ============================================================================
// HeaderManager Implementation
// ============================================================================

HeaderManager::HeaderManager() {
    // Seed random generator
    rng_.seed(std::random_device{}());

    // Initialize method-specific policies
    initialize_method_policies();
}

bool HeaderManager::load_headers(const std::string& headers_dir) {
    namespace fs = std::filesystem;

    if (!fs::exists(headers_dir) || !fs::is_directory(headers_dir)) {
        std::cerr << "Headers directory not found: " << headers_dir << std::endl;
        return false;
    }

    // Load each header file
    load_file_lines(headers_dir + "/ua.txt", user_agents_);
    load_file_lines(headers_dir + "/accept.txt", accepts_);
    load_file_lines(headers_dir + "/accept_language.txt", accept_languages_);
    load_file_lines(headers_dir + "/accept_encoding.txt", accept_encodings_);
    load_file_lines(headers_dir + "/referer.txt", referers_);
    load_file_lines(headers_dir + "/sec_headers.txt", sec_headers_);
    load_file_lines(headers_dir + "/client_hints.txt", client_hints_);

    std::cout << "Loaded headers: " << std::endl;
    std::cout << "  User-Agents: " << user_agents_.size() << std::endl;
    std::cout << "  Accept: " << accepts_.size() << std::endl;
    std::cout << "  Accept-Language: " << accept_languages_.size() << std::endl;
    std::cout << "  Accept-Encoding: " << accept_encodings_.size() << std::endl;
    std::cout << "  Referers: " << referers_.size() << std::endl;

    return user_agents_.size() > 0 && accepts_.size() > 0;
}

bool HeaderManager::load_file_lines(const std::string& filepath, std::vector<std::string>& out) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open: " << filepath << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // Skip empty lines and comments
        if (!line.empty() && line[0] != '#') {
            out.push_back(line);
        }
    }

    return out.size() > 0;
}

std::string HeaderManager::get_random_from_vector(const std::vector<std::string>& vec) {
    if (vec.empty()) return "";
    std::uniform_int_distribution<size_t> dist(0, vec.size() - 1);
    return vec[dist(rng_)];
}

std::string HeaderManager::get_random_user_agent() {
    return get_random_from_vector(user_agents_);
}

std::string HeaderManager::get_random_accept() {
    return get_random_from_vector(accepts_);
}

std::string HeaderManager::get_random_accept_language() {
    return get_random_from_vector(accept_languages_);
}

std::string HeaderManager::get_random_accept_encoding() {
    return get_random_from_vector(accept_encodings_);
}

std::string HeaderManager::get_random_referer() {
    return get_random_from_vector(referers_);
}

std::string HeaderManager::get_random_sec_header(const std::string& header_name) {
    // Sec-Fetch-* headers
    if (header_name == "Sec-Fetch-Dest") {
        std::vector<std::string> values = {"document", "empty", "image", "script", "style"};
        return get_random_from_vector(values);
    } else if (header_name == "Sec-Fetch-Mode") {
        std::vector<std::string> values = {"cors", "navigate", "no-cors", "same-origin"};
        return get_random_from_vector(values);
    } else if (header_name == "Sec-Fetch-Site") {
        std::vector<std::string> values = {"cross-site", "same-origin", "same-site", "none"};
        return get_random_from_vector(values);
    } else if (header_name == "Sec-Fetch-User") {
        return "?1";
    }
    return "";
}

std::string HeaderManager::get_random_client_hint(const std::string& header_name) {
    // Client Hints headers
    if (header_name == "Sec-CH-UA") {
        return "\"Chromium\";v=\"122\", \"Not:A-Brand\";v=\"99\", \"Google Chrome\";v=\"122\"";
    } else if (header_name == "Sec-CH-UA-Mobile") {
        return "?0";
    } else if (header_name == "Sec-CH-UA-Platform") {
        std::vector<std::string> platforms = {"\"Windows\"", "\"macOS\"", "\"Linux\""};
        return get_random_from_vector(platforms);
    }
    return "";
}

std::string HeaderManager::generate_fake_ip() {
    std::uniform_int_distribution<int> octet(1, 254);
    std::stringstream ss;
    ss << octet(rng_) << "." << octet(rng_) << "." << octet(rng_) << "." << octet(rng_);
    return ss.str();
}

std::map<std::string, std::string> HeaderManager::generate_proxy_headers() {
    std::map<std::string, std::string> headers;
    std::string fake_ip = generate_fake_ip();

    headers["X-Forwarded-For"] = fake_ip;
    headers["X-Real-IP"] = fake_ip;
    headers["X-Originating-IP"] = fake_ip;
    headers["X-Client-IP"] = fake_ip;
    headers["X-Remote-IP"] = fake_ip;
    headers["X-Remote-Addr"] = fake_ip;
    headers["CF-Connecting-IP"] = fake_ip;  // Cloudflare
    headers["True-Client-IP"] = fake_ip;    // Akamai/Cloudflare

    return headers;
}

std::map<std::string, std::string> HeaderManager::generate_headers(
    const HeaderConfig& config,
    const std::string& method_type
) {
    std::map<std::string, std::string> headers;

    // Check policies for this method
    auto method_config = config;
    if (!method_type.empty() && method_policies_.count(method_type)) {
        auto& policies = method_policies_[method_type];

        // Apply REQUIRED policies
        for (const auto& [header, policy] : policies) {
            if (policy == HeaderPolicy::REQUIRED) {
                if (header == "User-Agent") method_config.enable_user_agent = true;
                else if (header == "Accept") method_config.enable_accept = true;
                else if (header == "Accept-Language") method_config.enable_accept_language = true;
            } else if (policy == HeaderPolicy::FORBIDDEN) {
                if (header == "User-Agent") method_config.enable_user_agent = false;
                else if (header == "Sec-Fetch-*") method_config.enable_sec_headers = false;
            }
        }
    }

    // Generate headers based on config
    if (method_config.enable_user_agent && !user_agents_.empty()) {
        headers["User-Agent"] = get_random_user_agent();
    }

    if (method_config.enable_accept && !accepts_.empty()) {
        headers["Accept"] = get_random_accept();
    }

    if (method_config.enable_accept_language && !accept_languages_.empty()) {
        headers["Accept-Language"] = get_random_accept_language();
    }

    if (method_config.enable_accept_encoding && !accept_encodings_.empty()) {
        headers["Accept-Encoding"] = get_random_accept_encoding();
    }

    if (method_config.enable_referer && !referers_.empty()) {
        headers["Referer"] = get_random_referer();
    }

    // Sec-Fetch-* headers
    if (method_config.enable_sec_headers) {
        headers["Sec-Fetch-Dest"] = get_random_sec_header("Sec-Fetch-Dest");
        headers["Sec-Fetch-Mode"] = get_random_sec_header("Sec-Fetch-Mode");
        headers["Sec-Fetch-Site"] = get_random_sec_header("Sec-Fetch-Site");
        headers["Sec-Fetch-User"] = get_random_sec_header("Sec-Fetch-User");
    }

    // Client Hints
    if (method_config.enable_client_hints) {
        headers["Sec-CH-UA"] = get_random_client_hint("Sec-CH-UA");
        headers["Sec-CH-UA-Mobile"] = get_random_client_hint("Sec-CH-UA-Mobile");
        headers["Sec-CH-UA-Platform"] = get_random_client_hint("Sec-CH-UA-Platform");
    }

    // Proxy headers (X-Forwarded-For, X-Real-IP, etc.)
    if (method_config.enable_proxy_headers) {
        auto proxy_headers = generate_proxy_headers();
        headers.insert(proxy_headers.begin(), proxy_headers.end());
    }

    // Custom headers
    for (const auto& [key, value] : method_config.custom_headers) {
        headers[key] = value;
    }

    return headers;
}

void HeaderManager::initialize_method_policies() {
    // HTTP methods - REQUIRE standard headers
    method_policies_["GET"]["User-Agent"] = HeaderPolicy::REQUIRED;
    method_policies_["GET"]["Accept"] = HeaderPolicy::REQUIRED;
    method_policies_["GET"]["Accept-Language"] = HeaderPolicy::HEADER_OPTIONAL;

    method_policies_["POST"]["User-Agent"] = HeaderPolicy::REQUIRED;
    method_policies_["POST"]["Accept"] = HeaderPolicy::REQUIRED;
    method_policies_["POST"]["Content-Type"] = HeaderPolicy::REQUIRED;

    // Cloudflare bypass - REQUIRE browser-like headers
    method_policies_["CLOUDFLARE"]["User-Agent"] = HeaderPolicy::REQUIRED;
    method_policies_["CLOUDFLARE"]["Accept"] = HeaderPolicy::REQUIRED;
    method_policies_["CLOUDFLARE"]["Sec-Fetch-*"] = HeaderPolicy::REQUIRED;
    method_policies_["CLOUDFLARE"]["Accept-Language"] = HeaderPolicy::REQUIRED;

    // WebSocket - Special headers
    method_policies_["WEBSOCKET"]["User-Agent"] = HeaderPolicy::REQUIRED;
    method_policies_["WEBSOCKET"]["Upgrade"] = HeaderPolicy::REQUIRED;
    method_policies_["WEBSOCKET"]["Connection"] = HeaderPolicy::REQUIRED;

    // Redis, MongoDB - NO HTTP headers
    method_policies_["REDIS"]["User-Agent"] = HeaderPolicy::FORBIDDEN;
    method_policies_["REDIS"]["Accept"] = HeaderPolicy::FORBIDDEN;

    method_policies_["MONGODB"]["User-Agent"] = HeaderPolicy::FORBIDDEN;
    method_policies_["MONGODB"]["Accept"] = HeaderPolicy::FORBIDDEN;
}

HeaderConfig HeaderManager::get_default_config_for_method(const std::string& method) {
    HeaderConfig config;

    // Database protocols - no HTTP headers
    if (method == "REDIS" || method == "MONGODB" || method == "ELASTICSEARCH") {
        config.enable_user_agent = false;
        config.enable_accept = false;
        config.enable_accept_language = false;
        config.enable_accept_encoding = false;
        config.enable_referer = false;
        return config;
    }

    // Cloudflare/CDN bypass - enable everything
    if (method == "CLOUDFLARE" || method == "CFB" || method == "CFBUAM" ||
        method == "DDOSGUARD" || method == "ARVANCLOUD") {
        config.enable_user_agent = true;
        config.enable_accept = true;
        config.enable_accept_language = true;
        config.enable_accept_encoding = true;
        config.enable_referer = true;
        config.enable_sec_headers = true;
        config.enable_client_hints = true;
        config.enable_proxy_headers = true;
        return config;
    }

    // HTTP/2, HTTP/3, WebSocket - modern headers
    if (method == "HTTP2-STREAM" || method == "HTTP3" || method == "WEBSOCKET") {
        config.enable_sec_headers = true;
        config.enable_client_hints = true;
    }

    // Default: basic HTTP headers
    return config;
}

bool HeaderManager::is_header_allowed(const std::string& header_name, const std::string& method) {
    if (method_policies_.count(method) == 0) {
        return true;  // No policy = allowed
    }

    auto& policies = method_policies_[method];
    if (policies.count(header_name) == 0) {
        return true;  // Not in policy = allowed
    }

    return policies[header_name] != HeaderPolicy::FORBIDDEN;
}

// ============================================================================
// IPRangeManager Implementation
// ============================================================================

IPRangeManager::IPRangeManager() {
    rng_.seed(std::random_device{}());
}

bool IPRangeManager::load_ip_ranges(const std::string& ip_ranges_dir) {
    namespace fs = std::filesystem;

    if (!fs::exists(ip_ranges_dir) || !fs::is_directory(ip_ranges_dir)) {
        std::cerr << "IP ranges directory not found: " << ip_ranges_dir << std::endl;
        return false;
    }

    // Load all .txt files in directory
    for (const auto& entry : fs::directory_iterator(ip_ranges_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".txt") {
            std::string filename = entry.path().stem().string();
            load_range_file(filename, entry.path().string());
        }
    }

    std::cout << "Loaded IP ranges:" << std::endl;
    for (const auto& [name, ips] : ip_ranges_) {
        std::cout << "  " << name << ": " << ips.size() << " ranges" << std::endl;
    }

    return !ip_ranges_.empty();
}

bool IPRangeManager::load_range_file(const std::string& name, const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open: " << filepath << std::endl;
        return false;
    }

    std::vector<std::string> ranges;
    std::string line;
    while (std::getline(file, line)) {
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        // Skip empty lines and comments
        if (!line.empty() && line[0] != '#') {
            ranges.push_back(line);
        }
    }

    if (!ranges.empty()) {
        ip_ranges_[name] = ranges;
    }

    return !ranges.empty();
}

std::string IPRangeManager::get_random_ip_from_range(const std::string& range_name) {
    if (ip_ranges_.count(range_name) == 0 || ip_ranges_[range_name].empty()) {
        return "";
    }

    auto& ranges = ip_ranges_[range_name];
    std::uniform_int_distribution<size_t> dist(0, ranges.size() - 1);
    std::string cidr = ranges[dist(rng_)];

    return get_random_from_cidr(cidr);
}

std::string IPRangeManager::get_random_ip() {
    if (ip_ranges_.empty()) return "";

    // Pick random range
    std::uniform_int_distribution<size_t> range_dist(0, ip_ranges_.size() - 1);
    auto it = ip_ranges_.begin();
    std::advance(it, range_dist(rng_));

    return get_random_ip_from_range(it->first);
}

std::string IPRangeManager::get_random_from_cidr(const std::string& cidr) {
    uint32_t start, end;
    if (cidr_to_ip_range(cidr, start, end) == 0) {
        return "";
    }

    std::uniform_int_distribution<uint32_t> dist(start, end);
    uint32_t random_ip = dist(rng_);

    return uint32_to_ip(random_ip);
}

uint32_t IPRangeManager::cidr_to_ip_range(const std::string& cidr, uint32_t& start, uint32_t& end) {
    size_t slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        return 0;
    }

    std::string ip_str = cidr.substr(0, slash_pos);
    int prefix_len = std::stoi(cidr.substr(slash_pos + 1));

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return 0;
    }

    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));

    start = ip & mask;
    end = start | ~mask;

    return 1;
}

std::string IPRangeManager::uint32_to_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
    return std::string(buffer);
}

bool IPRangeManager::has_range(const std::string& range_name) {
    return ip_ranges_.count(range_name) > 0;
}

std::vector<std::string> IPRangeManager::get_loaded_ranges() {
    std::vector<std::string> names;
    for (const auto& [name, _] : ip_ranges_) {
        names.push_back(name);
    }
    return names;
}

// ============================================================================
// ProxyConnector Implementation
// ============================================================================

ProxyConnector::ProxyConnector(const ProxyConfig& config) : config_(config) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

ProxyConnector::~ProxyConnector() {
#ifdef _WIN32
    WSACleanup();
#endif
}

int ProxyConnector::connect_through_proxy(const std::string& target_host, int target_port) {
    if (!config_.enabled) {
        // Direct connection without proxy
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) return -1;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_host.c_str(), &addr.sin_addr);

        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sockfd);
            return -1;
        }

        return sockfd;
    }

    // Connect to proxy first
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(config_.proxy_port);
    inet_pton(AF_INET, config_.proxy_host.c_str(), &proxy_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    // Perform proxy handshake
    bool success = false;
    if (config_.proxy_type == "socks5") {
        success = socks5_handshake(sockfd, target_host, target_port);
    } else if (config_.proxy_type == "socks4") {
        success = socks4_handshake(sockfd, target_host, target_port);
    } else if (config_.proxy_type == "http") {
        success = http_connect_handshake(sockfd, target_host, target_port);
    }

    if (!success) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

bool ProxyConnector::socks5_handshake(int sockfd, const std::string& target_host, int target_port) {
    // SOCKS5 authentication method selection
    unsigned char auth_request[3] = {0x05, 0x01, 0x00};  // VER=5, NMETHODS=1, METHOD=NO_AUTH
    if (send(sockfd, (char*)auth_request, 3, 0) != 3) {
        return false;
    }

    unsigned char auth_response[2];
    if (recv(sockfd, (char*)auth_response, 2, 0) != 2) {
        return false;
    }

    if (auth_response[0] != 0x05 || auth_response[1] != 0x00) {
        return false;  // Authentication failed or not supported
    }

    // SOCKS5 connection request
    std::vector<unsigned char> conn_request;
    conn_request.push_back(0x05);  // VER
    conn_request.push_back(0x01);  // CMD = CONNECT
    conn_request.push_back(0x00);  // RSV
    conn_request.push_back(0x03);  // ATYP = DOMAINNAME

    conn_request.push_back(static_cast<unsigned char>(target_host.length()));
    for (char c : target_host) {
        conn_request.push_back(static_cast<unsigned char>(c));
    }

    conn_request.push_back((target_port >> 8) & 0xFF);
    conn_request.push_back(target_port & 0xFF);

    if (send(sockfd, (char*)conn_request.data(), conn_request.size(), 0) != (ssize_t)conn_request.size()) {
        return false;
    }

    unsigned char conn_response[10];
    if (recv(sockfd, (char*)conn_response, 10, 0) < 2) {
        return false;
    }

    return (conn_response[0] == 0x05 && conn_response[1] == 0x00);
}

bool ProxyConnector::socks4_handshake(int sockfd, const std::string& target_host, int target_port) {
    // SOCKS4 connection request
    unsigned char request[9];
    request[0] = 0x04;  // VER
    request[1] = 0x01;  // CMD = CONNECT
    request[2] = (target_port >> 8) & 0xFF;
    request[3] = target_port & 0xFF;

    // IP address (0.0.0.1 for SOCKS4a)
    request[4] = 0x00;
    request[5] = 0x00;
    request[6] = 0x00;
    request[7] = 0x01;
    request[8] = 0x00;  // NULL terminator for user ID

    if (send(sockfd, (char*)request, 9, 0) != 9) {
        return false;
    }

    // Send hostname for SOCKS4a
    if (send(sockfd, target_host.c_str(), target_host.length() + 1, 0) != (ssize_t)(target_host.length() + 1)) {
        return false;
    }

    unsigned char response[8];
    if (recv(sockfd, (char*)response, 8, 0) != 8) {
        return false;
    }

    return (response[0] == 0x00 && response[1] == 0x5A);
}

bool ProxyConnector::http_connect_handshake(int sockfd, const std::string& target_host, int target_port) {
    // HTTP CONNECT method
    std::stringstream ss;
    ss << "CONNECT " << target_host << ":" << target_port << " HTTP/1.1\r\n";
    ss << "Host: " << target_host << ":" << target_port << "\r\n";
    ss << "Proxy-Connection: Keep-Alive\r\n";
    ss << "\r\n";

    std::string request = ss.str();
    if (send(sockfd, request.c_str(), request.length(), 0) != (ssize_t)request.length()) {
        return false;
    }

    char response[1024];
    ssize_t n = recv(sockfd, response, sizeof(response) - 1, 0);
    if (n <= 0) {
        return false;
    }

    response[n] = '\0';
    std::string resp_str(response);

    return (resp_str.find("200 Connection established") != std::string::npos ||
            resp_str.find("200 OK") != std::string::npos);
}

ssize_t ProxyConnector::send_data(int sockfd, const char* data, size_t len) {
    return send(sockfd, data, len, 0);
}

ssize_t ProxyConnector::recv_data(int sockfd, char* buffer, size_t len) {
    return recv(sockfd, buffer, len, 0);
}

void ProxyConnector::close_connection(int sockfd) {
    if (sockfd >= 0) {
        close(sockfd);
    }
}

} // namespace laitoxx
