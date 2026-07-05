#pragma once

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <random>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace laitoxx {

// Header configuration policies
enum class HeaderPolicy {
    REQUIRED,          // Mandatory header (cannot be disabled)
    HEADER_OPTIONAL,   // Optional header (can be enabled/disabled)
    FORBIDDEN          // Forbidden header (cannot be used for this method)
};

// Header configuration for specific attack method
struct HeaderConfig {
    bool enable_user_agent = true;
    bool enable_accept = true;
    bool enable_accept_language = true;
    bool enable_accept_encoding = true;
    bool enable_referer = true;
    bool enable_sec_headers = false;       // Sec-Fetch-* headers
    bool enable_client_hints = false;      // Client Hints headers
    bool enable_proxy_headers = false;     // X-Forwarded-For, X-Real-IP, etc.

    // Custom headers
    std::map<std::string, std::string> custom_headers;

    // Method-specific policy overrides
    std::map<std::string, HeaderPolicy> header_policies;
};

// Header Manager - loads headers from txt files and generates them
class HeaderManager {
public:
    HeaderManager();
    ~HeaderManager() = default;

    // Load headers from files
    bool load_headers(const std::string& headers_dir);

    // Generate random headers based on config
    std::map<std::string, std::string> generate_headers(
        const HeaderConfig& config,
        const std::string& method_type = ""
    );

    // Generate specific header types
    std::string get_random_user_agent();
    std::string get_random_accept();
    std::string get_random_accept_language();
    std::string get_random_accept_encoding();
    std::string get_random_referer();
    std::string get_random_sec_header(const std::string& header_name);
    std::string get_random_client_hint(const std::string& header_name);

    // Proxy headers generation
    std::string generate_fake_ip();
    std::map<std::string, std::string> generate_proxy_headers();

    // Method-specific policies
    HeaderConfig get_default_config_for_method(const std::string& method);

    // Check if header is allowed for method
    bool is_header_allowed(const std::string& header_name, const std::string& method);

private:
    // Header lists loaded from files
    std::vector<std::string> user_agents_;
    std::vector<std::string> accepts_;
    std::vector<std::string> accept_languages_;
    std::vector<std::string> accept_encodings_;
    std::vector<std::string> referers_;
    std::vector<std::string> sec_headers_;
    std::vector<std::string> client_hints_;

    // Random generator
    std::mt19937 rng_;

    // Helper functions
    bool load_file_lines(const std::string& filepath, std::vector<std::string>& out);
    std::string get_random_from_vector(const std::vector<std::string>& vec);

    // Method-specific header policies
    std::map<std::string, std::map<std::string, HeaderPolicy>> method_policies_;

    void initialize_method_policies();
};

// IP Range Manager - loads and manages IP ranges
class IPRangeManager {
public:
    IPRangeManager();
    ~IPRangeManager() = default;

    // Load IP ranges from files
    bool load_ip_ranges(const std::string& ip_ranges_dir);

    // Load specific range file
    bool load_range_file(const std::string& name, const std::string& filepath);

    // Get random IP from specific range
    std::string get_random_ip_from_range(const std::string& range_name);

    // Get random IP from any loaded range
    std::string get_random_ip();

    // Check if range is loaded
    bool has_range(const std::string& range_name);

    // Get all loaded range names
    std::vector<std::string> get_loaded_ranges();

private:
    // IP ranges by name (e.g., "cloudflare", "ovh", etc.)
    std::map<std::string, std::vector<std::string>> ip_ranges_;

    // Random generator
    std::mt19937 rng_;

    // Helper functions
    std::string get_random_from_cidr(const std::string& cidr);
    uint32_t cidr_to_ip_range(const std::string& cidr, uint32_t& start, uint32_t& end);
    std::string uint32_to_ip(uint32_t ip);
};

// Proxy configuration
struct ProxyConfig {
    bool enabled = false;
    std::string proxy_type = "socks5";  // socks5, socks4, http
    std::string proxy_host;
    int proxy_port = 1080;
    std::string proxy_username;
    std::string proxy_password;
    int connect_timeout = 10;  // seconds
    int read_timeout = 30;     // seconds
    int retries = 3;
};

// Proxy connector for L7 attacks
class ProxyConnector {
public:
    ProxyConnector(const ProxyConfig& config);
    ~ProxyConnector();

    // Connect through proxy
    int connect_through_proxy(const std::string& target_host, int target_port);

    // Send data through proxy connection
    ssize_t send_data(int sockfd, const char* data, size_t len);

    // Receive data through proxy connection
    ssize_t recv_data(int sockfd, char* buffer, size_t len);

    // Close proxy connection
    void close_connection(int sockfd);

    // Check if proxy is configured
    bool is_enabled() const { return config_.enabled; }

private:
    ProxyConfig config_;

    // SOCKS5 handshake
    bool socks5_handshake(int sockfd, const std::string& target_host, int target_port);

    // SOCKS4 handshake
    bool socks4_handshake(int sockfd, const std::string& target_host, int target_port);

    // HTTP CONNECT handshake
    bool http_connect_handshake(int sockfd, const std::string& target_host, int target_port);
};

} // namespace laitoxx
