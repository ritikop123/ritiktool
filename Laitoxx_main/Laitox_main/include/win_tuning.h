#pragma once

#ifdef _WIN32

#include <string>
#include <vector>
#include <cstdint>

namespace laitoxx {

/// Result of a tuning operation
struct TuningResult {
    bool success;
    std::string message;
};

/// System information snapshot
struct SystemInfo {
    uint32_t cpu_count;
    uint64_t total_memory_mb;
    uint64_t available_memory_mb;
    std::string os_version;
    bool is_admin;

    // Current TCP/IP tuning state
    uint32_t max_user_port;
    uint32_t tcp_timed_wait_delay;
    uint32_t dynamic_port_start;
    uint32_t dynamic_port_end;
};

/// Check if the current process is running as Administrator
bool is_running_as_admin();

/// Get system information and current tuning state
SystemInfo get_system_info();

/// Apply recommended Windows TCP/IP registry tuning for high-throughput networking.
/// Requires Administrator privileges. Changes take effect after reboot.
///
/// Modifications:
///   HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
///     - TcpTimedWaitDelay  → 30  (default 120 or 240; reduces TIME_WAIT duration)
///     - MaxUserPort        → 65534  (default 5000; expands ephemeral port range)
///     - TcpMaxDataRetransmissions → 3 (default 5; faster timeout on dead connections)
///     - EnableDynamicBacklog → 1  (enables dynamic SYN backlog)
///     - MinimumDynamicBacklog → 200
///     - MaximumDynamicBacklog → 200000
///     - DynamicBacklogGrowthDelta → 100
///
///   HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters
///     - EnableDynamicBacklog → 1
///     - MinimumDynamicBacklog → 200
///     - MaximumDynamicBacklog → 200000
///     - DynamicBacklogGrowthDelta → 100
///
std::vector<TuningResult> apply_windows_tuning();

/// Set a DWORD value in the Windows registry.
TuningResult set_registry_dword(
    const std::string& key_path,
    const std::string& value_name,
    uint32_t value
);

/// Configure socket for high-performance operation.
/// Sets SO_REUSEADDR, TCP_NODELAY, send/recv buffer sizes, linger off.
void configure_socket_options(uintptr_t sock, bool is_tcp = true,
                              int send_buf = 65536, int recv_buf = 65536);

} // namespace laitoxx

#endif // _WIN32
