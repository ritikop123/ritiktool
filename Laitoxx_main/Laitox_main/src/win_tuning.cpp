#ifdef _WIN32

#include "win_tuning.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

namespace laitoxx {

// ── Admin check ──────────────────────────────────────────────────────────

bool is_running_as_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;

    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin != FALSE;
}

// ── System info ──────────────────────────────────────────────────────────

static uint32_t read_registry_dword(const char* key_path, const char* value_name, uint32_t default_val) {
    HKEY hkey;
    DWORD value = default_val;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        RegQueryValueExA(hkey, value_name, nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(hkey);
    }
    return value;
}

SystemInfo get_system_info() {
    SystemInfo info{};

    // CPU count
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    info.cpu_count = si.dwNumberOfProcessors;

    // Memory
    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        info.total_memory_mb = mem.ullTotalPhys / (1024 * 1024);
        info.available_memory_mb = mem.ullAvailPhys / (1024 * 1024);
    }

    // OS version
    OSVERSIONINFOA osvi{};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    #pragma warning(suppress: 4996) // GetVersionExA is deprecated
    if (GetVersionExA(&osvi)) {
        std::ostringstream oss;
        oss << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
            << " (Build " << osvi.dwBuildNumber << ")";
        info.os_version = oss.str();
    }

    info.is_admin = is_running_as_admin();

    // Current TCP/IP tuning values
    const char* tcp_params = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    info.max_user_port = read_registry_dword(tcp_params, "MaxUserPort", 5000);
    info.tcp_timed_wait_delay = read_registry_dword(tcp_params, "TcpTimedWaitDelay", 120);

    // Dynamic port range (netsh int ipv4 show dynamicport tcp)
    info.dynamic_port_start = read_registry_dword(tcp_params, "DynamicPortRangeStartPort", 49152);
    info.dynamic_port_end = info.dynamic_port_start +
        read_registry_dword(tcp_params, "DynamicPortRangeNumberOfPorts", 16384) - 1;

    return info;
}

// ── Registry tuning ──────────────────────────────────────────────────────

TuningResult set_registry_dword(
    const std::string& key_path,
    const std::string& value_name,
    uint32_t value)
{
    TuningResult result;
    HKEY hkey;

    LONG status = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        key_path.c_str(),
        0, nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hkey,
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        result.success = false;
        result.message = "Failed to open/create key: " + key_path +
                         " (error " + std::to_string(status) + ")";
        return result;
    }

    DWORD dw_value = static_cast<DWORD>(value);
    status = RegSetValueExA(
        hkey,
        value_name.c_str(),
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&dw_value),
        sizeof(DWORD)
    );

    RegCloseKey(hkey);

    if (status == ERROR_SUCCESS) {
        result.success = true;
        result.message = "Set " + key_path + "\\" + value_name +
                         " = " + std::to_string(value);
    } else {
        result.success = false;
        result.message = "Failed to set " + value_name +
                         " (error " + std::to_string(status) + ")";
    }
    return result;
}

std::vector<TuningResult> apply_windows_tuning() {
    std::vector<TuningResult> results;

    if (!is_running_as_admin()) {
        results.push_back({false, "Administrator privileges required for registry tuning"});
        return results;
    }

    const std::string tcp_params = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    const std::string afd_params = "SYSTEM\\CurrentControlSet\\Services\\AFD\\Parameters";

    // TCP/IP Parameters
    results.push_back(set_registry_dword(tcp_params, "TcpTimedWaitDelay", 30));
    results.push_back(set_registry_dword(tcp_params, "MaxUserPort", 65534));
    results.push_back(set_registry_dword(tcp_params, "TcpMaxDataRetransmissions", 3));
    results.push_back(set_registry_dword(tcp_params, "EnableDynamicBacklog", 1));
    results.push_back(set_registry_dword(tcp_params, "MinimumDynamicBacklog", 200));
    results.push_back(set_registry_dword(tcp_params, "MaximumDynamicBacklog", 200000));
    results.push_back(set_registry_dword(tcp_params, "DynamicBacklogGrowthDelta", 100));

    // AFD Parameters (Ancillary Function Driver — kernel-level socket parameters)
    results.push_back(set_registry_dword(afd_params, "EnableDynamicBacklog", 1));
    results.push_back(set_registry_dword(afd_params, "MinimumDynamicBacklog", 200));
    results.push_back(set_registry_dword(afd_params, "MaximumDynamicBacklog", 200000));
    results.push_back(set_registry_dword(afd_params, "DynamicBacklogGrowthDelta", 100));

    return results;
}

// ── Socket options helper ────────────────────────────────────────────────

void configure_socket_options(uintptr_t sock_handle, bool is_tcp,
                              int send_buf, int recv_buf) {
    SOCKET sock = static_cast<SOCKET>(sock_handle);

    // SO_REUSEADDR — allow rapid port reuse after TIME_WAIT
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    // Send/receive buffer sizes
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&send_buf), sizeof(send_buf));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&recv_buf), sizeof(recv_buf));

    if (is_tcp) {
        // TCP_NODELAY — disable Nagle's algorithm for lower latency
        int nodelay = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
                   reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    }

    // Linger off — immediate close, don't wait for pending data
    struct linger lin{};
    lin.l_onoff = 1;
    lin.l_linger = 0;
    setsockopt(sock, SOL_SOCKET, SO_LINGER,
               reinterpret_cast<const char*>(&lin), sizeof(lin));
}

} // namespace laitoxx

#endif // _WIN32
