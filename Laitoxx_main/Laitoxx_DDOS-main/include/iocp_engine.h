#pragma once

#ifdef _WIN32

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <atomic>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace laitoxx {

/// Operation type for IOCP completion key
enum class IOCPOp : uint8_t {
    CONNECT,
    SEND,
    RECV,
    DISCONNECT,
};

/// Per-I/O data structure overlapping OVERLAPPED
struct IOCPOverlapped {
    OVERLAPPED  overlapped;
    IOCPOp      op;
    SOCKET      socket;
    WSABUF      wsa_buf;
    char        buffer[4096];
    uint32_t    bytes_transferred;
};

/// High-performance IOCP-based async I/O engine.
///
/// Replaces the std::thread-per-worker model with:
///   - A single IOCP completion port
///   - N worker threads (default = 2 × CPU cores) processing completions
///   - Async ConnectEx / WSASend for non-blocking I/O
///   - Pre-allocated IOCPOverlapped structures via a pool
///
/// Usage:
///   IOCPEngine engine(worker_count);
///   engine.start();
///   engine.async_connect(target_ip, port, on_connected);
///   // ... on_connected fires when connection completes
///   engine.async_send(sock, data, len, on_sent);
///   engine.stop();
///
class IOCPEngine {
public:
    using ConnectCallback = std::function<void(SOCKET sock, bool success)>;
    using SendCallback    = std::function<void(SOCKET sock, uint32_t bytes, bool success)>;

    /// Create an IOCP engine with `worker_count` threads.
    /// If worker_count == 0, defaults to 2 × number of CPU cores.
    explicit IOCPEngine(uint32_t worker_count = 0);
    ~IOCPEngine();

    IOCPEngine(const IOCPEngine&) = delete;
    IOCPEngine& operator=(const IOCPEngine&) = delete;

    /// Start the worker threads and begin processing completions.
    bool start();

    /// Signal all workers to stop and wait for them to drain.
    void stop();

    /// Initiate an async TCP connection. Callback fires on the worker thread.
    bool async_connect(const std::string& ip, int port, ConnectCallback cb);

    /// Initiate an async send on an already-connected socket.
    bool async_send(SOCKET sock, const char* data, uint32_t len, SendCallback cb);

    /// Associate an existing socket with this IOCP.
    bool associate_socket(SOCKET sock);

    /// Statistics
    uint64_t total_connections() const { return total_connections_.load(std::memory_order_relaxed); }
    uint64_t total_sends()       const { return total_sends_.load(std::memory_order_relaxed); }
    uint64_t total_errors()      const { return total_errors_.load(std::memory_order_relaxed); }
    bool     is_running()        const { return running_.load(std::memory_order_acquire); }

private:
    HANDLE                  iocp_;
    uint32_t                worker_count_;
    std::atomic<bool>       running_;
    std::vector<HANDLE>     worker_threads_;

    // Function pointers loaded at runtime (ConnectEx is an extension)
    LPFN_CONNECTEX          fn_connect_ex_;

    // Statistics
    std::atomic<uint64_t>   total_connections_;
    std::atomic<uint64_t>   total_sends_;
    std::atomic<uint64_t>   total_errors_;

    // Callbacks stored per-overlapped (indexed by pointer)
    // For simplicity we store callbacks inside a companion map
    // In production, embed in a custom struct or use the overlapped's hEvent.
    struct PendingOp {
        ConnectCallback connect_cb;
        SendCallback    send_cb;
    };
    // Thread-safe storage for pending operations
    CRITICAL_SECTION        pending_lock_;
    std::unordered_map<IOCPOverlapped*, PendingOp> pending_ops_;

    static DWORD WINAPI worker_thread_proc(LPVOID param);
    void worker_loop();

    IOCPOverlapped* alloc_overlapped(IOCPOp op, SOCKET sock);
    void free_overlapped(IOCPOverlapped* ov);

    bool load_connect_ex();

    void store_pending(IOCPOverlapped* ov, PendingOp&& op);
    PendingOp take_pending(IOCPOverlapped* ov);
};

} // namespace laitoxx

#endif // _WIN32
