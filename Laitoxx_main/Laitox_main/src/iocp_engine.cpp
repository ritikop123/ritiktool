#ifdef _WIN32

#include "iocp_engine.h"
#include "win_tuning.h"
#include <iostream>
#include <cassert>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

namespace laitoxx {

// ── Construction / Destruction ───────────────────────────────────────────

IOCPEngine::IOCPEngine(uint32_t worker_count)
    : iocp_(INVALID_HANDLE_VALUE)
    , worker_count_(worker_count)
    , running_(false)
    , fn_connect_ex_(nullptr)
    , total_connections_(0)
    , total_sends_(0)
    , total_errors_(0)
{
    InitializeCriticalSection(&pending_lock_);

    if (worker_count_ == 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        worker_count_ = si.dwNumberOfProcessors * 2;
    }
}

IOCPEngine::~IOCPEngine() {
    stop();
    DeleteCriticalSection(&pending_lock_);
}

// ── Start / Stop ─────────────────────────────────────────────────────────

bool IOCPEngine::start() {
    if (running_.load(std::memory_order_acquire))
        return true;

    // Create the IOCP with the specified concurrency
    iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, worker_count_);
    if (!iocp_) {
        std::cerr << "[IOCP] CreateIoCompletionPort failed: " << GetLastError() << "\n";
        return false;
    }

    if (!load_connect_ex()) {
        std::cerr << "[IOCP] Failed to load ConnectEx\n";
        CloseHandle(iocp_);
        iocp_ = INVALID_HANDLE_VALUE;
        return false;
    }

    running_.store(true, std::memory_order_release);

    // Launch worker threads
    worker_threads_.resize(worker_count_);
    for (uint32_t i = 0; i < worker_count_; ++i) {
        worker_threads_[i] = CreateThread(
            nullptr, 0, worker_thread_proc, this, 0, nullptr);
    }

    return true;
}

void IOCPEngine::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel))
        return;

    // Post one quit completion per worker
    for (uint32_t i = 0; i < worker_count_; ++i) {
        PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
    }

    // Wait for all workers to finish
    if (!worker_threads_.empty()) {
        WaitForMultipleObjects(
            static_cast<DWORD>(worker_threads_.size()),
            worker_threads_.data(),
            TRUE,
            5000  // 5 s timeout
        );
        for (auto h : worker_threads_) {
            if (h) CloseHandle(h);
        }
        worker_threads_.clear();
    }

    if (iocp_ != INVALID_HANDLE_VALUE) {
        CloseHandle(iocp_);
        iocp_ = INVALID_HANDLE_VALUE;
    }
}

// ── Async Connect ────────────────────────────────────────────────────────

bool IOCPEngine::async_connect(const std::string& ip, int port, ConnectCallback cb) {
    if (!running_.load(std::memory_order_acquire)) return false;

    // Create a socket and bind it (ConnectEx requires a bound socket)
    SOCKET sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                             nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        total_errors_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Configure high-perf socket options
    configure_socket_options(static_cast<uintptr_t>(sock), true);

    // Bind to INADDR_ANY:0 (ConnectEx requirement)
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;
    if (bind(sock, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        total_errors_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Associate with IOCP
    if (!associate_socket(sock)) {
        closesocket(sock);
        return false;
    }

    // Prepare target address
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);

    // Allocate overlapped structure
    auto* ov = alloc_overlapped(IOCPOp::CONNECT, sock);
    store_pending(ov, PendingOp{std::move(cb), nullptr});

    // Issue async connect
    BOOL result = fn_connect_ex_(
        sock,
        reinterpret_cast<sockaddr*>(&target),
        sizeof(target),
        nullptr, 0, nullptr,
        &ov->overlapped
    );

    if (!result && WSAGetLastError() != ERROR_IO_PENDING) {
        take_pending(ov);
        free_overlapped(ov);
        closesocket(sock);
        total_errors_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

// ── Async Send ───────────────────────────────────────────────────────────

bool IOCPEngine::async_send(SOCKET sock, const char* data, uint32_t len, SendCallback cb) {
    if (!running_.load(std::memory_order_acquire)) return false;

    auto* ov = alloc_overlapped(IOCPOp::SEND, sock);

    // Copy data into the overlapped's buffer (up to 4096)
    uint32_t copy_len = (len < sizeof(ov->buffer)) ? len : sizeof(ov->buffer);
    memcpy(ov->buffer, data, copy_len);
    ov->wsa_buf.buf = ov->buffer;
    ov->wsa_buf.len = copy_len;

    store_pending(ov, PendingOp{nullptr, std::move(cb)});

    DWORD sent = 0;
    int result = WSASend(sock, &ov->wsa_buf, 1, &sent, 0,
                         &ov->overlapped, nullptr);

    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        take_pending(ov);
        free_overlapped(ov);
        total_errors_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

// ── Associate socket with IOCP ───────────────────────────────────────────

bool IOCPEngine::associate_socket(SOCKET sock) {
    HANDLE h = CreateIoCompletionPort(
        reinterpret_cast<HANDLE>(sock), iocp_,
        static_cast<ULONG_PTR>(sock), 0);
    if (!h) {
        total_errors_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}

// ── Worker thread ────────────────────────────────────────────────────────

DWORD WINAPI IOCPEngine::worker_thread_proc(LPVOID param) {
    auto* engine = static_cast<IOCPEngine*>(param);
    engine->worker_loop();
    return 0;
}

void IOCPEngine::worker_loop() {
    while (running_.load(std::memory_order_acquire)) {
        DWORD bytes_transferred = 0;
        ULONG_PTR completion_key = 0;
        OVERLAPPED* raw_ov = nullptr;

        BOOL success = GetQueuedCompletionStatus(
            iocp_, &bytes_transferred, &completion_key,
            &raw_ov, 1000  // 1 s timeout to check running_ periodically
        );

        if (!raw_ov) {
            // Timeout or quit signal (completion_key == 0 && raw_ov == nullptr)
            if (!success && GetLastError() == WAIT_TIMEOUT)
                continue;
            break; // Quit signal
        }

        auto* ov = reinterpret_cast<IOCPOverlapped*>(raw_ov);
        ov->bytes_transferred = bytes_transferred;

        PendingOp pending = take_pending(ov);

        switch (ov->op) {
            case IOCPOp::CONNECT: {
                bool ok = success && bytes_transferred >= 0;
                if (ok) {
                    // Update socket context so shutdown/closesocket work properly
                    setsockopt(ov->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT,
                               nullptr, 0);
                    total_connections_.fetch_add(1, std::memory_order_relaxed);
                } else {
                    total_errors_.fetch_add(1, std::memory_order_relaxed);
                }
                if (pending.connect_cb)
                    pending.connect_cb(ov->socket, ok);
                break;
            }
            case IOCPOp::SEND: {
                bool ok = success && bytes_transferred > 0;
                if (ok) {
                    total_sends_.fetch_add(1, std::memory_order_relaxed);
                } else {
                    total_errors_.fetch_add(1, std::memory_order_relaxed);
                }
                if (pending.send_cb)
                    pending.send_cb(ov->socket, bytes_transferred, ok);
                break;
            }
            default:
                break;
        }

        free_overlapped(ov);
    }
}

// ── ConnectEx loader ─────────────────────────────────────────────────────

bool IOCPEngine::load_connect_ex() {
    // We need a temporary socket to load the function pointer
    SOCKET temp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (temp == INVALID_SOCKET) return false;

    GUID guid = WSAID_CONNECTEX;
    DWORD bytes = 0;
    int result = WSAIoctl(
        temp, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid, sizeof(guid),
        &fn_connect_ex_, sizeof(fn_connect_ex_),
        &bytes, nullptr, nullptr
    );

    closesocket(temp);
    return result == 0;
}

// ── Overlapped allocation ────────────────────────────────────────────────

IOCPOverlapped* IOCPEngine::alloc_overlapped(IOCPOp op, SOCKET sock) {
    auto* ov = new IOCPOverlapped();
    ZeroMemory(&ov->overlapped, sizeof(OVERLAPPED));
    ov->op = op;
    ov->socket = sock;
    ov->bytes_transferred = 0;
    ov->wsa_buf.buf = ov->buffer;
    ov->wsa_buf.len = sizeof(ov->buffer);
    return ov;
}

void IOCPEngine::free_overlapped(IOCPOverlapped* ov) {
    delete ov;
}

// ── Pending operations ───────────────────────────────────────────────────

void IOCPEngine::store_pending(IOCPOverlapped* ov, PendingOp&& op) {
    EnterCriticalSection(&pending_lock_);
    pending_ops_[ov] = std::move(op);
    LeaveCriticalSection(&pending_lock_);
}

IOCPEngine::PendingOp IOCPEngine::take_pending(IOCPOverlapped* ov) {
    PendingOp result;
    EnterCriticalSection(&pending_lock_);
    auto it = pending_ops_.find(ov);
    if (it != pending_ops_.end()) {
        result = std::move(it->second);
        pending_ops_.erase(it);
    }
    LeaveCriticalSection(&pending_lock_);
    return result;
}

} // namespace laitoxx

#endif // _WIN32
