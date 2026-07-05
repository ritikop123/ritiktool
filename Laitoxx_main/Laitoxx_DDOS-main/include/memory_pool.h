#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <new>

namespace laitoxx {

/// Lock-free fixed-size memory pool using a Treiber stack (LIFO free-list).
/// Each block is `BlockSize` bytes; the pool pre-allocates `PoolSize` blocks.
/// Thread-safe for concurrent alloc/free from any number of threads.
template <std::size_t BlockSize, std::size_t PoolSize>
class MemoryPool {
public:
    MemoryPool() {
        // Chain all blocks into the free-list
        for (std::size_t i = 0; i < PoolSize - 1; ++i) {
            next(i) = static_cast<uint32_t>(i + 1);
        }
        next(PoolSize - 1) = INVALID;
        head_.store(0, std::memory_order_relaxed);
        alloc_count_.store(0, std::memory_order_relaxed);
    }

    /// Allocate a block. Returns nullptr if the pool is exhausted.
    void* allocate() noexcept {
        uint64_t old_head = head_.load(std::memory_order_acquire);
        while (true) {
            uint32_t idx = index_of(old_head);
            if (idx == INVALID) return nullptr; // pool exhausted

            uint32_t new_idx = next(idx);
            uint64_t new_head = make_head(new_idx, tag_of(old_head) + 1);

            if (head_.compare_exchange_weak(old_head, new_head,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                alloc_count_.fetch_add(1, std::memory_order_relaxed);
                return block_ptr(idx);
            }
        }
    }

    /// Free a block back to the pool.
    void deallocate(void* ptr) noexcept {
        if (!ptr) return;
        auto idx = static_cast<uint32_t>(
            (reinterpret_cast<char*>(ptr) - reinterpret_cast<char*>(storage_.data())) / BlockSize
        );
        if (idx >= PoolSize) return; // not from this pool

        uint64_t old_head = head_.load(std::memory_order_acquire);
        while (true) {
            next(idx) = index_of(old_head);
            uint64_t new_head = make_head(idx, tag_of(old_head) + 1);

            if (head_.compare_exchange_weak(old_head, new_head,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                alloc_count_.fetch_sub(1, std::memory_order_relaxed);
                return;
            }
        }
    }

    /// Number of blocks currently allocated.
    std::size_t allocated() const noexcept {
        return alloc_count_.load(std::memory_order_relaxed);
    }

    /// Blocks available in the pool.
    static constexpr std::size_t capacity() noexcept { return PoolSize; }
    static constexpr std::size_t block_size() noexcept { return BlockSize; }

private:
    static constexpr uint32_t INVALID = 0xFFFFFFFF;

    // Packed head: low 32 bits = index, high 32 bits = ABA tag
    static uint32_t index_of(uint64_t h) { return static_cast<uint32_t>(h & 0xFFFFFFFF); }
    static uint32_t tag_of(uint64_t h)   { return static_cast<uint32_t>(h >> 32); }
    static uint64_t make_head(uint32_t idx, uint32_t tag) {
        return (static_cast<uint64_t>(tag) << 32) | idx;
    }

    char* block_ptr(uint32_t idx) {
        return reinterpret_cast<char*>(storage_.data()) + idx * BlockSize;
    }

    // First 4 bytes of each free block store the next-pointer
    uint32_t& next(uint32_t idx) {
        return *reinterpret_cast<uint32_t*>(block_ptr(idx));
    }

    // Ensure each block is at least sizeof(uint32_t) for the free-list pointer
    static_assert(BlockSize >= sizeof(uint32_t), "BlockSize must be >= 4");

    alignas(64) std::atomic<uint64_t> head_;
    alignas(64) std::atomic<std::size_t> alloc_count_;
    // Raw storage — use std::array of chars sized for all blocks
    alignas(64) std::array<char, BlockSize * PoolSize> storage_;
};

// ── Pre-configured pool types ────────────────────────────────────────────

/// 1 KB packet buffers — 8192 blocks  (8 MB total)
using PacketPool    = MemoryPool<1024, 8192>;

/// 64-byte header scratch buffers — 16384 blocks (1 MB)
using HeaderPool    = MemoryPool<64, 16384>;

/// 4 KB large payload buffers — 2048 blocks (8 MB)
using PayloadPool   = MemoryPool<4096, 2048>;

} // namespace laitoxx
