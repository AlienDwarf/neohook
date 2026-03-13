// NeoHook C++ wrapper for RAII and type safety.
#pragma once
#include "neohook.h"
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace neohook
{
    /**
     * @brief Manages the lifetime of installed hooks.
     *
     * When this object is destroyed, all hooks referenced by the underlying
     * handle are removed automatically.
     */
    class HookGuard
    {
    public:
        explicit HookGuard(void *handle) : handle_(handle) {}

        ~HookGuard()
        {
            if (handle_)
            {
                detours_handle_unhook_and_free(handle_);
            }
        }

        HookGuard(const HookGuard &) = delete;
        HookGuard &operator=(const HookGuard &) = delete;

        HookGuard(HookGuard &&other) noexcept : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        HookGuard &operator=(HookGuard &&other) noexcept
        {
            if (this != &other)
            {
                if (handle_)
                {
                    detours_handle_unhook_and_free(handle_);
                }

                handle_ = other.handle_;
                other.handle_ = nullptr;
            }
            return *this;
        }

        size_t count() const
        {
            return handle_ ? static_cast<size_t>(detours_handle_len(handle_)) : 0;
        }

        /**
         * @brief Returns the original function pointer for the hook at @p index.
         *
         * For inline hooks, this is the trampoline entry.
         * For IAT hooks, this is the original imported function pointer.
         */
        template <typename T>
        T get_original_ptr(size_t index) const
        {
            return reinterpret_cast<T>(detours_handle_get_trampoline(handle_, index));
        }

        /**
         * @brief Backward-compatible alias for get_original_ptr().
         */
        template <typename T>
        T get_trampoline(size_t index) const
        {
            return get_original_ptr<T>(index);
        }

    private:
        void *handle_ = nullptr;
    };

    /**
     * @brief High-level transaction wrapper.
     */
    class Transaction
    {
    public:
        Transaction()
        {
            tx_ = detours_transaction_begin();
            if (!tx_)
                throw std::runtime_error("NeoHook: Failed to begin transaction");
        }

        ~Transaction() = default;

        Transaction(const Transaction &) = delete;
        Transaction &operator=(const Transaction &) = delete;

        Transaction(Transaction &&) = delete;
        Transaction &operator=(Transaction &&) = delete;

        /**
         * @brief Opens, suspends, and tracks the thread identified by @p thread_id.
         *
         * Note: this expects a Win32 thread ID, not a HANDLE.
         */
        void update_thread(uint32_t thread_id)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction is no longer valid");

            if (!detours_transaction_update_thread(tx_, thread_id))
                throw std::runtime_error("NeoHook: Failed to update thread");
        }

        /**
         * @brief Queues an inline hook.
         *
         * @return The original function pointer cast to type T.
         */
        template <typename T>
        T attach(void *target, T detour)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction is no longer valid");

            auto *tramp = detours_transaction_attach(
                tx_,
                static_cast<uint8_t *>(target),
                reinterpret_cast<const uint8_t *>(detour));

            if (!tramp)
                throw std::runtime_error("NeoHook: Failed to attach hook");

            return reinterpret_cast<T>(tramp);
        }

        /**
         * @brief Atomically applies all queued hooks.
         *
         * @return A HookGuard that restores the original state when destroyed.
         */
        HookGuard commit()
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction is no longer valid");

            void *handle = detours_transaction_commit(tx_);
            if (!handle)
                throw std::runtime_error("NeoHook: Transaction commit failed");

            tx_ = nullptr; // Rust takes ownership during commit
            return HookGuard(handle);
        }

    private:
        DetourTransaction *tx_ = nullptr;
    };
}