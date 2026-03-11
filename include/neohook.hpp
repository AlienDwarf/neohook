#pragma once
#include "neohook.h" // The auto generated C header from neohook
#include <stdexcept>
#include <memory>
#include <cstdint>

namespace neohook
{
    /**
     * @brief Manages the lifetime of installed hooks.
     * When this object is destroyed, all hooks in this handle are removed.
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

        // Ownership management: No copying allowed
        HookGuard(const HookGuard &) = delete;
        HookGuard &operator=(const HookGuard &) = delete;

        // Move semantics: Transfer ownership of hooks
        HookGuard(HookGuard &&other) noexcept : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        size_t count() const
        {
            return handle_ ? static_cast<size_t>(detours_handle_len(handle_)) : 0;
        }

        template <typename T>
        T get_trampoline(size_t index) const
        {
            return reinterpret_cast<T>(detours_handle_get_trampoline(handle_, index));
        }

    private:
        void *handle_;
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

        /**
         * @brief Queues an inline hook.
         * @return The trampoline (original function) pointer cast to type T.
         */
        template <typename T>
        T attach(void *target, T detour)
        {
            uint8_t *tramp = detours_transaction_attach(
                tx_,
                static_cast<uint8_t *>(target),
                reinterpret_cast<const uint8_t *>(detour));

            if (!tramp)
                throw std::runtime_error("NeoHook: Failed to attach hook");

            return reinterpret_cast<T>(tramp);
        }

        /**
         * @brief Atomically applies all queued hooks.
         * @return A HookGuard that restores original code when it goes out of scope.
         */
        HookGuard commit()
        {
            void *handle = detours_transaction_commit(tx_);
            if (!handle)
                throw std::runtime_error("NeoHook: Transaction commit failed");

            tx_ = nullptr; // Rust takes ownership and frees tx during commit
            return HookGuard(handle);
        }

    private:
        DetourTransaction *tx_; // the opaque Type
    };
}