// NeoHook C++ wrapper for RAII and type safety.
#pragma once
#include "neohook.h"
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>

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

        // No copying
        HookGuard(const HookGuard &) = delete;
        HookGuard &operator=(const HookGuard &) = delete;

        // Move support
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
            return reinterpret_cast<T>(const_cast<uint8_t *>(detours_handle_get_original_ptr(handle_, index)));
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

        ~Transaction()
        {
            if (tx_)
            {
                // If the transaction is still active, abort it to clean up any queued hooks.
                detours_transaction_abort(tx_);
            }
        }

        Transaction(const Transaction &) = delete;
        Transaction &operator=(const Transaction &) = delete;

        Transaction(Transaction &&) = delete;
        Transaction &operator=(Transaction &&) = delete;

        void update_all_threads()
        {
            if (!tx_ || !detours_transaction_update_all_threads(tx_))
            {
                throw std::runtime_error("NeoHook: Failed to update all threads");
            }
        }

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
         * @brief Queues an IAT (Import Address Table) hook.
         */
        void attach_iat(void *h_module, const std::string &dll, const std::string &func, const void *detour)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction invalid");

            if (!detours_transaction_attach_iat(tx_, h_module, dll.c_str(), func.c_str(),
                                                static_cast<const uint8_t *>(detour)))
            {
                throw std::runtime_error("NeoHook: Failed to attach IAT hook");
            }
        }

        /**
         * @brief Queues a VTable hook for the given slot index.
         *
         * @return The original function pointer cast to type T.
         */
        template <typename T>
        T attach_vtable(void **vtable, size_t index, T detour)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction invalid");

            auto *original = detours_transaction_attach_vtable(
                tx_,
                reinterpret_cast<uint8_t **>(vtable),
                static_cast<uintptr_t>(index),
                reinterpret_cast<const uint8_t *>(detour));

            if (!original)
                throw std::runtime_error("NeoHook: Failed to attach VTable hook");

            return reinterpret_cast<T>(original);
        }

        /**
         * @brief Queues a per-instance VTable hook for the given slot index.
         *
         * The object's VTable is cloned so only that instance is affected.
         *
         * @return The original function pointer cast to type T.
         */
        template <typename T>
        T attach_vtable_instance(void **object_vptr, size_t index, size_t vtable_len, T detour)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction invalid");

            auto *original = detours_transaction_attach_vtable_instance(
                tx_,
                reinterpret_cast<uint8_t **>(object_vptr),
                static_cast<uintptr_t>(index),
                static_cast<uintptr_t>(vtable_len),
                reinterpret_cast<const uint8_t *>(detour));

            if (!original)
                throw std::runtime_error("NeoHook: Failed to attach per-instance VTable hook");

            return reinterpret_cast<T>(original);
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

        void abort()
        {
            if (tx_)
            {
                detours_transaction_abort(tx_);
                tx_ = nullptr;
            }
        }

    private:
        DetourTransaction *tx_ = nullptr;
    };
}