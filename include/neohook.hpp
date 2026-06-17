// NeoHook C++ wrapper for RAII and type safety.
#pragma once
#include "neohook.h"
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace neohook
{
    /**
     * @brief Resolves leading jump stubs/import thunks to the real code address.
     */
    inline void *code_from_pointer(const void *pointer)
    {
        return static_cast<void *>(detours_code_from_pointer(static_cast<const uint8_t *>(pointer)));
    }

    // ----------------- Module / PE introspection -----------------

    /** @brief A module loaded in the current process. */
    struct ModuleInfo
    {
        void *base = nullptr;
        uint32_t size = 0;
        std::string name;
    };

    /** @brief A single entry in a module's Export Address Table. */
    struct ExportInfo
    {
        uint32_t ordinal = 0;
        std::string name;      // empty for ordinal-only exports
        void *address = nullptr;
        std::string forwarder; // non-empty only for forwarded exports
    };

    /** @brief A single imported function in a module's import table. */
    struct ImportInfo
    {
        std::string dll;
        std::string name;                  // empty when imported by ordinal
        uint32_t ordinal = 0xFFFFFFFFu;    // 0xFFFFFFFF when imported by name
        void *address = nullptr;
    };

    namespace detail
    {
        inline std::string from_c(const char *s)
        {
            return s ? std::string(s) : std::string();
        }
    }

    /**
     * @brief Enumerates every module loaded in the calling process.
     */
    inline std::vector<ModuleInfo> enumerate_modules()
    {
        std::vector<ModuleInfo> out;
        void *h = detours_enumerate_modules();
        if (!h)
            return out;

        size_t n = detours_modules_len(h);
        out.reserve(n);
        for (size_t i = 0; i < n; ++i)
        {
            ModuleInfo m;
            m.base = detours_modules_base(h, i);
            m.size = detours_modules_size(h, i);
            m.name = detail::from_c(detours_modules_name(h, i));
            out.push_back(std::move(m));
        }
        detours_modules_free(h);
        return out;
    }

    /**
     * @brief Returns a module's entry point (the main executable's if @p h_module is null).
     */
    inline void *get_entry_point(void *h_module)
    {
        return static_cast<void *>(detours_get_entry_point(h_module));
    }

    /**
     * @brief Enumerates the exports (EAT) of a loaded module.
     */
    inline std::vector<ExportInfo> enumerate_exports(void *h_module)
    {
        std::vector<ExportInfo> out;
        void *h = detours_enumerate_exports(h_module);
        if (!h)
            return out;

        size_t n = detours_exports_len(h);
        out.reserve(n);
        for (size_t i = 0; i < n; ++i)
        {
            ExportInfo e;
            e.ordinal = detours_exports_ordinal(h, i);
            e.name = detail::from_c(detours_exports_name(h, i));
            e.address = const_cast<uint8_t *>(detours_exports_address(h, i));
            e.forwarder = detail::from_c(detours_exports_forwarder(h, i));
            out.push_back(std::move(e));
        }
        detours_exports_free(h);
        return out;
    }

    /**
     * @brief Enumerates the imports of a loaded module across all imported DLLs.
     */
    inline std::vector<ImportInfo> enumerate_imports(void *h_module)
    {
        std::vector<ImportInfo> out;
        void *h = detours_enumerate_imports(h_module);
        if (!h)
            return out;

        size_t n = detours_imports_len(h);
        out.reserve(n);
        for (size_t i = 0; i < n; ++i)
        {
            ImportInfo im;
            im.dll = detail::from_c(detours_imports_dll(h, i));
            im.name = detail::from_c(detours_imports_name(h, i));
            im.ordinal = detours_imports_ordinal(h, i);
            im.address = const_cast<uint8_t *>(detours_imports_address(h, i));
            out.push_back(std::move(im));
        }
        detours_imports_free(h);
        return out;
    }

    /**
     * @brief Resolves an exported function by name, loading the module if needed.
     */
    inline void *find_function(const std::string &module, const std::string &func)
    {
        return const_cast<uint8_t *>(detours_find_function(module.c_str(), func.c_str()));
    }

    /**
     * @brief Resolves an exported function by ordinal, loading the module if needed.
     */
    inline void *find_function(const std::string &module, uint16_t ordinal)
    {
        return const_cast<uint8_t *>(detours_find_function_by_ordinal(module.c_str(), ordinal));
    }

    /**
     * @brief Manages the lifetime of installed hooks.
     *
     * When this object is destroyed, all hooks referenced by the underlying
     * handle are removed automatically.
     */
    class HookGuard
    {
        friend class Transaction;

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

        /**
         * @brief Disables the hook at @p index without unhooking it.
         *
         * Restores the original code/pointer while keeping the hook installed so
         * it can be re-enabled later. Returns true on success.
         */
        bool disable(size_t index)
        {
            return handle_ && detours_handle_set_enabled(handle_, index, 0) != 0;
        }

        /**
         * @brief Re-enables a previously disabled hook at @p index.
         *
         * Returns true on success.
         */
        bool enable(size_t index)
        {
            return handle_ && detours_handle_set_enabled(handle_, index, 1) != 0;
        }

        /**
         * @brief Returns whether the hook at @p index is currently enabled.
         */
        bool is_enabled(size_t index) const
        {
            return handle_ && detours_handle_is_enabled(handle_, index) != 0;
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
         * @brief Queues one hook from an existing HookGuard to be removed on commit.
         */
        void detach(HookGuard &guard, size_t index)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction is no longer valid");

            if (!guard.handle_ || !detours_transaction_detach(tx_, guard.handle_, static_cast<uintptr_t>(index)))
                throw std::runtime_error("NeoHook: Failed to detach hook");
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
         * @brief Queues an EAT (Export Address Table) hook.
         *
         * Redirects the named export of @p h_module for every consumer that
         * resolves it after commit (e.g. via GetProcAddress).
         */
        void attach_eat(void *h_module, const std::string &func, const void *detour)
        {
            if (!tx_)
                throw std::runtime_error("NeoHook: Transaction invalid");

            if (!detours_transaction_attach_eat(tx_, h_module, func.c_str(),
                                                static_cast<const uint8_t *>(detour)))
            {
                throw std::runtime_error("NeoHook: Failed to attach EAT hook");
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

    /**
     * @brief RAII guard for a VEH (hardware-breakpoint) hook.
     *
     * Redirects @p target to @p detour using a CPU hardware breakpoint and a
     * vectored exception handler, without modifying the target's bytes. The
     * breakpoint is cleared on every thread when the guard is destroyed.
     *
     * At most four VEH hooks can be active at once (one per debug register).
     */
    class VehHook
    {
    public:
        VehHook(const void *target, const void *detour)
        {
            hook_ = detours_veh_install(
                static_cast<const uint8_t *>(target),
                static_cast<const uint8_t *>(detour));
            if (!hook_)
                throw std::runtime_error("NeoHook: Failed to install VEH hook");
        }

        ~VehHook()
        {
            if (hook_)
                detours_veh_unhook(hook_);
        }

        VehHook(const VehHook &) = delete;
        VehHook &operator=(const VehHook &) = delete;

        VehHook(VehHook &&other) noexcept : hook_(other.hook_)
        {
            other.hook_ = nullptr;
        }

        VehHook &operator=(VehHook &&other) noexcept
        {
            if (this != &other)
            {
                if (hook_)
                    detours_veh_unhook(hook_);
                hook_ = other.hook_;
                other.hook_ = nullptr;
            }
            return *this;
        }

        /// Removes the hook early. Idempotent.
        void unhook()
        {
            if (hook_)
            {
                detours_veh_unhook(hook_);
                hook_ = nullptr;
            }
        }

    private:
        ::VehHook *hook_ = nullptr;
    };
}
