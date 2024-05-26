// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Threading_H
#define WINRT_Windows_System_Threading_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Threading.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_System_Threading_IThreadPoolStatics<D>::RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolStatics)->RunAsync(*(void**)(&handler), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_System_Threading_IThreadPoolStatics<D>::RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler, winrt::Windows::System::Threading::WorkItemPriority const& priority) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolStatics)->RunWithPriorityAsync(*(void**)(&handler), static_cast<int32_t>(priority), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_System_Threading_IThreadPoolStatics<D>::RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler, winrt::Windows::System::Threading::WorkItemPriority const& priority, winrt::Windows::System::Threading::WorkItemOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolStatics)->RunWithPriorityAndOptionsAsync(*(void**)(&handler), static_cast<int32_t>(priority), static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_System_Threading_IThreadPoolTimer<D>::Period() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimer)->get_Period(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_System_Threading_IThreadPoolTimer<D>::Delay() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimer)->get_Delay(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Threading_IThreadPoolTimer<D>::Cancel() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimer)->Cancel());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Threading::ThreadPoolTimer) consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreatePeriodicTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& period) const
    {
        void* timer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimerStatics)->CreatePeriodicTimer(*(void**)(&handler), impl::bind_in(period), &timer));
        return winrt::Windows::System::Threading::ThreadPoolTimer{ timer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Threading::ThreadPoolTimer) consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreateTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& delay) const
    {
        void* timer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimerStatics)->CreateTimer(*(void**)(&handler), impl::bind_in(delay), &timer));
        return winrt::Windows::System::Threading::ThreadPoolTimer{ timer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Threading::ThreadPoolTimer) consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreatePeriodicTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& period, winrt::Windows::System::Threading::TimerDestroyedHandler const& destroyed) const
    {
        void* timer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimerStatics)->CreatePeriodicTimerWithCompletion(*(void**)(&handler), impl::bind_in(period), *(void**)(&destroyed), &timer));
        return winrt::Windows::System::Threading::ThreadPoolTimer{ timer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Threading::ThreadPoolTimer) consume_Windows_System_Threading_IThreadPoolTimerStatics<D>::CreateTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& delay, winrt::Windows::System::Threading::TimerDestroyedHandler const& destroyed) const
    {
        void* timer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Threading::IThreadPoolTimerStatics)->CreateTimerWithCompletion(*(void**)(&handler), impl::bind_in(delay), *(void**)(&destroyed), &timer));
        return winrt::Windows::System::Threading::ThreadPoolTimer{ timer, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::System::Threading::TimerDestroyedHandler, H> final : implements_delegate<winrt::Windows::System::Threading::TimerDestroyedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::System::Threading::TimerDestroyedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* timer) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::System::Threading::ThreadPoolTimer const*>(&timer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::System::Threading::TimerElapsedHandler, H> final : implements_delegate<winrt::Windows::System::Threading::TimerElapsedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::System::Threading::TimerElapsedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* timer) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::System::Threading::ThreadPoolTimer const*>(&timer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::System::Threading::WorkItemHandler, H> final : implements_delegate<winrt::Windows::System::Threading::WorkItemHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::System::Threading::WorkItemHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* operation) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IAsyncAction const*>(&operation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Threading::IThreadPoolStatics> : produce_base<D, winrt::Windows::System::Threading::IThreadPoolStatics>
    {
        int32_t __stdcall RunAsync(void* handler, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<winrt::Windows::System::Threading::WorkItemHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RunWithPriorityAsync(void* handler, int32_t priority, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<winrt::Windows::System::Threading::WorkItemHandler const*>(&handler), *reinterpret_cast<winrt::Windows::System::Threading::WorkItemPriority const*>(&priority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RunWithPriorityAndOptionsAsync(void* handler, int32_t priority, uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<winrt::Windows::System::Threading::WorkItemHandler const*>(&handler), *reinterpret_cast<winrt::Windows::System::Threading::WorkItemPriority const*>(&priority), *reinterpret_cast<winrt::Windows::System::Threading::WorkItemOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Threading::IThreadPoolTimer> : produce_base<D, winrt::Windows::System::Threading::IThreadPoolTimer>
    {
        int32_t __stdcall get_Period(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Delay(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Delay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Cancel() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Threading::IThreadPoolTimerStatics> : produce_base<D, winrt::Windows::System::Threading::IThreadPoolTimerStatics>
    {
        int32_t __stdcall CreatePeriodicTimer(void* handler, int64_t period, void** timer) noexcept final try
        {
            clear_abi(timer);
            typename D::abi_guard guard(this->shim());
            *timer = detach_from<winrt::Windows::System::Threading::ThreadPoolTimer>(this->shim().CreatePeriodicTimer(*reinterpret_cast<winrt::Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&period)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTimer(void* handler, int64_t delay, void** timer) noexcept final try
        {
            clear_abi(timer);
            typename D::abi_guard guard(this->shim());
            *timer = detach_from<winrt::Windows::System::Threading::ThreadPoolTimer>(this->shim().CreateTimer(*reinterpret_cast<winrt::Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&delay)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePeriodicTimerWithCompletion(void* handler, int64_t period, void* destroyed, void** timer) noexcept final try
        {
            clear_abi(timer);
            typename D::abi_guard guard(this->shim());
            *timer = detach_from<winrt::Windows::System::Threading::ThreadPoolTimer>(this->shim().CreatePeriodicTimer(*reinterpret_cast<winrt::Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&period), *reinterpret_cast<winrt::Windows::System::Threading::TimerDestroyedHandler const*>(&destroyed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTimerWithCompletion(void* handler, int64_t delay, void* destroyed, void** timer) noexcept final try
        {
            clear_abi(timer);
            typename D::abi_guard guard(this->shim());
            *timer = detach_from<winrt::Windows::System::Threading::ThreadPoolTimer>(this->shim().CreateTimer(*reinterpret_cast<winrt::Windows::System::Threading::TimerElapsedHandler const*>(&handler), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&delay), *reinterpret_cast<winrt::Windows::System::Threading::TimerDestroyedHandler const*>(&destroyed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Threading
{
    constexpr auto operator|(WorkItemOptions const left, WorkItemOptions const right) noexcept
    {
        return static_cast<WorkItemOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(WorkItemOptions& left, WorkItemOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(WorkItemOptions const left, WorkItemOptions const right) noexcept
    {
        return static_cast<WorkItemOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(WorkItemOptions& left, WorkItemOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(WorkItemOptions const value) noexcept
    {
        return static_cast<WorkItemOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(WorkItemOptions const left, WorkItemOptions const right) noexcept
    {
        return static_cast<WorkItemOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(WorkItemOptions& left, WorkItemOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto ThreadPool::RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler)
    {
        return impl::call_factory<ThreadPool, IThreadPoolStatics>([&](IThreadPoolStatics const& f) { return f.RunAsync(handler); });
    }
    inline auto ThreadPool::RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler, winrt::Windows::System::Threading::WorkItemPriority const& priority)
    {
        return impl::call_factory<ThreadPool, IThreadPoolStatics>([&](IThreadPoolStatics const& f) { return f.RunAsync(handler, priority); });
    }
    inline auto ThreadPool::RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler, winrt::Windows::System::Threading::WorkItemPriority const& priority, winrt::Windows::System::Threading::WorkItemOptions const& options)
    {
        return impl::call_factory<ThreadPool, IThreadPoolStatics>([&](IThreadPoolStatics const& f) { return f.RunAsync(handler, priority, options); });
    }
    inline auto ThreadPoolTimer::CreatePeriodicTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& period)
    {
        return impl::call_factory<ThreadPoolTimer, IThreadPoolTimerStatics>([&](IThreadPoolTimerStatics const& f) { return f.CreatePeriodicTimer(handler, period); });
    }
    inline auto ThreadPoolTimer::CreateTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& delay)
    {
        return impl::call_factory<ThreadPoolTimer, IThreadPoolTimerStatics>([&](IThreadPoolTimerStatics const& f) { return f.CreateTimer(handler, delay); });
    }
    inline auto ThreadPoolTimer::CreatePeriodicTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& period, winrt::Windows::System::Threading::TimerDestroyedHandler const& destroyed)
    {
        return impl::call_factory<ThreadPoolTimer, IThreadPoolTimerStatics>([&](IThreadPoolTimerStatics const& f) { return f.CreatePeriodicTimer(handler, period, destroyed); });
    }
    inline auto ThreadPoolTimer::CreateTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& delay, winrt::Windows::System::Threading::TimerDestroyedHandler const& destroyed)
    {
        return impl::call_factory<ThreadPoolTimer, IThreadPoolTimerStatics>([&](IThreadPoolTimerStatics const& f) { return f.CreateTimer(handler, delay, destroyed); });
    }
    template <typename L> TimerDestroyedHandler::TimerDestroyedHandler(L handler) :
        TimerDestroyedHandler(impl::make_delegate<TimerDestroyedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> TimerDestroyedHandler::TimerDestroyedHandler(F* handler) :
        TimerDestroyedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> TimerDestroyedHandler::TimerDestroyedHandler(O* object, M method) :
        TimerDestroyedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> TimerDestroyedHandler::TimerDestroyedHandler(com_ptr<O>&& object, M method) :
        TimerDestroyedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> TimerDestroyedHandler::TimerDestroyedHandler(weak_ref<O>&& object, M method) :
        TimerDestroyedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto TimerDestroyedHandler::operator()(winrt::Windows::System::Threading::ThreadPoolTimer const& timer) const
    {
        check_hresult((*(impl::abi_t<TimerDestroyedHandler>**)this)->Invoke(*(void**)(&timer)));
    }
    template <typename L> TimerElapsedHandler::TimerElapsedHandler(L handler) :
        TimerElapsedHandler(impl::make_delegate<TimerElapsedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> TimerElapsedHandler::TimerElapsedHandler(F* handler) :
        TimerElapsedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> TimerElapsedHandler::TimerElapsedHandler(O* object, M method) :
        TimerElapsedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> TimerElapsedHandler::TimerElapsedHandler(com_ptr<O>&& object, M method) :
        TimerElapsedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> TimerElapsedHandler::TimerElapsedHandler(weak_ref<O>&& object, M method) :
        TimerElapsedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto TimerElapsedHandler::operator()(winrt::Windows::System::Threading::ThreadPoolTimer const& timer) const
    {
        check_hresult((*(impl::abi_t<TimerElapsedHandler>**)this)->Invoke(*(void**)(&timer)));
    }
    template <typename L> WorkItemHandler::WorkItemHandler(L handler) :
        WorkItemHandler(impl::make_delegate<WorkItemHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> WorkItemHandler::WorkItemHandler(F* handler) :
        WorkItemHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> WorkItemHandler::WorkItemHandler(O* object, M method) :
        WorkItemHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> WorkItemHandler::WorkItemHandler(com_ptr<O>&& object, M method) :
        WorkItemHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> WorkItemHandler::WorkItemHandler(weak_ref<O>&& object, M method) :
        WorkItemHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto WorkItemHandler::operator()(winrt::Windows::Foundation::IAsyncAction const& operation) const
    {
        check_hresult((*(impl::abi_t<WorkItemHandler>**)this)->Invoke(*(void**)(&operation)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Threading::IThreadPoolStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Threading::IThreadPoolTimer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Threading::IThreadPoolTimerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Threading::ThreadPool> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Threading::ThreadPoolTimer> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
