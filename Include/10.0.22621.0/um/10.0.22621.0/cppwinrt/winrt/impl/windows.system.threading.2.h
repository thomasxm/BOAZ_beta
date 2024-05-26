// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Threading_2_H
#define WINRT_Windows_System_Threading_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.Threading.1.h"
WINRT_EXPORT namespace winrt::Windows::System::Threading
{
    struct TimerDestroyedHandler : winrt::Windows::Foundation::IUnknown
    {
        TimerDestroyedHandler(std::nullptr_t = nullptr) noexcept {}
        TimerDestroyedHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> TimerDestroyedHandler(L lambda);
        template <typename F> TimerDestroyedHandler(F* function);
        template <typename O, typename M> TimerDestroyedHandler(O* object, M method);
        template <typename O, typename M> TimerDestroyedHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> TimerDestroyedHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::System::Threading::ThreadPoolTimer const& timer) const;
    };
    struct TimerElapsedHandler : winrt::Windows::Foundation::IUnknown
    {
        TimerElapsedHandler(std::nullptr_t = nullptr) noexcept {}
        TimerElapsedHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> TimerElapsedHandler(L lambda);
        template <typename F> TimerElapsedHandler(F* function);
        template <typename O, typename M> TimerElapsedHandler(O* object, M method);
        template <typename O, typename M> TimerElapsedHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> TimerElapsedHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::System::Threading::ThreadPoolTimer const& timer) const;
    };
    struct WorkItemHandler : winrt::Windows::Foundation::IUnknown
    {
        WorkItemHandler(std::nullptr_t = nullptr) noexcept {}
        WorkItemHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> WorkItemHandler(L lambda);
        template <typename F> WorkItemHandler(F* function);
        template <typename O, typename M> WorkItemHandler(O* object, M method);
        template <typename O, typename M> WorkItemHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> WorkItemHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Foundation::IAsyncAction const& operation) const;
    };
    struct ThreadPool
    {
        ThreadPool() = delete;
        static auto RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler);
        static auto RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler, winrt::Windows::System::Threading::WorkItemPriority const& priority);
        static auto RunAsync(winrt::Windows::System::Threading::WorkItemHandler const& handler, winrt::Windows::System::Threading::WorkItemPriority const& priority, winrt::Windows::System::Threading::WorkItemOptions const& options);
    };
    struct __declspec(empty_bases) ThreadPoolTimer : winrt::Windows::System::Threading::IThreadPoolTimer
    {
        ThreadPoolTimer(std::nullptr_t) noexcept {}
        ThreadPoolTimer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Threading::IThreadPoolTimer(ptr, take_ownership_from_abi) {}
        static auto CreatePeriodicTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& period);
        static auto CreateTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& delay);
        static auto CreatePeriodicTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& period, winrt::Windows::System::Threading::TimerDestroyedHandler const& destroyed);
        static auto CreateTimer(winrt::Windows::System::Threading::TimerElapsedHandler const& handler, winrt::Windows::Foundation::TimeSpan const& delay, winrt::Windows::System::Threading::TimerDestroyedHandler const& destroyed);
    };
}
#endif
