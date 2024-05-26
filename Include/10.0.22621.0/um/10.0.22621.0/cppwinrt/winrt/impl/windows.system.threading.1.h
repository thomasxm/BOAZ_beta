// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Threading_1_H
#define WINRT_Windows_System_Threading_1_H
#include "winrt/impl/Windows.System.Threading.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Threading
{
    struct __declspec(empty_bases) IThreadPoolStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IThreadPoolStatics>
    {
        IThreadPoolStatics(std::nullptr_t = nullptr) noexcept {}
        IThreadPoolStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IThreadPoolTimer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IThreadPoolTimer>
    {
        IThreadPoolTimer(std::nullptr_t = nullptr) noexcept {}
        IThreadPoolTimer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IThreadPoolTimerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IThreadPoolTimerStatics>
    {
        IThreadPoolTimerStatics(std::nullptr_t = nullptr) noexcept {}
        IThreadPoolTimerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
