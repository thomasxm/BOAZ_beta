// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Power_1_H
#define WINRT_Windows_System_Power_1_H
#include "winrt/impl/Windows.System.Power.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Power
{
    struct __declspec(empty_bases) IBackgroundEnergyManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackgroundEnergyManagerStatics>
    {
        IBackgroundEnergyManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IBackgroundEnergyManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IForegroundEnergyManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IForegroundEnergyManagerStatics>
    {
        IForegroundEnergyManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IForegroundEnergyManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPowerManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPowerManagerStatics>
    {
        IPowerManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPowerManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
