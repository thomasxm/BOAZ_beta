// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Inventory_1_H
#define WINRT_Windows_System_Inventory_1_H
#include "winrt/impl/Windows.System.Inventory.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Inventory
{
    struct __declspec(empty_bases) IInstalledDesktopApp :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInstalledDesktopApp>
    {
        IInstalledDesktopApp(std::nullptr_t = nullptr) noexcept {}
        IInstalledDesktopApp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInstalledDesktopAppStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInstalledDesktopAppStatics>
    {
        IInstalledDesktopAppStatics(std::nullptr_t = nullptr) noexcept {}
        IInstalledDesktopAppStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
