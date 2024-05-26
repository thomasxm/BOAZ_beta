// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Profile_SystemManufacturers_1_H
#define WINRT_Windows_System_Profile_SystemManufacturers_1_H
#include "winrt/impl/Windows.System.Profile.SystemManufacturers.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Profile::SystemManufacturers
{
    struct __declspec(empty_bases) IOemSupportInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IOemSupportInfo>
    {
        IOemSupportInfo(std::nullptr_t = nullptr) noexcept {}
        IOemSupportInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISmbiosInformationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISmbiosInformationStatics>
    {
        ISmbiosInformationStatics(std::nullptr_t = nullptr) noexcept {}
        ISmbiosInformationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemSupportDeviceInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemSupportDeviceInfo>
    {
        ISystemSupportDeviceInfo(std::nullptr_t = nullptr) noexcept {}
        ISystemSupportDeviceInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemSupportInfoStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemSupportInfoStatics>
    {
        ISystemSupportInfoStatics(std::nullptr_t = nullptr) noexcept {}
        ISystemSupportInfoStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemSupportInfoStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemSupportInfoStatics2>
    {
        ISystemSupportInfoStatics2(std::nullptr_t = nullptr) noexcept {}
        ISystemSupportInfoStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
