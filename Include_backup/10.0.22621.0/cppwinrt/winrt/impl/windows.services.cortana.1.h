// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Cortana_1_H
#define WINRT_Windows_Services_Cortana_1_H
#include "winrt/impl/Windows.Services.Cortana.0.h"
WINRT_EXPORT namespace winrt::Windows::Services::Cortana
{
    struct __declspec(empty_bases) ICortanaActionableInsights :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaActionableInsights>
    {
        ICortanaActionableInsights(std::nullptr_t = nullptr) noexcept {}
        ICortanaActionableInsights(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICortanaActionableInsightsOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaActionableInsightsOptions>
    {
        ICortanaActionableInsightsOptions(std::nullptr_t = nullptr) noexcept {}
        ICortanaActionableInsightsOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICortanaActionableInsightsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaActionableInsightsStatics>
    {
        ICortanaActionableInsightsStatics(std::nullptr_t = nullptr) noexcept {}
        ICortanaActionableInsightsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICortanaPermissionsManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaPermissionsManager>
    {
        ICortanaPermissionsManager(std::nullptr_t = nullptr) noexcept {}
        ICortanaPermissionsManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICortanaPermissionsManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaPermissionsManagerStatics>
    {
        ICortanaPermissionsManagerStatics(std::nullptr_t = nullptr) noexcept {}
        ICortanaPermissionsManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICortanaSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaSettings>
    {
        ICortanaSettings(std::nullptr_t = nullptr) noexcept {}
        ICortanaSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICortanaSettingsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICortanaSettingsStatics>
    {
        ICortanaSettingsStatics(std::nullptr_t = nullptr) noexcept {}
        ICortanaSettingsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
