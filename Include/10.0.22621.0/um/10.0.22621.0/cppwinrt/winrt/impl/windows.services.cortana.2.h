// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Services_Cortana_2_H
#define WINRT_Windows_Services_Cortana_2_H
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Services.Cortana.1.h"
WINRT_EXPORT namespace winrt::Windows::Services::Cortana
{
    struct __declspec(empty_bases) CortanaActionableInsights : winrt::Windows::Services::Cortana::ICortanaActionableInsights
    {
        CortanaActionableInsights(std::nullptr_t) noexcept {}
        CortanaActionableInsights(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Cortana::ICortanaActionableInsights(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) CortanaActionableInsightsOptions : winrt::Windows::Services::Cortana::ICortanaActionableInsightsOptions
    {
        CortanaActionableInsightsOptions(std::nullptr_t) noexcept {}
        CortanaActionableInsightsOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Cortana::ICortanaActionableInsightsOptions(ptr, take_ownership_from_abi) {}
        CortanaActionableInsightsOptions();
    };
    struct __declspec(empty_bases) CortanaPermissionsManager : winrt::Windows::Services::Cortana::ICortanaPermissionsManager
    {
        CortanaPermissionsManager(std::nullptr_t) noexcept {}
        CortanaPermissionsManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Cortana::ICortanaPermissionsManager(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
    };
    struct __declspec(empty_bases) CortanaSettings : winrt::Windows::Services::Cortana::ICortanaSettings
    {
        CortanaSettings(std::nullptr_t) noexcept {}
        CortanaSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Services::Cortana::ICortanaSettings(ptr, take_ownership_from_abi) {}
        static auto IsSupported();
        static auto GetDefault();
    };
}
#endif
