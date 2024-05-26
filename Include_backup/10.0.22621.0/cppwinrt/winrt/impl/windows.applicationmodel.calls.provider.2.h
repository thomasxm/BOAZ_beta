// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Calls_Provider_2_H
#define WINRT_Windows_ApplicationModel_Calls_Provider_2_H
#include "winrt/impl/Windows.ApplicationModel.Calls.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Provider
{
    struct __declspec(empty_bases) PhoneCallOrigin : winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin,
        impl::require<PhoneCallOrigin, winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2, winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3>
    {
        PhoneCallOrigin(std::nullptr_t) noexcept {}
        PhoneCallOrigin(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin(ptr, take_ownership_from_abi) {}
        PhoneCallOrigin();
    };
    struct PhoneCallOriginManager
    {
        PhoneCallOriginManager() = delete;
        [[nodiscard]] static auto IsCurrentAppActiveCallOriginApp();
        static auto ShowPhoneCallOriginSettingsUI();
        static auto SetCallOrigin(winrt::guid const& requestId, winrt::Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin const& callOrigin);
        static auto RequestSetAsActiveCallOriginAppAsync();
        [[nodiscard]] static auto IsSupported();
    };
}
#endif
