// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Deployment_Preview_2_H
#define WINRT_Windows_Management_Deployment_Preview_2_H
#include "winrt/impl/Windows.Management.Deployment.Preview.1.h"
WINRT_EXPORT namespace winrt::Windows::Management::Deployment::Preview
{
    struct ClassicAppManager
    {
        ClassicAppManager() = delete;
        static auto FindInstalledApp(param::hstring const& appUninstallKey);
    };
    struct __declspec(empty_bases) InstalledClassicAppInfo : winrt::Windows::Management::Deployment::Preview::IInstalledClassicAppInfo
    {
        InstalledClassicAppInfo(std::nullptr_t) noexcept {}
        InstalledClassicAppInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Management::Deployment::Preview::IInstalledClassicAppInfo(ptr, take_ownership_from_abi) {}
    };
}
#endif
