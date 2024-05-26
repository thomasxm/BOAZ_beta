// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Deployment_Preview_1_H
#define WINRT_Windows_Management_Deployment_Preview_1_H
#include "winrt/impl/Windows.Management.Deployment.Preview.0.h"
WINRT_EXPORT namespace winrt::Windows::Management::Deployment::Preview
{
    struct __declspec(empty_bases) IClassicAppManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IClassicAppManagerStatics>
    {
        IClassicAppManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IClassicAppManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInstalledClassicAppInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInstalledClassicAppInfo>
    {
        IInstalledClassicAppInfo(std::nullptr_t = nullptr) noexcept {}
        IInstalledClassicAppInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
