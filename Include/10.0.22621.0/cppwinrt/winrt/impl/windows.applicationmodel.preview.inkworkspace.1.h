// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Preview_InkWorkspace_1_H
#define WINRT_Windows_ApplicationModel_Preview_InkWorkspace_1_H
#include "winrt/impl/Windows.ApplicationModel.Preview.InkWorkspace.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::InkWorkspace
{
    struct __declspec(empty_bases) IInkWorkspaceHostedAppManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkWorkspaceHostedAppManager>
    {
        IInkWorkspaceHostedAppManager(std::nullptr_t = nullptr) noexcept {}
        IInkWorkspaceHostedAppManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInkWorkspaceHostedAppManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInkWorkspaceHostedAppManagerStatics>
    {
        IInkWorkspaceHostedAppManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IInkWorkspaceHostedAppManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
