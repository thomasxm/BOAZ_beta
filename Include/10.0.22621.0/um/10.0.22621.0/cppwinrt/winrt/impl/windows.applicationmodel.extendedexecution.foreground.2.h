// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_ExtendedExecution_Foreground_2_H
#define WINRT_Windows_ApplicationModel_ExtendedExecution_Foreground_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.Foreground.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution::Foreground
{
    struct __declspec(empty_bases) ExtendedExecutionForegroundRevokedEventArgs : winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs
    {
        ExtendedExecutionForegroundRevokedEventArgs(std::nullptr_t) noexcept {}
        ExtendedExecutionForegroundRevokedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ExtendedExecutionForegroundSession : winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession
    {
        ExtendedExecutionForegroundSession(std::nullptr_t) noexcept {}
        ExtendedExecutionForegroundSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession(ptr, take_ownership_from_abi) {}
        ExtendedExecutionForegroundSession();
    };
}
#endif
