// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_ExtendedExecution_2_H
#define WINRT_Windows_ApplicationModel_ExtendedExecution_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution
{
    struct __declspec(empty_bases) ExtendedExecutionRevokedEventArgs : winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs
    {
        ExtendedExecutionRevokedEventArgs(std::nullptr_t) noexcept {}
        ExtendedExecutionRevokedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ExtendedExecutionSession : winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession
    {
        ExtendedExecutionSession(std::nullptr_t) noexcept {}
        ExtendedExecutionSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession(ptr, take_ownership_from_abi) {}
        ExtendedExecutionSession();
    };
}
#endif
