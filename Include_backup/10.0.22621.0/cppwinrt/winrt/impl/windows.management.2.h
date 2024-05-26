// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_2_H
#define WINRT_Windows_Management_2_H
#include "winrt/impl/Windows.Management.1.h"
WINRT_EXPORT namespace winrt::Windows::Management
{
    struct __declspec(empty_bases) MdmAlert : winrt::Windows::Management::IMdmAlert
    {
        MdmAlert(std::nullptr_t) noexcept {}
        MdmAlert(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Management::IMdmAlert(ptr, take_ownership_from_abi) {}
        MdmAlert();
    };
    struct __declspec(empty_bases) MdmSession : winrt::Windows::Management::IMdmSession
    {
        MdmSession(std::nullptr_t) noexcept {}
        MdmSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Management::IMdmSession(ptr, take_ownership_from_abi) {}
    };
    struct MdmSessionManager
    {
        MdmSessionManager() = delete;
        [[nodiscard]] static auto SessionIds();
        static auto TryCreateSession();
        static auto DeleteSessionById(param::hstring const& sessionId);
        static auto GetSessionById(param::hstring const& sessionId);
    };
}
#endif
