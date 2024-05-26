// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_1_H
#define WINRT_Windows_System_RemoteDesktop_1_H
#include "winrt/impl/Windows.System.RemoteDesktop.0.h"
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop
{
    struct __declspec(empty_bases) IInteractiveSessionStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInteractiveSessionStatics>
    {
        IInteractiveSessionStatics(std::nullptr_t = nullptr) noexcept {}
        IInteractiveSessionStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
