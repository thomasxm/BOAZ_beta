// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Display_1_H
#define WINRT_Windows_System_Display_1_H
#include "winrt/impl/Windows.System.Display.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Display
{
    struct __declspec(empty_bases) IDisplayRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDisplayRequest>
    {
        IDisplayRequest(std::nullptr_t = nullptr) noexcept {}
        IDisplayRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
