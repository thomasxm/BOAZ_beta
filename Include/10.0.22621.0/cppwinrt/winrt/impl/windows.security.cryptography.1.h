// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Cryptography_1_H
#define WINRT_Windows_Security_Cryptography_1_H
#include "winrt/impl/Windows.Security.Cryptography.0.h"
WINRT_EXPORT namespace winrt::Windows::Security::Cryptography
{
    struct __declspec(empty_bases) ICryptographicBufferStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICryptographicBufferStatics>
    {
        ICryptographicBufferStatics(std::nullptr_t = nullptr) noexcept {}
        ICryptographicBufferStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
