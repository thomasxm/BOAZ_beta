// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_1_H
#define WINRT_Windows_Graphics_1_H
#include "winrt/impl/Windows.Graphics.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics
{
    struct __declspec(empty_bases) IGeometrySource2D :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGeometrySource2D>
    {
        IGeometrySource2D(std::nullptr_t = nullptr) noexcept {}
        IGeometrySource2D(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
