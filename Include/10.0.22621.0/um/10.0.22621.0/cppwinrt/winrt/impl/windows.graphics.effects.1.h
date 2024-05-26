// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Effects_1_H
#define WINRT_Windows_Graphics_Effects_1_H
#include "winrt/impl/Windows.Graphics.Effects.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Effects
{
    struct __declspec(empty_bases) IGraphicsEffect :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsEffect>,
        impl::require<winrt::Windows::Graphics::Effects::IGraphicsEffect, winrt::Windows::Graphics::Effects::IGraphicsEffectSource>
    {
        IGraphicsEffect(std::nullptr_t = nullptr) noexcept {}
        IGraphicsEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsEffectSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsEffectSource>
    {
        IGraphicsEffectSource(std::nullptr_t = nullptr) noexcept {}
        IGraphicsEffectSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
