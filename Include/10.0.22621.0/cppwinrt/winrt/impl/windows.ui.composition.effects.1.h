// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Effects_1_H
#define WINRT_Windows_UI_Composition_Effects_1_H
#include "winrt/impl/Windows.UI.Composition.Effects.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Effects
{
    struct __declspec(empty_bases) ISceneLightingEffect :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISceneLightingEffect>
    {
        ISceneLightingEffect(std::nullptr_t = nullptr) noexcept {}
        ISceneLightingEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISceneLightingEffect2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISceneLightingEffect2>
    {
        ISceneLightingEffect2(std::nullptr_t = nullptr) noexcept {}
        ISceneLightingEffect2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
