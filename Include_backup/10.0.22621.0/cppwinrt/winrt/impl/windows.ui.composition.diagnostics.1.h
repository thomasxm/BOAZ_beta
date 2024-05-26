// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Diagnostics_1_H
#define WINRT_Windows_UI_Composition_Diagnostics_1_H
#include "winrt/impl/Windows.UI.Composition.Diagnostics.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics
{
    struct __declspec(empty_bases) ICompositionDebugHeatMaps :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompositionDebugHeatMaps>
    {
        ICompositionDebugHeatMaps(std::nullptr_t = nullptr) noexcept {}
        ICompositionDebugHeatMaps(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICompositionDebugSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompositionDebugSettings>
    {
        ICompositionDebugSettings(std::nullptr_t = nullptr) noexcept {}
        ICompositionDebugSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICompositionDebugSettingsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompositionDebugSettingsStatics>
    {
        ICompositionDebugSettingsStatics(std::nullptr_t = nullptr) noexcept {}
        ICompositionDebugSettingsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
