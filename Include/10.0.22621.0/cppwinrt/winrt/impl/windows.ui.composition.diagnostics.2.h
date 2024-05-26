// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Diagnostics_2_H
#define WINRT_Windows_UI_Composition_Diagnostics_2_H
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.Composition.Diagnostics.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics
{
    struct __declspec(empty_bases) CompositionDebugHeatMaps : winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps
    {
        CompositionDebugHeatMaps(std::nullptr_t) noexcept {}
        CompositionDebugHeatMaps(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CompositionDebugSettings : winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings
    {
        CompositionDebugSettings(std::nullptr_t) noexcept {}
        CompositionDebugSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings(ptr, take_ownership_from_abi) {}
        static auto TryGetSettings(winrt::Windows::UI::Composition::Compositor const& compositor);
    };
}
#endif
