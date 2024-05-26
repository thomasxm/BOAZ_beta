// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Core_2_H
#define WINRT_Windows_UI_Input_Core_2_H
#include "winrt/impl/Windows.ApplicationModel.Core.1.h"
#include "winrt/impl/Windows.UI.Input.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Core
{
    struct __declspec(empty_bases) RadialControllerIndependentInputSource : winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource,
        impl::require<RadialControllerIndependentInputSource, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>
    {
        RadialControllerIndependentInputSource(std::nullptr_t) noexcept {}
        RadialControllerIndependentInputSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource(ptr, take_ownership_from_abi) {}
        static auto CreateForView(winrt::Windows::ApplicationModel::Core::CoreApplicationView const& view);
    };
}
#endif
