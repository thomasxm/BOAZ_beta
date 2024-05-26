// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Preview_Holographic_2_H
#define WINRT_Windows_ApplicationModel_Preview_Holographic_2_H
#include "winrt/impl/Windows.ApplicationModel.Activation.1.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.Holographic.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic
{
    struct HolographicApplicationPreview
    {
        HolographicApplicationPreview() = delete;
        static auto IsCurrentViewPresentedOnHolographicDisplay();
        static auto IsHolographicActivation(winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs const& activatedEventArgs);
    };
    struct __declspec(empty_bases) HolographicKeyboardPlacementOverridePreview : winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview
    {
        HolographicKeyboardPlacementOverridePreview(std::nullptr_t) noexcept {}
        HolographicKeyboardPlacementOverridePreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
}
#endif
