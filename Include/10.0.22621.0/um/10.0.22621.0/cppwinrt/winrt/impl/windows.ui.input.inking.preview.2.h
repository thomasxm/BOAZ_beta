// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_Preview_2_H
#define WINRT_Windows_UI_Input_Inking_Preview_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.Input.Inking.Preview.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Preview
{
    struct __declspec(empty_bases) PalmRejectionDelayZonePreview : winrt::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview,
        impl::require<PalmRejectionDelayZonePreview, winrt::Windows::Foundation::IClosable>
    {
        PalmRejectionDelayZonePreview(std::nullptr_t) noexcept {}
        PalmRejectionDelayZonePreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview(ptr, take_ownership_from_abi) {}
        static auto CreateForVisual(winrt::Windows::UI::Composition::Visual const& inputPanelVisual, winrt::Windows::Foundation::Rect const& inputPanelRect);
        static auto CreateForVisual(winrt::Windows::UI::Composition::Visual const& inputPanelVisual, winrt::Windows::Foundation::Rect const& inputPanelRect, winrt::Windows::UI::Composition::Visual const& viewportVisual, winrt::Windows::Foundation::Rect const& viewportRect);
    };
}
#endif
