// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Desktop_2_H
#define WINRT_Windows_UI_Composition_Desktop_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.Composition.Desktop.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop
{
    struct __declspec(empty_bases) DesktopWindowTarget : winrt::Windows::UI::Composition::Desktop::IDesktopWindowTarget,
        impl::base<DesktopWindowTarget, winrt::Windows::UI::Composition::CompositionTarget, winrt::Windows::UI::Composition::CompositionObject>,
        impl::require<DesktopWindowTarget, winrt::Windows::UI::Composition::ICompositionTarget, winrt::Windows::UI::Composition::ICompositionObject, winrt::Windows::UI::Composition::ICompositionObject2, winrt::Windows::UI::Composition::ICompositionObject3, winrt::Windows::UI::Composition::ICompositionObject4, winrt::Windows::UI::Composition::ICompositionObject5, winrt::Windows::Foundation::IClosable, winrt::Windows::UI::Composition::IAnimationObject>
    {
        DesktopWindowTarget(std::nullptr_t) noexcept {}
        DesktopWindowTarget(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Composition::Desktop::IDesktopWindowTarget(ptr, take_ownership_from_abi) {}
        using impl::consume_t<DesktopWindowTarget, winrt::Windows::UI::Composition::ICompositionObject>::StartAnimation;
        using impl::consume_t<DesktopWindowTarget, winrt::Windows::UI::Composition::ICompositionObject5>::StartAnimation;
    };
}
#endif
