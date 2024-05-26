// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_ViewManagement_Core_2_H
#define WINRT_Windows_UI_ViewManagement_Core_2_H
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.ViewManagement.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement::Core
{
    struct __declspec(empty_bases) CoreFrameworkInputView : winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView
    {
        CoreFrameworkInputView(std::nullptr_t) noexcept {}
        CoreFrameworkInputView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputView(ptr, take_ownership_from_abi) {}
        static auto GetForUIContext(winrt::Windows::UI::UIContext const& context);
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) CoreFrameworkInputViewAnimationStartingEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs
    {
        CoreFrameworkInputViewAnimationStartingEventArgs(std::nullptr_t) noexcept {}
        CoreFrameworkInputViewAnimationStartingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewAnimationStartingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreFrameworkInputViewOcclusionsChangedEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs
    {
        CoreFrameworkInputViewOcclusionsChangedEventArgs(std::nullptr_t) noexcept {}
        CoreFrameworkInputViewOcclusionsChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreFrameworkInputViewOcclusionsChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreInputView : winrt::Windows::UI::ViewManagement::Core::ICoreInputView,
        impl::require<CoreInputView, winrt::Windows::UI::ViewManagement::Core::ICoreInputView2, winrt::Windows::UI::ViewManagement::Core::ICoreInputView3, winrt::Windows::UI::ViewManagement::Core::ICoreInputView4, winrt::Windows::UI::ViewManagement::Core::ICoreInputView5>
    {
        CoreInputView(std::nullptr_t) noexcept {}
        CoreInputView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputView(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
        static auto GetForUIContext(winrt::Windows::UI::UIContext const& context);
    };
    struct __declspec(empty_bases) CoreInputViewAnimationStartingEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs
    {
        CoreInputViewAnimationStartingEventArgs(std::nullptr_t) noexcept {}
        CoreInputViewAnimationStartingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewAnimationStartingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreInputViewHidingEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewHidingEventArgs
    {
        CoreInputViewHidingEventArgs(std::nullptr_t) noexcept {}
        CoreInputViewHidingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewHidingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreInputViewOcclusion : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion
    {
        CoreInputViewOcclusion(std::nullptr_t) noexcept {}
        CoreInputViewOcclusion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreInputViewOcclusionsChangedEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs
    {
        CoreInputViewOcclusionsChangedEventArgs(std::nullptr_t) noexcept {}
        CoreInputViewOcclusionsChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreInputViewShowingEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewShowingEventArgs
    {
        CoreInputViewShowingEventArgs(std::nullptr_t) noexcept {}
        CoreInputViewShowingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewShowingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CoreInputViewTransferringXYFocusEventArgs : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs
    {
        CoreInputViewTransferringXYFocusEventArgs(std::nullptr_t) noexcept {}
        CoreInputViewTransferringXYFocusEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UISettingsController : winrt::Windows::UI::ViewManagement::Core::IUISettingsController
    {
        UISettingsController(std::nullptr_t) noexcept {}
        UISettingsController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::ViewManagement::Core::IUISettingsController(ptr, take_ownership_from_abi) {}
        static auto RequestDefaultAsync();
    };
}
#endif
