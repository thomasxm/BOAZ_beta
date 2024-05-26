// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_Preview_2_H
#define WINRT_Windows_UI_Core_Preview_2_H
#include "winrt/impl/Windows.UI.WindowManagement.1.h"
#include "winrt/impl/Windows.UI.Core.Preview.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview
{
    struct __declspec(empty_bases) CoreAppWindowPreview : winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview
    {
        CoreAppWindowPreview(std::nullptr_t) noexcept {}
        CoreAppWindowPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview(ptr, take_ownership_from_abi) {}
        static auto GetIdFromWindow(winrt::Windows::UI::WindowManagement::AppWindow const& window);
    };
    struct __declspec(empty_bases) SystemNavigationCloseRequestedPreviewEventArgs : winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs
    {
        SystemNavigationCloseRequestedPreviewEventArgs(std::nullptr_t) noexcept {}
        SystemNavigationCloseRequestedPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemNavigationManagerPreview : winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview
    {
        SystemNavigationManagerPreview(std::nullptr_t) noexcept {}
        SystemNavigationManagerPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
}
#endif
