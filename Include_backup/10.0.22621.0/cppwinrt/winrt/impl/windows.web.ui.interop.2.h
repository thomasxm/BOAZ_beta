// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_UI_Interop_2_H
#define WINRT_Windows_Web_UI_Interop_2_H
#include "winrt/impl/Windows.Web.UI.1.h"
#include "winrt/impl/Windows.Web.UI.Interop.1.h"
WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop
{
    struct __declspec(empty_bases) WebViewControl : winrt::Windows::Web::UI::IWebViewControl,
        impl::require<WebViewControl, winrt::Windows::Web::UI::Interop::IWebViewControlSite, winrt::Windows::Web::UI::IWebViewControl2, winrt::Windows::Web::UI::Interop::IWebViewControlSite2>
    {
        WebViewControl(std::nullptr_t) noexcept {}
        WebViewControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::UI::IWebViewControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebViewControlAcceleratorKeyPressedEventArgs : winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs
    {
        WebViewControlAcceleratorKeyPressedEventArgs(std::nullptr_t) noexcept {}
        WebViewControlAcceleratorKeyPressedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebViewControlMoveFocusRequestedEventArgs : winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs
    {
        WebViewControlMoveFocusRequestedEventArgs(std::nullptr_t) noexcept {}
        WebViewControlMoveFocusRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WebViewControlProcess : winrt::Windows::Web::UI::Interop::IWebViewControlProcess
    {
        WebViewControlProcess(std::nullptr_t) noexcept {}
        WebViewControlProcess(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::UI::Interop::IWebViewControlProcess(ptr, take_ownership_from_abi) {}
        WebViewControlProcess();
        explicit WebViewControlProcess(winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions);
    };
    struct __declspec(empty_bases) WebViewControlProcessOptions : winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions
    {
        WebViewControlProcessOptions(std::nullptr_t) noexcept {}
        WebViewControlProcessOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions(ptr, take_ownership_from_abi) {}
        WebViewControlProcessOptions();
    };
}
#endif
