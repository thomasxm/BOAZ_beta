// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_UI_Interop_1_H
#define WINRT_Windows_Web_UI_Interop_1_H
#include "winrt/impl/Windows.Web.UI.Interop.0.h"
WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop
{
    struct __declspec(empty_bases) IWebViewControlAcceleratorKeyPressedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlAcceleratorKeyPressedEventArgs>
    {
        IWebViewControlAcceleratorKeyPressedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlAcceleratorKeyPressedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlMoveFocusRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlMoveFocusRequestedEventArgs>
    {
        IWebViewControlMoveFocusRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlMoveFocusRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlProcess :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlProcess>
    {
        IWebViewControlProcess(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlProcess(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlProcessFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlProcessFactory>
    {
        IWebViewControlProcessFactory(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlProcessFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlProcessOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlProcessOptions>
    {
        IWebViewControlProcessOptions(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlProcessOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlSite :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlSite>
    {
        IWebViewControlSite(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlSite(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlSite2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlSite2>
    {
        IWebViewControlSite2(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlSite2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
