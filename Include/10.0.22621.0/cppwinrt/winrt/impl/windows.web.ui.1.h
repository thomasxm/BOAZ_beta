// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_UI_1_H
#define WINRT_Windows_Web_UI_1_H
#include "winrt/impl/Windows.Web.UI.0.h"
WINRT_EXPORT namespace winrt::Windows::Web::UI
{
    struct __declspec(empty_bases) IWebViewControl :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControl>
    {
        IWebViewControl(std::nullptr_t = nullptr) noexcept {}
        IWebViewControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControl2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControl2>
    {
        IWebViewControl2(std::nullptr_t = nullptr) noexcept {}
        IWebViewControl2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlContentLoadingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlContentLoadingEventArgs>
    {
        IWebViewControlContentLoadingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlContentLoadingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlDOMContentLoadedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlDOMContentLoadedEventArgs>
    {
        IWebViewControlDOMContentLoadedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlDOMContentLoadedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlDeferredPermissionRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlDeferredPermissionRequest>
    {
        IWebViewControlDeferredPermissionRequest(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlDeferredPermissionRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlLongRunningScriptDetectedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlLongRunningScriptDetectedEventArgs>
    {
        IWebViewControlLongRunningScriptDetectedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlLongRunningScriptDetectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlNavigationCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlNavigationCompletedEventArgs>
    {
        IWebViewControlNavigationCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlNavigationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlNavigationStartingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlNavigationStartingEventArgs>
    {
        IWebViewControlNavigationStartingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlNavigationStartingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlNewWindowRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlNewWindowRequestedEventArgs>
    {
        IWebViewControlNewWindowRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlNewWindowRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlNewWindowRequestedEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlNewWindowRequestedEventArgs2>
    {
        IWebViewControlNewWindowRequestedEventArgs2(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlNewWindowRequestedEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlPermissionRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlPermissionRequest>
    {
        IWebViewControlPermissionRequest(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlPermissionRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlPermissionRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlPermissionRequestedEventArgs>
    {
        IWebViewControlPermissionRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlPermissionRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlScriptNotifyEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlScriptNotifyEventArgs>
    {
        IWebViewControlScriptNotifyEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlScriptNotifyEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlSettings>
    {
        IWebViewControlSettings(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs>
    {
        IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlUnviewableContentIdentifiedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlUnviewableContentIdentifiedEventArgs>
    {
        IWebViewControlUnviewableContentIdentifiedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlUnviewableContentIdentifiedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebViewControlWebResourceRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebViewControlWebResourceRequestedEventArgs>
    {
        IWebViewControlWebResourceRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebViewControlWebResourceRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
