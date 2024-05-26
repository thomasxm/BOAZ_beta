// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WebUI_Core_1_H
#define WINRT_Windows_UI_WebUI_Core_1_H
#include "winrt/impl/Windows.UI.WebUI.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::WebUI::Core
{
    struct __declspec(empty_bases) IWebUICommandBar :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBar>
    {
        IWebUICommandBar(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBar(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarBitmapIcon :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarBitmapIcon>,
        impl::require<winrt::Windows::UI::WebUI::Core::IWebUICommandBarBitmapIcon, winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>
    {
        IWebUICommandBarBitmapIcon(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarBitmapIcon(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarBitmapIconFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarBitmapIconFactory>
    {
        IWebUICommandBarBitmapIconFactory(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarBitmapIconFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarConfirmationButton :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarConfirmationButton>,
        impl::require<winrt::Windows::UI::WebUI::Core::IWebUICommandBarConfirmationButton, winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>
    {
        IWebUICommandBarConfirmationButton(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarConfirmationButton(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarElement :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarElement>
    {
        IWebUICommandBarElement(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarIcon :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarIcon>
    {
        IWebUICommandBarIcon(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarIcon(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarIconButton :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarIconButton>,
        impl::require<winrt::Windows::UI::WebUI::Core::IWebUICommandBarIconButton, winrt::Windows::UI::WebUI::Core::IWebUICommandBarElement>
    {
        IWebUICommandBarIconButton(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarIconButton(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarItemInvokedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarItemInvokedEventArgs>
    {
        IWebUICommandBarItemInvokedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarItemInvokedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarSizeChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarSizeChangedEventArgs>
    {
        IWebUICommandBarSizeChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarSizeChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarStatics>
    {
        IWebUICommandBarStatics(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarSymbolIcon :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarSymbolIcon>,
        impl::require<winrt::Windows::UI::WebUI::Core::IWebUICommandBarSymbolIcon, winrt::Windows::UI::WebUI::Core::IWebUICommandBarIcon>
    {
        IWebUICommandBarSymbolIcon(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarSymbolIcon(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUICommandBarSymbolIconFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUICommandBarSymbolIconFactory>
    {
        IWebUICommandBarSymbolIconFactory(std::nullptr_t = nullptr) noexcept {}
        IWebUICommandBarSymbolIconFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
