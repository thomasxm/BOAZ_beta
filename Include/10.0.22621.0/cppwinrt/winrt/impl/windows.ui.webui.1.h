// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WebUI_1_H
#define WINRT_Windows_UI_WebUI_1_H
#include "winrt/impl/Windows.Graphics.Printing.0.h"
#include "winrt/impl/Windows.UI.WebUI.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::WebUI
{
    struct __declspec(empty_bases) IActivatedDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IActivatedDeferral>
    {
        IActivatedDeferral(std::nullptr_t = nullptr) noexcept {}
        IActivatedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IActivatedEventArgsDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IActivatedEventArgsDeferral>
    {
        IActivatedEventArgsDeferral(std::nullptr_t = nullptr) noexcept {}
        IActivatedEventArgsDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IActivatedOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IActivatedOperation>
    {
        IActivatedOperation(std::nullptr_t = nullptr) noexcept {}
        IActivatedOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHtmlPrintDocumentSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHtmlPrintDocumentSource>,
        impl::require<winrt::Windows::UI::WebUI::IHtmlPrintDocumentSource, winrt::Windows::Graphics::Printing::IPrintDocumentSource>
    {
        IHtmlPrintDocumentSource(std::nullptr_t = nullptr) noexcept {}
        IHtmlPrintDocumentSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INewWebUIViewCreatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INewWebUIViewCreatedEventArgs>
    {
        INewWebUIViewCreatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INewWebUIViewCreatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIActivationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIActivationStatics>
    {
        IWebUIActivationStatics(std::nullptr_t = nullptr) noexcept {}
        IWebUIActivationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIActivationStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIActivationStatics2>
    {
        IWebUIActivationStatics2(std::nullptr_t = nullptr) noexcept {}
        IWebUIActivationStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIActivationStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIActivationStatics3>
    {
        IWebUIActivationStatics3(std::nullptr_t = nullptr) noexcept {}
        IWebUIActivationStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIActivationStatics4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIActivationStatics4>
    {
        IWebUIActivationStatics4(std::nullptr_t = nullptr) noexcept {}
        IWebUIActivationStatics4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIBackgroundTaskInstance :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIBackgroundTaskInstance>
    {
        IWebUIBackgroundTaskInstance(std::nullptr_t = nullptr) noexcept {}
        IWebUIBackgroundTaskInstance(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIBackgroundTaskInstanceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIBackgroundTaskInstanceStatics>
    {
        IWebUIBackgroundTaskInstanceStatics(std::nullptr_t = nullptr) noexcept {}
        IWebUIBackgroundTaskInstanceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUINavigatedDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUINavigatedDeferral>
    {
        IWebUINavigatedDeferral(std::nullptr_t = nullptr) noexcept {}
        IWebUINavigatedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUINavigatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUINavigatedEventArgs>
    {
        IWebUINavigatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWebUINavigatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUINavigatedOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUINavigatedOperation>
    {
        IWebUINavigatedOperation(std::nullptr_t = nullptr) noexcept {}
        IWebUINavigatedOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIView :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIView>
    {
        IWebUIView(std::nullptr_t = nullptr) noexcept {}
        IWebUIView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebUIViewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebUIViewStatics>
    {
        IWebUIViewStatics(std::nullptr_t = nullptr) noexcept {}
        IWebUIViewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
