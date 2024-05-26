// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_UIAutomation_Core_1_H
#define WINRT_Windows_UI_UIAutomation_Core_1_H
#include "winrt/impl/Windows.UI.UIAutomation.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::UIAutomation::Core
{
    struct __declspec(empty_bases) IAutomationRemoteOperationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAutomationRemoteOperationResult>
    {
        IAutomationRemoteOperationResult(std::nullptr_t = nullptr) noexcept {}
        IAutomationRemoteOperationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAutomationConnectionBoundObjectProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAutomationConnectionBoundObjectProvider>
    {
        ICoreAutomationConnectionBoundObjectProvider(std::nullptr_t = nullptr) noexcept {}
        ICoreAutomationConnectionBoundObjectProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAutomationRegistrarStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAutomationRegistrarStatics>
    {
        ICoreAutomationRegistrarStatics(std::nullptr_t = nullptr) noexcept {}
        ICoreAutomationRegistrarStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAutomationRemoteOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAutomationRemoteOperation>
    {
        ICoreAutomationRemoteOperation(std::nullptr_t = nullptr) noexcept {}
        ICoreAutomationRemoteOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAutomationRemoteOperation2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAutomationRemoteOperation2>
    {
        ICoreAutomationRemoteOperation2(std::nullptr_t = nullptr) noexcept {}
        ICoreAutomationRemoteOperation2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAutomationRemoteOperationContext :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAutomationRemoteOperationContext>
    {
        ICoreAutomationRemoteOperationContext(std::nullptr_t = nullptr) noexcept {}
        ICoreAutomationRemoteOperationContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAutomationRemoteOperationExtensionProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAutomationRemoteOperationExtensionProvider>
    {
        ICoreAutomationRemoteOperationExtensionProvider(std::nullptr_t = nullptr) noexcept {}
        ICoreAutomationRemoteOperationExtensionProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteAutomationClientSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteAutomationClientSession>
    {
        IRemoteAutomationClientSession(std::nullptr_t = nullptr) noexcept {}
        IRemoteAutomationClientSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteAutomationClientSessionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteAutomationClientSessionFactory>
    {
        IRemoteAutomationClientSessionFactory(std::nullptr_t = nullptr) noexcept {}
        IRemoteAutomationClientSessionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteAutomationConnectionRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteAutomationConnectionRequestedEventArgs>
    {
        IRemoteAutomationConnectionRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IRemoteAutomationConnectionRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteAutomationDisconnectedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteAutomationDisconnectedEventArgs>
    {
        IRemoteAutomationDisconnectedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IRemoteAutomationDisconnectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteAutomationServerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteAutomationServerStatics>
    {
        IRemoteAutomationServerStatics(std::nullptr_t = nullptr) noexcept {}
        IRemoteAutomationServerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRemoteAutomationWindow :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRemoteAutomationWindow>
    {
        IRemoteAutomationWindow(std::nullptr_t = nullptr) noexcept {}
        IRemoteAutomationWindow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
