// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Implementation_FileExplorer_1_H
#define WINRT_Windows_System_Implementation_FileExplorer_1_H
#include "winrt/impl/Windows.System.Implementation.FileExplorer.0.h"
WINRT_EXPORT namespace winrt::Windows::System::Implementation::FileExplorer
{
    struct __declspec(empty_bases) ISysStorageProviderEventReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISysStorageProviderEventReceivedEventArgs>
    {
        ISysStorageProviderEventReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISysStorageProviderEventReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISysStorageProviderEventReceivedEventArgsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISysStorageProviderEventReceivedEventArgsFactory>
    {
        ISysStorageProviderEventReceivedEventArgsFactory(std::nullptr_t = nullptr) noexcept {}
        ISysStorageProviderEventReceivedEventArgsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISysStorageProviderEventSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISysStorageProviderEventSource>
    {
        ISysStorageProviderEventSource(std::nullptr_t = nullptr) noexcept {}
        ISysStorageProviderEventSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISysStorageProviderHandlerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISysStorageProviderHandlerFactory>
    {
        ISysStorageProviderHandlerFactory(std::nullptr_t = nullptr) noexcept {}
        ISysStorageProviderHandlerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISysStorageProviderHttpRequestProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISysStorageProviderHttpRequestProvider>
    {
        ISysStorageProviderHttpRequestProvider(std::nullptr_t = nullptr) noexcept {}
        ISysStorageProviderHttpRequestProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
