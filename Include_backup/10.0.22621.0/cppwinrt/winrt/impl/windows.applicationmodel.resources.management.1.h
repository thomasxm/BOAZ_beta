// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_Management_1_H
#define WINRT_Windows_ApplicationModel_Resources_Management_1_H
#include "winrt/impl/Windows.ApplicationModel.Resources.Management.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Management
{
    struct __declspec(empty_bases) IIndexedResourceCandidate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IIndexedResourceCandidate>
    {
        IIndexedResourceCandidate(std::nullptr_t = nullptr) noexcept {}
        IIndexedResourceCandidate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IIndexedResourceQualifier :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IIndexedResourceQualifier>
    {
        IIndexedResourceQualifier(std::nullptr_t = nullptr) noexcept {}
        IIndexedResourceQualifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceIndexer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceIndexer>
    {
        IResourceIndexer(std::nullptr_t = nullptr) noexcept {}
        IResourceIndexer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceIndexerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceIndexerFactory>
    {
        IResourceIndexerFactory(std::nullptr_t = nullptr) noexcept {}
        IResourceIndexerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceIndexerFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceIndexerFactory2>
    {
        IResourceIndexerFactory2(std::nullptr_t = nullptr) noexcept {}
        IResourceIndexerFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
