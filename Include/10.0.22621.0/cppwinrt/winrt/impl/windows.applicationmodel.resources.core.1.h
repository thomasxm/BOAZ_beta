// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_Core_1_H
#define WINRT_Windows_ApplicationModel_Resources_Core_1_H
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Core
{
    struct __declspec(empty_bases) INamedResource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INamedResource>
    {
        INamedResource(std::nullptr_t = nullptr) noexcept {}
        INamedResource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceCandidate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceCandidate>
    {
        IResourceCandidate(std::nullptr_t = nullptr) noexcept {}
        IResourceCandidate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceCandidate2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceCandidate2>
    {
        IResourceCandidate2(std::nullptr_t = nullptr) noexcept {}
        IResourceCandidate2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceCandidate3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceCandidate3>
    {
        IResourceCandidate3(std::nullptr_t = nullptr) noexcept {}
        IResourceCandidate3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceContext :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceContext>
    {
        IResourceContext(std::nullptr_t = nullptr) noexcept {}
        IResourceContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceContextStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceContextStatics>
    {
        IResourceContextStatics(std::nullptr_t = nullptr) noexcept {}
        IResourceContextStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceContextStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceContextStatics2>
    {
        IResourceContextStatics2(std::nullptr_t = nullptr) noexcept {}
        IResourceContextStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceContextStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceContextStatics3>
    {
        IResourceContextStatics3(std::nullptr_t = nullptr) noexcept {}
        IResourceContextStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceContextStatics4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceContextStatics4>
    {
        IResourceContextStatics4(std::nullptr_t = nullptr) noexcept {}
        IResourceContextStatics4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceManager>
    {
        IResourceManager(std::nullptr_t = nullptr) noexcept {}
        IResourceManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceManager2>
    {
        IResourceManager2(std::nullptr_t = nullptr) noexcept {}
        IResourceManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceManagerStatics>
    {
        IResourceManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IResourceManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceMap :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceMap>,
        impl::require<winrt::Windows::ApplicationModel::Resources::Core::IResourceMap, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::ApplicationModel::Resources::Core::NamedResource>>, winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Resources::Core::NamedResource>>
    {
        IResourceMap(std::nullptr_t = nullptr) noexcept {}
        IResourceMap(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceQualifier :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceQualifier>
    {
        IResourceQualifier(std::nullptr_t = nullptr) noexcept {}
        IResourceQualifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
