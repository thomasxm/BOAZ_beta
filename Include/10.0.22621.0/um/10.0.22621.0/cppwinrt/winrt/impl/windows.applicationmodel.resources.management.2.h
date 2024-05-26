// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_Management_2_H
#define WINRT_Windows_ApplicationModel_Resources_Management_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.Management.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Management
{
    struct __declspec(empty_bases) IndexedResourceCandidate : winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate
    {
        IndexedResourceCandidate(std::nullptr_t) noexcept {}
        IndexedResourceCandidate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IndexedResourceQualifier : winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier
    {
        IndexedResourceQualifier(std::nullptr_t) noexcept {}
        IndexedResourceQualifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ResourceIndexer : winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer
    {
        ResourceIndexer(std::nullptr_t) noexcept {}
        ResourceIndexer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer(ptr, take_ownership_from_abi) {}
        explicit ResourceIndexer(winrt::Windows::Foundation::Uri const& projectRoot);
        ResourceIndexer(winrt::Windows::Foundation::Uri const& projectRoot, winrt::Windows::Foundation::Uri const& extensionDllPath);
    };
}
#endif
