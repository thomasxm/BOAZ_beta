// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_AtomPub_1_H
#define WINRT_Windows_Web_AtomPub_1_H
#include "winrt/impl/Windows.Web.Syndication.0.h"
#include "winrt/impl/Windows.Web.AtomPub.0.h"
WINRT_EXPORT namespace winrt::Windows::Web::AtomPub
{
    struct __declspec(empty_bases) IAtomPubClient :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAtomPubClient>,
        impl::require<winrt::Windows::Web::AtomPub::IAtomPubClient, winrt::Windows::Web::Syndication::ISyndicationClient>
    {
        IAtomPubClient(std::nullptr_t = nullptr) noexcept {}
        IAtomPubClient(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAtomPubClientFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAtomPubClientFactory>
    {
        IAtomPubClientFactory(std::nullptr_t = nullptr) noexcept {}
        IAtomPubClientFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IResourceCollection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IResourceCollection>,
        impl::require<winrt::Windows::Web::AtomPub::IResourceCollection, winrt::Windows::Web::Syndication::ISyndicationNode>
    {
        IResourceCollection(std::nullptr_t = nullptr) noexcept {}
        IResourceCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IServiceDocument :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IServiceDocument>,
        impl::require<winrt::Windows::Web::AtomPub::IServiceDocument, winrt::Windows::Web::Syndication::ISyndicationNode>
    {
        IServiceDocument(std::nullptr_t = nullptr) noexcept {}
        IServiceDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWorkspace :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWorkspace>,
        impl::require<winrt::Windows::Web::AtomPub::IWorkspace, winrt::Windows::Web::Syndication::ISyndicationNode>
    {
        IWorkspace(std::nullptr_t = nullptr) noexcept {}
        IWorkspace(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
