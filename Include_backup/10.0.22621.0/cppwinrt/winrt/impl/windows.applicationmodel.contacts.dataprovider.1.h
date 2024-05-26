// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Contacts_DataProvider_1_H
#define WINRT_Windows_ApplicationModel_Contacts_DataProvider_1_H
#include "winrt/impl/Windows.ApplicationModel.Contacts.DataProvider.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::DataProvider
{
    struct __declspec(empty_bases) IContactDataProviderConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactDataProviderConnection>
    {
        IContactDataProviderConnection(std::nullptr_t = nullptr) noexcept {}
        IContactDataProviderConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactDataProviderConnection2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactDataProviderConnection2>
    {
        IContactDataProviderConnection2(std::nullptr_t = nullptr) noexcept {}
        IContactDataProviderConnection2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactDataProviderTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactDataProviderTriggerDetails>
    {
        IContactDataProviderTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IContactDataProviderTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListCreateOrUpdateContactRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListCreateOrUpdateContactRequest>
    {
        IContactListCreateOrUpdateContactRequest(std::nullptr_t = nullptr) noexcept {}
        IContactListCreateOrUpdateContactRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListCreateOrUpdateContactRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListCreateOrUpdateContactRequestEventArgs>
    {
        IContactListCreateOrUpdateContactRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactListCreateOrUpdateContactRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListDeleteContactRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListDeleteContactRequest>
    {
        IContactListDeleteContactRequest(std::nullptr_t = nullptr) noexcept {}
        IContactListDeleteContactRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListDeleteContactRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListDeleteContactRequestEventArgs>
    {
        IContactListDeleteContactRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactListDeleteContactRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListServerSearchReadBatchRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListServerSearchReadBatchRequest>
    {
        IContactListServerSearchReadBatchRequest(std::nullptr_t = nullptr) noexcept {}
        IContactListServerSearchReadBatchRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListServerSearchReadBatchRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListServerSearchReadBatchRequestEventArgs>
    {
        IContactListServerSearchReadBatchRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactListServerSearchReadBatchRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListSyncManagerSyncRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListSyncManagerSyncRequest>
    {
        IContactListSyncManagerSyncRequest(std::nullptr_t = nullptr) noexcept {}
        IContactListSyncManagerSyncRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListSyncManagerSyncRequestEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListSyncManagerSyncRequestEventArgs>
    {
        IContactListSyncManagerSyncRequestEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactListSyncManagerSyncRequestEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
