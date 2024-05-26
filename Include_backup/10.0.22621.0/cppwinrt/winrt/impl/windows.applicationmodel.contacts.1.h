// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Contacts_1_H
#define WINRT_Windows_ApplicationModel_Contacts_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts
{
    struct __declspec(empty_bases) IAggregateContactManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAggregateContactManager>
    {
        IAggregateContactManager(std::nullptr_t = nullptr) noexcept {}
        IAggregateContactManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAggregateContactManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAggregateContactManager2>
    {
        IAggregateContactManager2(std::nullptr_t = nullptr) noexcept {}
        IAggregateContactManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContact :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContact>
    {
        IContact(std::nullptr_t = nullptr) noexcept {}
        IContact(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContact2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContact2>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContact2, winrt::Windows::ApplicationModel::Contacts::IContact>
    {
        IContact2(std::nullptr_t = nullptr) noexcept {}
        IContact2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContact3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContact3>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContact3, winrt::Windows::ApplicationModel::Contacts::IContact, winrt::Windows::ApplicationModel::Contacts::IContact2>
    {
        IContact3(std::nullptr_t = nullptr) noexcept {}
        IContact3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactAddress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactAddress>
    {
        IContactAddress(std::nullptr_t = nullptr) noexcept {}
        IContactAddress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactAnnotation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactAnnotation>
    {
        IContactAnnotation(std::nullptr_t = nullptr) noexcept {}
        IContactAnnotation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactAnnotation2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactAnnotation2>
    {
        IContactAnnotation2(std::nullptr_t = nullptr) noexcept {}
        IContactAnnotation2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactAnnotationList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactAnnotationList>
    {
        IContactAnnotationList(std::nullptr_t = nullptr) noexcept {}
        IContactAnnotationList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactAnnotationStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactAnnotationStore>
    {
        IContactAnnotationStore(std::nullptr_t = nullptr) noexcept {}
        IContactAnnotationStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactAnnotationStore2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactAnnotationStore2>
    {
        IContactAnnotationStore2(std::nullptr_t = nullptr) noexcept {}
        IContactAnnotationStore2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactBatch :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactBatch>
    {
        IContactBatch(std::nullptr_t = nullptr) noexcept {}
        IContactBatch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactCardDelayedDataLoader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactCardDelayedDataLoader>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader, winrt::Windows::Foundation::IClosable>
    {
        IContactCardDelayedDataLoader(std::nullptr_t = nullptr) noexcept {}
        IContactCardDelayedDataLoader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactCardOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactCardOptions>
    {
        IContactCardOptions(std::nullptr_t = nullptr) noexcept {}
        IContactCardOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactCardOptions2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactCardOptions2>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2, winrt::Windows::ApplicationModel::Contacts::IContactCardOptions>
    {
        IContactCardOptions2(std::nullptr_t = nullptr) noexcept {}
        IContactCardOptions2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactChange :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactChange>
    {
        IContactChange(std::nullptr_t = nullptr) noexcept {}
        IContactChange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactChangeReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactChangeReader>
    {
        IContactChangeReader(std::nullptr_t = nullptr) noexcept {}
        IContactChangeReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactChangeTracker :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactChangeTracker>
    {
        IContactChangeTracker(std::nullptr_t = nullptr) noexcept {}
        IContactChangeTracker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactChangeTracker2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactChangeTracker2>
    {
        IContactChangeTracker2(std::nullptr_t = nullptr) noexcept {}
        IContactChangeTracker2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactChangedDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactChangedDeferral>
    {
        IContactChangedDeferral(std::nullptr_t = nullptr) noexcept {}
        IContactChangedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactChangedEventArgs>
    {
        IContactChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactConnectedServiceAccount :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactConnectedServiceAccount>
    {
        IContactConnectedServiceAccount(std::nullptr_t = nullptr) noexcept {}
        IContactConnectedServiceAccount(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactDate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactDate>
    {
        IContactDate(std::nullptr_t = nullptr) noexcept {}
        IContactDate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactEmail :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactEmail>
    {
        IContactEmail(std::nullptr_t = nullptr) noexcept {}
        IContactEmail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactField :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactField>
    {
        IContactField(std::nullptr_t = nullptr) noexcept {}
        IContactField(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactFieldFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactFieldFactory>
    {
        IContactFieldFactory(std::nullptr_t = nullptr) noexcept {}
        IContactFieldFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactGroup>
    {
        IContactGroup(std::nullptr_t = nullptr) noexcept {}
        IContactGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactInformation>
    {
        IContactInformation(std::nullptr_t = nullptr) noexcept {}
        IContactInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactInstantMessageField :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactInstantMessageField>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField, winrt::Windows::ApplicationModel::Contacts::IContactField>
    {
        IContactInstantMessageField(std::nullptr_t = nullptr) noexcept {}
        IContactInstantMessageField(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactInstantMessageFieldFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactInstantMessageFieldFactory>
    {
        IContactInstantMessageFieldFactory(std::nullptr_t = nullptr) noexcept {}
        IContactInstantMessageFieldFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactJobInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactJobInfo>
    {
        IContactJobInfo(std::nullptr_t = nullptr) noexcept {}
        IContactJobInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactLaunchActionVerbsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactLaunchActionVerbsStatics>
    {
        IContactLaunchActionVerbsStatics(std::nullptr_t = nullptr) noexcept {}
        IContactLaunchActionVerbsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactList>
    {
        IContactList(std::nullptr_t = nullptr) noexcept {}
        IContactList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactList2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactList2>
    {
        IContactList2(std::nullptr_t = nullptr) noexcept {}
        IContactList2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactList3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactList3>
    {
        IContactList3(std::nullptr_t = nullptr) noexcept {}
        IContactList3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListLimitedWriteOperations :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListLimitedWriteOperations>
    {
        IContactListLimitedWriteOperations(std::nullptr_t = nullptr) noexcept {}
        IContactListLimitedWriteOperations(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListSyncConstraints :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListSyncConstraints>
    {
        IContactListSyncConstraints(std::nullptr_t = nullptr) noexcept {}
        IContactListSyncConstraints(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListSyncManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListSyncManager>
    {
        IContactListSyncManager(std::nullptr_t = nullptr) noexcept {}
        IContactListSyncManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactListSyncManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactListSyncManager2>
    {
        IContactListSyncManager2(std::nullptr_t = nullptr) noexcept {}
        IContactListSyncManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactLocationField :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactLocationField>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactLocationField, winrt::Windows::ApplicationModel::Contacts::IContactField>
    {
        IContactLocationField(std::nullptr_t = nullptr) noexcept {}
        IContactLocationField(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactLocationFieldFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactLocationFieldFactory>
    {
        IContactLocationFieldFactory(std::nullptr_t = nullptr) noexcept {}
        IContactLocationFieldFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactManagerForUser :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerForUser>
    {
        IContactManagerForUser(std::nullptr_t = nullptr) noexcept {}
        IContactManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactManagerForUser2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerForUser2>
    {
        IContactManagerForUser2(std::nullptr_t = nullptr) noexcept {}
        IContactManagerForUser2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerStatics>
    {
        IContactManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IContactManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerStatics2>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics>
    {
        IContactManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IContactManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactManagerStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerStatics3>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2>
    {
        IContactManagerStatics3(std::nullptr_t = nullptr) noexcept {}
        IContactManagerStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IContactManagerStatics3, IContactManagerStatics3>::RequestStoreAsync;
        using impl::consume_t<IContactManagerStatics3, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2>::RequestStoreAsync;
        using impl::consume_t<IContactManagerStatics3, IContactManagerStatics3>::ShowContactCard;
        using impl::consume_t<IContactManagerStatics3, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics>::ShowContactCard;
        using impl::consume_t<IContactManagerStatics3, IContactManagerStatics3>::ShowDelayLoadedContactCard;
        using impl::consume_t<IContactManagerStatics3, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics>::ShowDelayLoadedContactCard;
    };
    struct __declspec(empty_bases) IContactManagerStatics4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerStatics4>
    {
        IContactManagerStatics4(std::nullptr_t = nullptr) noexcept {}
        IContactManagerStatics4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactManagerStatics5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactManagerStatics5>
    {
        IContactManagerStatics5(std::nullptr_t = nullptr) noexcept {}
        IContactManagerStatics5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactMatchReason :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactMatchReason>
    {
        IContactMatchReason(std::nullptr_t = nullptr) noexcept {}
        IContactMatchReason(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactName :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactName>
    {
        IContactName(std::nullptr_t = nullptr) noexcept {}
        IContactName(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPanel :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPanel>
    {
        IContactPanel(std::nullptr_t = nullptr) noexcept {}
        IContactPanel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPanelClosingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPanelClosingEventArgs>
    {
        IContactPanelClosingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactPanelClosingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPanelLaunchFullAppRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPanelLaunchFullAppRequestedEventArgs>
    {
        IContactPanelLaunchFullAppRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactPanelLaunchFullAppRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPhone :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPhone>
    {
        IContactPhone(std::nullptr_t = nullptr) noexcept {}
        IContactPhone(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPicker :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPicker>
    {
        IContactPicker(std::nullptr_t = nullptr) noexcept {}
        IContactPicker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPicker2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPicker2>
    {
        IContactPicker2(std::nullptr_t = nullptr) noexcept {}
        IContactPicker2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPicker3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPicker3>
    {
        IContactPicker3(std::nullptr_t = nullptr) noexcept {}
        IContactPicker3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPickerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPickerStatics>
    {
        IContactPickerStatics(std::nullptr_t = nullptr) noexcept {}
        IContactPickerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactQueryOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactQueryOptions>
    {
        IContactQueryOptions(std::nullptr_t = nullptr) noexcept {}
        IContactQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactQueryOptionsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactQueryOptionsFactory>
    {
        IContactQueryOptionsFactory(std::nullptr_t = nullptr) noexcept {}
        IContactQueryOptionsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactQueryTextSearch :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactQueryTextSearch>
    {
        IContactQueryTextSearch(std::nullptr_t = nullptr) noexcept {}
        IContactQueryTextSearch(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactReader>
    {
        IContactReader(std::nullptr_t = nullptr) noexcept {}
        IContactReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactSignificantOther :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactSignificantOther>
    {
        IContactSignificantOther(std::nullptr_t = nullptr) noexcept {}
        IContactSignificantOther(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactSignificantOther2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactSignificantOther2>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2, winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther>
    {
        IContactSignificantOther2(std::nullptr_t = nullptr) noexcept {}
        IContactSignificantOther2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactStore>
    {
        IContactStore(std::nullptr_t = nullptr) noexcept {}
        IContactStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactStore2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactStore2>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactStore2, winrt::Windows::ApplicationModel::Contacts::IContactStore>
    {
        IContactStore2(std::nullptr_t = nullptr) noexcept {}
        IContactStore2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactStore3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactStore3>
    {
        IContactStore3(std::nullptr_t = nullptr) noexcept {}
        IContactStore3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactStoreNotificationTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactStoreNotificationTriggerDetails>
    {
        IContactStoreNotificationTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IContactStoreNotificationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactWebsite :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactWebsite>
    {
        IContactWebsite(std::nullptr_t = nullptr) noexcept {}
        IContactWebsite(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactWebsite2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactWebsite2>,
        impl::require<winrt::Windows::ApplicationModel::Contacts::IContactWebsite2, winrt::Windows::ApplicationModel::Contacts::IContactWebsite>
    {
        IContactWebsite2(std::nullptr_t = nullptr) noexcept {}
        IContactWebsite2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFullContactCardOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFullContactCardOptions>
    {
        IFullContactCardOptions(std::nullptr_t = nullptr) noexcept {}
        IFullContactCardOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKnownContactFieldStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKnownContactFieldStatics>
    {
        IKnownContactFieldStatics(std::nullptr_t = nullptr) noexcept {}
        IKnownContactFieldStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPinnedContactIdsQueryResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPinnedContactIdsQueryResult>
    {
        IPinnedContactIdsQueryResult(std::nullptr_t = nullptr) noexcept {}
        IPinnedContactIdsQueryResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPinnedContactManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPinnedContactManager>
    {
        IPinnedContactManager(std::nullptr_t = nullptr) noexcept {}
        IPinnedContactManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPinnedContactManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPinnedContactManagerStatics>
    {
        IPinnedContactManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPinnedContactManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
