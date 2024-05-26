// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Contacts_H
#define WINRT_Windows_ApplicationModel_Contacts_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Data.Text.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>) consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::FindRawContactsAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager)->FindRawContactsAsync(*(void**)(&contact), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::TryLinkContactsAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& primaryContact, winrt::Windows::ApplicationModel::Contacts::Contact const& secondaryContact) const
    {
        void* contact{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager)->TryLinkContactsAsync(*(void**)(&primaryContact), *(void**)(&secondaryContact), &contact));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ contact, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::UnlinkRawContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager)->UnlinkRawContactAsync(*(void**)(&contact), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IAggregateContactManager<D>::TrySetPreferredSourceForPictureAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& aggregateContact, winrt::Windows::ApplicationModel::Contacts::Contact const& rawContact) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager)->TrySetPreferredSourceForPictureAsync(*(void**)(&aggregateContact), *(void**)(&rawContact), &value));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IAggregateContactManager2<D>::SetRemoteIdentificationInformationAsync(param::hstring const& contactListId, param::hstring const& remoteSourceId, param::hstring const& accountId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager2)->SetRemoteIdentificationInformationAsync(*(void**)(&contactListId), *(void**)(&remoteSourceId), *(void**)(&accountId), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Contacts_IContact<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact<D>::Thumbnail(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::IContactField>) consume_Windows_ApplicationModel_Contacts_IContact<D>::Fields() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact)->get_Fields(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::IContactField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Notes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_Notes(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Notes(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->put_Notes(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactPhone>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Phones() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_Phones(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactPhone>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactEmail>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Emails() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_Emails(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactEmail>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactAddress>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Addresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_Addresses(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactAddress>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::ConnectedServiceAccounts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_ConnectedServiceAccounts(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactDate>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::ImportantDates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_ImportantDates(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactDate>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::DataSuppliers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_DataSuppliers(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactJobInfo>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::JobInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_JobInfo(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactJobInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactSignificantOther>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::SignificantOthers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_SignificantOthers(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactSignificantOther>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactWebsite>) consume_Windows_ApplicationModel_Contacts_IContact2<D>::Websites() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_Websites(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactWebsite>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_ApplicationModel_Contacts_IContact2<D>::ProviderProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact2)->get_ProviderProperties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::ContactListId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_ContactListId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayPictureUserUpdateTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_DisplayPictureUserUpdateTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayPictureUserUpdateTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_DisplayPictureUserUpdateTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContact3<D>::IsMe() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_IsMe(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::AggregateId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_AggregateId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::RingToneToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_RingToneToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::RingToneToken(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_RingToneToken(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContact3<D>::IsDisplayPictureManuallySet() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_IsDisplayPictureManuallySet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Contacts_IContact3<D>::LargeDisplayPicture() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_LargeDisplayPicture(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Contacts_IContact3<D>::SmallDisplayPicture() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_SmallDisplayPicture(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Contacts_IContact3<D>::SourceDisplayPicture() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_SourceDisplayPicture(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::SourceDisplayPicture(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_SourceDisplayPicture(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::TextToneToken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_TextToneToken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::TextToneToken(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_TextToneToken(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContact3<D>::IsAggregate() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_IsAggregate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::FullName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_FullName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayNameOverride() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_DisplayNameOverride(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::DisplayNameOverride(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_DisplayNameOverride(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::Nickname() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_Nickname(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContact3<D>::Nickname(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->put_Nickname(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContact3<D>::SortName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContact3)->get_SortName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::StreetAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_StreetAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::StreetAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_StreetAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Locality() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_Locality(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Locality(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_Locality(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Region() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_Region(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Region(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_Region(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Country() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_Country(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Country(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_Country(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::PostalCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_PostalCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::PostalCode(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_PostalCode(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactAddressKind) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactAddressKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Kind(winrt::Windows::ApplicationModel::Contacts::ContactAddressKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAddress<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAddress)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::AnnotationListId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_AnnotationListId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::ContactId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_ContactId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::ContactId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->put_ContactId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::RemoteId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_RemoteId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::RemoteId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->put_RemoteId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::SupportedOperations() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_SupportedOperations(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::SupportedOperations(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->put_SupportedOperations(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::IsDisabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_IsDisabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_ApplicationModel_Contacts_IContactAnnotation<D>::ProviderProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation)->get_ProviderProperties(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotation2<D>::ContactListId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2)->get_ContactListId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactAnnotation2<D>::ContactListId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2)->put_ContactListId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::ProviderPackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->get_ProviderPackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::UserDataAccountId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->get_UserDataAccountId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::DeleteAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->DeleteAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::TrySaveAnnotationAsync(winrt::Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const
    {
        void* ppResult{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->TrySaveAnnotationAsync(*(void**)(&annotation), &ppResult));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ ppResult, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::GetAnnotationAsync(param::hstring const& annotationId) const
    {
        void* annotation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->GetAnnotationAsync(*(void**)(&annotationId), &annotation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>{ annotation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::FindAnnotationsByRemoteIdAsync(param::hstring const& remoteId) const
    {
        void* annotations{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->FindAnnotationsByRemoteIdAsync(*(void**)(&remoteId), &annotations));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>{ annotations, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::FindAnnotationsAsync() const
    {
        void* annotations{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->FindAnnotationsAsync(&annotations));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>{ annotations, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactAnnotationList<D>::DeleteAnnotationAsync(winrt::Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList)->DeleteAnnotationAsync(*(void**)(&annotation), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindContactIdsByEmailAsync(param::hstring const& emailAddress) const
    {
        void* contactIds{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindContactIdsByEmailAsync(*(void**)(&emailAddress), &contactIds));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>{ contactIds, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindContactIdsByPhoneNumberAsync(param::hstring const& phoneNumber) const
    {
        void* contactIds{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindContactIdsByPhoneNumberAsync(*(void**)(&phoneNumber), &contactIds));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>{ contactIds, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindAnnotationsForContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* annotations{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindAnnotationsForContactAsync(*(void**)(&contact), &annotations));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>{ annotations, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::DisableAnnotationAsync(winrt::Windows::ApplicationModel::Contacts::ContactAnnotation const& annotation) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->DisableAnnotationAsync(*(void**)(&annotation), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::CreateAnnotationListAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->CreateAnnotationListAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::CreateAnnotationListAsync(param::hstring const& userDataAccountId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->CreateAnnotationListInAccountAsync(*(void**)(&userDataAccountId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::GetAnnotationListAsync(param::hstring const& annotationListId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->GetAnnotationListAsync(*(void**)(&annotationListId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore<D>::FindAnnotationListsAsync() const
    {
        void* lists{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore)->FindAnnotationListsAsync(&lists));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>>{ lists, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>) consume_Windows_ApplicationModel_Contacts_IContactAnnotationStore2<D>::FindAnnotationsForContactListAsync(param::hstring const& contactListId) const
    {
        void* annotations{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore2)->FindAnnotationsForContactListAsync(*(void**)(&contactListId), &annotations));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>{ annotations, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactBatch<D>::Contacts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactBatch)->get_Contacts(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactBatchStatus) consume_Windows_ApplicationModel_Contacts_IContactBatch<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactBatchStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactBatch)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactCardDelayedDataLoader<D>::SetData(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader)->SetData(*(void**)(&contact)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactCardHeaderKind) consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::HeaderKind() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactCardHeaderKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactCardOptions)->get_HeaderKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::HeaderKind(winrt::Windows::ApplicationModel::Contacts::ContactCardHeaderKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactCardOptions)->put_HeaderKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactCardTabKind) consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::InitialTabKind() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactCardTabKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactCardOptions)->get_InitialTabKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactCardOptions<D>::InitialTabKind(winrt::Windows::ApplicationModel::Contacts::ContactCardTabKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactCardOptions)->put_InitialTabKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Contacts_IContactCardOptions2<D>::ServerSearchContactListIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2)->get_ServerSearchContactListIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangeType) consume_Windows_ApplicationModel_Contacts_IContactChange<D>::ChangeType() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactChangeType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChange)->get_ChangeType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::Contact) consume_Windows_ApplicationModel_Contacts_IContactChange<D>::Contact() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChange)->get_Contact(&value));
        return winrt::Windows::ApplicationModel::Contacts::Contact{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>::AcceptChanges() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeReader)->AcceptChanges());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>::AcceptChangesThrough(winrt::Windows::ApplicationModel::Contacts::ContactChange const& lastChangeToAccept) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeReader)->AcceptChangesThrough(*(void**)(&lastChangeToAccept)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactChange>>) consume_Windows_ApplicationModel_Contacts_IContactChangeReader<D>::ReadBatchAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeReader)->ReadBatchAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactChange>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>::Enable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker)->Enable());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangeReader) consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>::GetChangeReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker)->GetChangeReader(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactChangeReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactChangeTracker<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactChangeTracker2<D>::IsTracking() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker2)->get_IsTracking(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactChangedDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangedDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangedDeferral) consume_Windows_ApplicationModel_Contacts_IContactChangedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactChangedEventArgs)->GetDeferral(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactChangedDeferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::ServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->get_ServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactConnectedServiceAccount<D>::ServiceName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount)->put_ServiceName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Day() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->get_Day(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Day(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->put_Day(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Month() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->get_Month(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Month(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->put_Month(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Year() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->get_Year(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Year(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->put_Year(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactDateKind) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactDateKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Kind(winrt::Windows::ApplicationModel::Contacts::ContactDateKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactDate<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactDate)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Address() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactEmail)->get_Address(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Address(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactEmail)->put_Address(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactEmailKind) consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactEmailKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactEmail)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Kind(winrt::Windows::ApplicationModel::Contacts::ContactEmailKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactEmail)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactEmail)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactEmail<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactEmail)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactFieldType) consume_Windows_ApplicationModel_Contacts_IContactField<D>::Type() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactFieldType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactField)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory) consume_Windows_ApplicationModel_Contacts_IContactField<D>::Category() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactField)->get_Category(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactField<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactField)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactField<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactField)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactField) consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>::CreateField(param::hstring const& value, winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory)->CreateField_Default(*(void**)(&value), static_cast<int32_t>(type), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactField) consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>::CreateField(param::hstring const& value, winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory)->CreateField_Category(*(void**)(&value), static_cast<int32_t>(type), static_cast<int32_t>(category), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactField) consume_Windows_ApplicationModel_Contacts_IContactFieldFactory<D>::CreateField(param::hstring const& name, param::hstring const& value, winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory)->CreateField_Custom(*(void**)(&name), *(void**)(&value), static_cast<int32_t>(type), static_cast<int32_t>(category), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::GetThumbnailAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->GetThumbnailAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::Emails() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->get_Emails(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::PhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->get_PhoneNumbers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactLocationField>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::Locations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->get_Locations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactLocationField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::InstantMessages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->get_InstantMessages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::CustomFields() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->get_CustomFields(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>) consume_Windows_ApplicationModel_Contacts_IContactInformation<D>::QueryCustomFields(param::hstring const& customName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInformation)->QueryCustomFields(*(void**)(&customName), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::UserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_UserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::Service() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_Service(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::DisplayText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_DisplayText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageField<D>::LaunchUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField)->get_LaunchUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>::CreateInstantMessage(param::hstring const& userName) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory)->CreateInstantMessage_Default(*(void**)(&userName), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>::CreateInstantMessage(param::hstring const& userName, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory)->CreateInstantMessage_Category(*(void**)(&userName), static_cast<int32_t>(category), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField) consume_Windows_ApplicationModel_Contacts_IContactInstantMessageFieldFactory<D>::CreateInstantMessage(param::hstring const& userName, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& service, param::hstring const& displayText, winrt::Windows::Foundation::Uri const& verb) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory)->CreateInstantMessage_All(*(void**)(&userName), static_cast<int32_t>(category), *(void**)(&service), *(void**)(&displayText), *(void**)(&verb), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_CompanyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_CompanyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyYomiName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_CompanyYomiName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyYomiName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_CompanyYomiName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Department() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Department(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Department(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Department(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Manager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Manager(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Manager(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Manager(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Office() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Office(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Office(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Office(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_CompanyAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::CompanyAddress(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_CompanyAddress(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactJobInfo<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactJobInfo)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Call() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Call(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Map() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Map(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::Post() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_Post(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLaunchActionVerbsStatics<D>::VideoCall() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics)->get_VideoCall(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactList<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactList<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactList<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactList<D>::SourceDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_SourceDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactList<D>::IsHidden() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_IsHidden(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactList<D>::IsHidden(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->put_IsHidden(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess) consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppReadAccess() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_OtherAppReadAccess(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppReadAccess(winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->put_OtherAppReadAccess(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess) consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppWriteAccess() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_OtherAppWriteAccess(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactList<D>::OtherAppWriteAccess(winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->put_OtherAppWriteAccess(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker) consume_Windows_ApplicationModel_Contacts_IContactList<D>::ChangeTracker() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_ChangeTracker(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager) consume_Windows_ApplicationModel_Contacts_IContactList<D>::SyncManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_SyncManager(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactList<D>::SupportsServerSearch() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_SupportsServerSearch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactList<D>::UserDataAccountId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->get_UserDataAccountId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactList, winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
    {
        winrt::event_token returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->add_ContactChanged(*(void**)(&value), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged_revoker consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactList, winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, ContactChanged_revoker>(this, ContactChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactList<D>::ContactChanged(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->remove_ContactChanged(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactList<D>::SaveAsync() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->SaveAsync(&returnValue));
        return winrt::Windows::Foundation::IAsyncAction{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactList<D>::DeleteAsync() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->DeleteAsync(&returnValue));
        return winrt::Windows::Foundation::IAsyncAction{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactFromRemoteIdAsync(param::hstring const& remoteId) const
    {
        void* contact{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->GetContactFromRemoteIdAsync(*(void**)(&remoteId), &contact));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ contact, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetMeContactAsync() const
    {
        void* meContact{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->GetMeContactAsync(&meContact));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ meContact, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactReader) consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->GetContactReader(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactReader) consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactReader(winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions const& options) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->GetContactReaderWithOptions(*(void**)(&options), &value));
        return winrt::Windows::ApplicationModel::Contacts::ContactReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactList<D>::SaveContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->SaveContactAsync(*(void**)(&contact), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactList<D>::DeleteContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->DeleteContactAsync(*(void**)(&contact), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactList<D>::GetContactAsync(param::hstring const& contactId) const
    {
        void* contacts{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList)->GetContactAsync(*(void**)(&contactId), &contacts));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ contacts, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Contacts_IContactList2<D>::RegisterSyncManagerAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList2)->RegisterSyncManagerAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactList2<D>::SupportsServerSearch(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList2)->put_SupportsServerSearch(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactListSyncConstraints) consume_Windows_ApplicationModel_Contacts_IContactList2<D>::SyncConstraints() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList2)->get_SyncConstraints(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactListSyncConstraints{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations) consume_Windows_ApplicationModel_Contacts_IContactList3<D>::LimitedWriteOperations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList3)->get_LimitedWriteOperations(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker) consume_Windows_ApplicationModel_Contacts_IContactList3<D>::GetChangeTracker(param::hstring const& identity) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactList3)->GetChangeTracker(*(void**)(&identity), &result));
        return winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IContactListLimitedWriteOperations<D>::TryCreateOrUpdateContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations)->TryCreateOrUpdateContactAsync(*(void**)(&contact), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IContactListLimitedWriteOperations<D>::TryDeleteContactAsync(param::hstring const& contactId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations)->TryDeleteContactAsync(*(void**)(&contactId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::CanSyncDescriptions() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_CanSyncDescriptions(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::CanSyncDescriptions(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_CanSyncDescriptions(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomePhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxHomePhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomePhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxHomePhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxMobilePhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxMobilePhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxMobilePhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxMobilePhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWorkPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWorkPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPagerPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxPagerPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPagerPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxPagerPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBusinessFaxPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxBusinessFaxPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBusinessFaxPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxBusinessFaxPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeFaxPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxHomeFaxPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeFaxPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxHomeFaxPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxCompanyPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxCompanyPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxCompanyPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxCompanyPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAssistantPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxAssistantPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAssistantPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxAssistantPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxRadioPhoneNumbers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxRadioPhoneNumbers(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxRadioPhoneNumbers(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxRadioPhoneNumbers(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPersonalEmailAddresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxPersonalEmailAddresses(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPersonalEmailAddresses(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxPersonalEmailAddresses(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkEmailAddresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWorkEmailAddresses(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkEmailAddresses(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWorkEmailAddresses(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherEmailAddresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherEmailAddresses(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherEmailAddresses(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherEmailAddresses(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeAddresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxHomeAddresses(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxHomeAddresses(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxHomeAddresses(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkAddresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWorkAddresses(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWorkAddresses(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWorkAddresses(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherAddresses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherAddresses(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherAddresses(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherAddresses(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBirthdayDates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxBirthdayDates(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxBirthdayDates(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxBirthdayDates(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAnniversaryDates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxAnniversaryDates(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxAnniversaryDates(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxAnniversaryDates(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherDates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherDates(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherDates(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherDates(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherRelationships() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxOtherRelationships(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxOtherRelationships(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxOtherRelationships(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSpouseRelationships() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxSpouseRelationships(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSpouseRelationships(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxSpouseRelationships(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPartnerRelationships() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxPartnerRelationships(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxPartnerRelationships(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxPartnerRelationships(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSiblingRelationships() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxSiblingRelationships(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxSiblingRelationships(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxSiblingRelationships(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxParentRelationships() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxParentRelationships(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxParentRelationships(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxParentRelationships(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxChildRelationships() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxChildRelationships(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxChildRelationships(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxChildRelationships(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxJobInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxJobInfo(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxJobInfo(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxJobInfo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWebsites() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->get_MaxWebsites(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncConstraints<D>::MaxWebsites(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints)->put_MaxWebsites(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactListSyncStatus) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactListSyncStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::LastSuccessfulSyncTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager)->get_LastSuccessfulSyncTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::LastAttemptedSyncTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager)->get_LastAttemptedSyncTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager)->SyncAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager)->add_SyncStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged_revoker consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SyncStatusChanged_revoker>(this, SyncStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager<D>::SyncStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager)->remove_SyncStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>::Status(winrt::Windows::ApplicationModel::Contacts::ContactListSyncStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>::LastSuccessfulSyncTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2)->put_LastSuccessfulSyncTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactListSyncManager2<D>::LastAttemptedSyncTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2)->put_LastAttemptedSyncTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::UnstructuredAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationField)->get_UnstructuredAddress(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::Street() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationField)->get_Street(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::City() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationField)->get_City(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::Region() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationField)->get_Region(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::Country() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationField)->get_Country(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactLocationField<D>::PostalCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationField)->get_PostalCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactLocationField) consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>::CreateLocation(param::hstring const& unstructuredAddress) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory)->CreateLocation_Default(*(void**)(&unstructuredAddress), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactLocationField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactLocationField) consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>::CreateLocation(param::hstring const& unstructuredAddress, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory)->CreateLocation_Category(*(void**)(&unstructuredAddress), static_cast<int32_t>(category), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactLocationField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactLocationField) consume_Windows_ApplicationModel_Contacts_IContactLocationFieldFactory<D>::CreateLocation(param::hstring const& unstructuredAddress, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& street, param::hstring const& city, param::hstring const& region, param::hstring const& country, param::hstring const& postalCode) const
    {
        void* field{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory)->CreateLocation_All(*(void**)(&unstructuredAddress), static_cast<int32_t>(category), *(void**)(&street), *(void**)(&city), *(void**)(&region), *(void**)(&country), *(void**)(&postalCode), &field));
        return winrt::Windows::ApplicationModel::Contacts::ContactLocationField{ field, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::ConvertContactToVCardAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->ConvertContactToVCardAsync(*(void**)(&contact), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::ConvertContactToVCardAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->ConvertContactToVCardAsyncWithMaxBytes(*(void**)(&contact), maxBytes, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::ConvertVCardToContactAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& vCard) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->ConvertVCardToContactAsync(*(void**)(&vCard), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::RequestStoreAsync(winrt::Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->RequestStoreAsync(static_cast<int32_t>(accessType), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore>) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::RequestAnnotationStoreAsync(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->RequestAnnotationStoreAsync(static_cast<int32_t>(accessType), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemDisplayNameOrder() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactNameOrder value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->get_SystemDisplayNameOrder(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemDisplayNameOrder(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->put_SystemDisplayNameOrder(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemSortOrder() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactNameOrder value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->get_SystemSortOrder(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::SystemSortOrder(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->put_SystemSortOrder(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerForUser2<D>::ShowFullContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser2)->ShowFullContactCard(*(void**)(&contact), *(void**)(&fullContactCardOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>::ShowContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics)->ShowContactCard(*(void**)(&contact), impl::bind_in(selection)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>::ShowContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics)->ShowContactCardWithPlacement(*(void**)(&contact), impl::bind_in(selection), static_cast<int32_t>(preferredPlacement)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics<D>::ShowDelayLoadedContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement) const
    {
        void* dataLoader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics)->ShowDelayLoadedContactCard(*(void**)(&contact), impl::bind_in(selection), static_cast<int32_t>(preferredPlacement), &dataLoader));
        return winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader{ dataLoader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics2<D>::RequestStoreAsync() const
    {
        void* store{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2)->RequestStoreAsync(&store));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>{ store, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ConvertContactToVCardAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* vCard{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ConvertContactToVCardAsync(*(void**)(&contact), &vCard));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ vCard, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ConvertContactToVCardAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes) const
    {
        void* vCard{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ConvertContactToVCardAsyncWithMaxBytes(*(void**)(&contact), maxBytes, &vCard));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ vCard, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ConvertVCardToContactAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& vCard) const
    {
        void* contact{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ConvertVCardToContactAsync(*(void**)(&vCard), &contact));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ contact, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::RequestStoreAsync(winrt::Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType) const
    {
        void* store{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->RequestStoreAsyncWithAccessType(static_cast<int32_t>(accessType), &store));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>{ store, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::RequestAnnotationStoreAsync(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType) const
    {
        void* store{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->RequestAnnotationStoreAsync(static_cast<int32_t>(accessType), &store));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore>{ store, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::IsShowContactCardSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->IsShowContactCardSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ShowContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement, winrt::Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ShowContactCardWithOptions(*(void**)(&contact), impl::bind_in(selection), static_cast<int32_t>(preferredPlacement), *(void**)(&contactCardOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::IsShowDelayLoadedContactCardSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->IsShowDelayLoadedContactCardSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ShowDelayLoadedContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement, winrt::Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions) const
    {
        void* dataLoader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ShowDelayLoadedContactCardWithOptions(*(void**)(&contact), impl::bind_in(selection), static_cast<int32_t>(preferredPlacement), *(void**)(&contactCardOptions), &dataLoader));
        return winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader{ dataLoader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::ShowFullContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->ShowFullContactCard(*(void**)(&contact), *(void**)(&fullContactCardOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemDisplayNameOrder() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactNameOrder value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->get_SystemDisplayNameOrder(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemDisplayNameOrder(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->put_SystemDisplayNameOrder(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemSortOrder() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactNameOrder value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->get_SystemSortOrder(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics3<D>::SystemSortOrder(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3)->put_SystemSortOrder(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactManagerForUser) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics4<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics4)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::ApplicationModel::Contacts::ContactManagerForUser{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>::IsShowFullContactCardSupportedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5)->IsShowFullContactCardSupportedAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>::IncludeMiddleNameInSystemDisplayAndSort() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5)->get_IncludeMiddleNameInSystemDisplayAndSort(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactManagerStatics5<D>::IncludeMiddleNameInSystemDisplayAndSort(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5)->put_IncludeMiddleNameInSystemDisplayAndSort(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactMatchReasonKind) consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>::Field() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactMatchReasonKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactMatchReason)->get_Field(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::TextSegment>) consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>::Segments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactMatchReason)->get_Segments(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::TextSegment>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactMatchReason<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactMatchReason)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::FirstName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_FirstName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::FirstName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_FirstName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::LastName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_LastName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::LastName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_LastName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::MiddleName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_MiddleName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::MiddleName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_MiddleName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiGivenName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_YomiGivenName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiGivenName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_YomiGivenName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_YomiFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiFamilyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_YomiFamilyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNameSuffix() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_HonorificNameSuffix(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNameSuffix(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_HonorificNameSuffix(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNamePrefix() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_HonorificNamePrefix(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactName<D>::HonorificNamePrefix(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->put_HonorificNamePrefix(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactName<D>::YomiDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactName)->get_YomiDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::ClosePanel() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->ClosePanel());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::HeaderColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->get_HeaderColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::HeaderColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->put_HeaderColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactPanel, winrt::Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->add_LaunchFullAppRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested_revoker consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactPanel, winrt::Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LaunchFullAppRequested_revoker>(this, LaunchFullAppRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::LaunchFullAppRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->remove_LaunchFullAppRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactPanel, winrt::Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->add_Closing(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing_revoker consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactPanel, winrt::Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closing_revoker>(this, Closing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPanel<D>::Closing(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanel)->remove_Closing(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_ApplicationModel_Contacts_IContactPanelClosingEventArgs<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs)->GetDeferral(&deferral));
        return winrt::Windows::Foundation::Deferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactPanelLaunchFullAppRequestedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPanelLaunchFullAppRequestedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Number() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPhone)->get_Number(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Number(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPhone)->put_Number(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactPhoneKind) consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactPhoneKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPhone)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Kind(winrt::Windows::ApplicationModel::Contacts::ContactPhoneKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPhone)->put_Kind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPhone)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPhone<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPhone)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::CommitButtonText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->get_CommitButtonText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::CommitButtonText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->put_CommitButtonText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::SelectionMode() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->get_SelectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::SelectionMode(winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->put_SelectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::DesiredFields() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->get_DesiredFields(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactInformation>) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::PickSingleContactAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->PickSingleContactAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactInformation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactInformation>>) consume_Windows_ApplicationModel_Contacts_IContactPicker<D>::PickMultipleContactsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker)->PickMultipleContactsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactInformation>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>) consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>::DesiredFieldsWithContactFieldType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker2)->get_DesiredFieldsWithContactFieldType(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>::PickContactAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker2)->PickContactAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::Contact>>) consume_Windows_ApplicationModel_Contacts_IContactPicker2<D>::PickContactsAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker2)->PickContactsAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::Contact>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_ApplicationModel_Contacts_IContactPicker3<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPicker3)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactPicker) consume_Windows_ApplicationModel_Contacts_IContactPickerStatics<D>::CreateForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics)->CreateForUser(*(void**)(&user), &result));
        return winrt::Windows::ApplicationModel::Contacts::ContactPicker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IContactPickerStatics<D>::IsSupportedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics)->IsSupportedAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactQueryTextSearch) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::TextSearch() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_TextSearch(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactQueryTextSearch{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::ContactListIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_ContactListIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::IncludeContactsFromHiddenLists() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_IncludeContactsFromHiddenLists(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::IncludeContactsFromHiddenLists(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->put_IncludeContactsFromHiddenLists(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactQueryDesiredFields) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredFields() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactQueryDesiredFields value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_DesiredFields(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredFields(winrt::Windows::ApplicationModel::Contacts::ContactQueryDesiredFields const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->put_DesiredFields(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredOperations() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_DesiredOperations(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::DesiredOperations(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->put_DesiredOperations(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Contacts_IContactQueryOptions<D>::AnnotationListIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions)->get_AnnotationListIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions) consume_Windows_ApplicationModel_Contacts_IContactQueryOptionsFactory<D>::CreateWithText(param::hstring const& text) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory)->CreateWithText(*(void**)(&text), &result));
        return winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions) consume_Windows_ApplicationModel_Contacts_IContactQueryOptionsFactory<D>::CreateWithTextAndFields(param::hstring const& text, winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& fields) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory)->CreateWithTextAndFields(*(void**)(&text), static_cast<uint32_t>(fields), &result));
        return winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields) consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Fields() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->get_Fields(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Fields(winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->put_Fields(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchScope) consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::SearchScope() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchScope value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->get_SearchScope(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactQueryTextSearch<D>::SearchScope(winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchScope const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch)->put_SearchScope(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactBatch>) consume_Windows_ApplicationModel_Contacts_IContactReader<D>::ReadBatchAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactReader)->ReadBatchAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactBatch>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactMatchReason>) consume_Windows_ApplicationModel_Contacts_IContactReader<D>::GetMatchingPropertiesWithMatchReason(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        void* ppRetVal{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactReader)->GetMatchingPropertiesWithMatchReason(*(void**)(&contact), &ppRetVal));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactMatchReason>{ ppRetVal, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactSignificantOther<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactRelationship) consume_Windows_ApplicationModel_Contacts_IContactSignificantOther2<D>::Relationship() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactRelationship value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2)->get_Relationship(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactSignificantOther2<D>::Relationship(winrt::Windows::ApplicationModel::Contacts::ContactRelationship const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2)->put_Relationship(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>) consume_Windows_ApplicationModel_Contacts_IContactStore<D>::FindContactsAsync() const
    {
        void* contacts{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore)->FindContactsAsync(&contacts));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>{ contacts, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>) consume_Windows_ApplicationModel_Contacts_IContactStore<D>::FindContactsAsync(param::hstring const& searchText) const
    {
        void* contacts{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore)->FindContactsWithSearchTextAsync(*(void**)(&searchText), &contacts));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>{ contacts, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactStore<D>::GetContactAsync(param::hstring const& contactId) const
    {
        void* contacts{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore)->GetContactAsync(*(void**)(&contactId), &contacts));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ contacts, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ChangeTracker() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->get_ChangeTracker(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactStore, winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
    {
        winrt::event_token returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->add_ContactChanged(*(void**)(&value), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged_revoker consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactStore, winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, ContactChanged_revoker>(this, ContactChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::ContactChanged(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->remove_ContactChanged(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::AggregateContactManager) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::AggregateContactManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->get_AggregateContactManager(&value));
        return winrt::Windows::ApplicationModel::Contacts::AggregateContactManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactList>>) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::FindContactListsAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->FindContactListsAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactList>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetContactListAsync(param::hstring const& contactListId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->GetContactListAsync(*(void**)(&contactListId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::CreateContactListAsync(param::hstring const& displayName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->CreateContactListAsync(*(void**)(&displayName), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetMeContactAsync() const
    {
        void* meContact{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->GetMeContactAsync(&meContact));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>{ meContact, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactReader) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetContactReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->GetContactReader(&value));
        return winrt::Windows::ApplicationModel::Contacts::ContactReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactReader) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::GetContactReader(winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions const& options) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->GetContactReaderWithOptions(*(void**)(&options), &value));
        return winrt::Windows::ApplicationModel::Contacts::ContactReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>) consume_Windows_ApplicationModel_Contacts_IContactStore2<D>::CreateContactListAsync(param::hstring const& displayName, param::hstring const& userDataAccountId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore2)->CreateContactListInAccountAsync(*(void**)(&displayName), *(void**)(&userDataAccountId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker) consume_Windows_ApplicationModel_Contacts_IContactStore3<D>::GetChangeTracker(param::hstring const& identity) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactStore3)->GetChangeTracker(*(void**)(&identity), &result));
        return winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactWebsite)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Uri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactWebsite)->put_Uri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactWebsite)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactWebsite<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactWebsite)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IContactWebsite2<D>::RawValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactWebsite2)->get_RawValue(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IContactWebsite2<D>::RawValue(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IContactWebsite2)->put_RawValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ViewSizePreference) consume_Windows_ApplicationModel_Contacts_IFullContactCardOptions<D>::DesiredRemainingView() const
    {
        winrt::Windows::UI::ViewManagement::ViewSizePreference value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions)->get_DesiredRemainingView(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IFullContactCardOptions<D>::DesiredRemainingView(winrt::Windows::UI::ViewManagement::ViewSizePreference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions)->put_DesiredRemainingView(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::Email() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_Email(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::PhoneNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_PhoneNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::Location() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_Location(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::InstantMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->get_InstantMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactFieldType) consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::ConvertNameToType(param::hstring const& name) const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactFieldType type{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->ConvertNameToType(*(void**)(&name), reinterpret_cast<int32_t*>(&type)));
        return type;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_IKnownContactFieldStatics<D>::ConvertTypeToName(winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type) const
    {
        void* name{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics)->ConvertTypeToName(static_cast<int32_t>(type), &name));
        return hstring{ name, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_Contacts_IPinnedContactIdsQueryResult<D>::ContactIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult)->get_ContactIds(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::User() const
    {
        void* user{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->get_User(&user));
        return winrt::Windows::System::User{ user, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::IsPinSurfaceSupported(winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->IsPinSurfaceSupported(static_cast<int32_t>(surface), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::IsContactPinned(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->IsContactPinned(*(void**)(&contact), static_cast<int32_t>(surface), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::RequestPinContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->RequestPinContactAsync(*(void**)(&contact), static_cast<int32_t>(surface), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::RequestPinContactsAsync(param::async_iterable<winrt::Windows::ApplicationModel::Contacts::Contact> const& contacts, winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->RequestPinContactsAsync(*(void**)(&contacts), static_cast<int32_t>(surface), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::RequestUnpinContactAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const& surface) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->RequestUnpinContactAsync(*(void**)(&contact), static_cast<int32_t>(surface), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::SignalContactActivity(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->SignalContactActivity(*(void**)(&contact)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>) consume_Windows_ApplicationModel_Contacts_IPinnedContactManager<D>::GetPinnedContactIdsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager)->GetPinnedContactIdsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::PinnedContactManager) consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics)->GetDefault(&result));
        return winrt::Windows::ApplicationModel::Contacts::PinnedContactManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::PinnedContactManager) consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::ApplicationModel::Contacts::PinnedContactManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_IPinnedContactManagerStatics<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics)->IsSupported(&result));
        return result;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager>
    {
        int32_t __stdcall FindRawContactsAsync(void* contact, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>>(this->shim().FindRawContactsAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryLinkContactsAsync(void* primaryContact, void* secondaryContact, void** contact) noexcept final try
        {
            clear_abi(contact);
            typename D::abi_guard guard(this->shim());
            *contact = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().TryLinkContactsAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&primaryContact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&secondaryContact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnlinkRawContactAsync(void* contact, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UnlinkRawContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetPreferredSourceForPictureAsync(void* aggregateContact, void* rawContact, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetPreferredSourceForPictureAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&aggregateContact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&rawContact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager2>
    {
        int32_t __stdcall SetRemoteIdentificationInformationAsync(void* contactListId, void* remoteSourceId, void* accountId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetRemoteIdentificationInformationAsync(*reinterpret_cast<hstring const*>(&contactListId), *reinterpret_cast<hstring const*>(&remoteSourceId), *reinterpret_cast<hstring const*>(&accountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContact> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContact>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Thumbnail(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Thumbnail(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Fields(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::IContactField>>(this->shim().Fields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContact2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContact2>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Notes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Notes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Notes(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Notes(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Phones(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactPhone>>(this->shim().Phones());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Emails(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactEmail>>(this->shim().Emails());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Addresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactAddress>>(this->shim().Addresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectedServiceAccounts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount>>(this->shim().ConnectedServiceAccounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ImportantDates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactDate>>(this->shim().ImportantDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataSuppliers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().DataSuppliers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JobInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactJobInfo>>(this->shim().JobInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignificantOthers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactSignificantOther>>(this->shim().SignificantOthers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Websites(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactWebsite>>(this->shim().Websites());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().ProviderProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContact3> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContact3>
    {
        int32_t __stdcall get_ContactListId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayPictureUserUpdateTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().DisplayPictureUserUpdateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayPictureUserUpdateTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayPictureUserUpdateTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMe(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMe());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AggregateId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AggregateId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RingToneToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RingToneToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RingToneToken(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RingToneToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisplayPictureManuallySet(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisplayPictureManuallySet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LargeDisplayPicture(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().LargeDisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmallDisplayPicture(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().SmallDisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceDisplayPicture(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().SourceDisplayPicture());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourceDisplayPicture(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceDisplayPicture(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextToneToken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TextToneToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextToneToken(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextToneToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAggregate(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAggregate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FullName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FullName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayNameOverride(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayNameOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayNameOverride(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayNameOverride(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Nickname(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Nickname());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Nickname(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Nickname(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SortName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SortName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactAddress> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactAddress>
    {
        int32_t __stdcall get_StreetAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StreetAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StreetAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StreetAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Locality(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Locality());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Locality(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Locality(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Region(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Region(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Region(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Country(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Country());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Country(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Country(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PostalCode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PostalCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PostalCode(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PostalCode(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactAddressKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAddressKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotation> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotation>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AnnotationListId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AnnotationListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContactId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContactId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContactId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedOperations(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations>(this->shim().SupportedOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SupportedOperations(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportedOperations(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().ProviderProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2>
    {
        int32_t __stdcall get_ContactListId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContactListId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactListId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderPackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProviderPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserDataAccountId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySaveAnnotationAsync(void* annotation, void** ppResult) noexcept final try
        {
            clear_abi(ppResult);
            typename D::abi_guard guard(this->shim());
            *ppResult = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySaveAnnotationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation const*>(&annotation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotationAsync(void* annotationId, void** annotation) noexcept final try
        {
            clear_abi(annotation);
            typename D::abi_guard guard(this->shim());
            *annotation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>(this->shim().GetAnnotationAsync(*reinterpret_cast<hstring const*>(&annotationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAnnotationsByRemoteIdAsync(void* remoteId, void** annotations) noexcept final try
        {
            clear_abi(annotations);
            typename D::abi_guard guard(this->shim());
            *annotations = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsByRemoteIdAsync(*reinterpret_cast<hstring const*>(&remoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAnnotationsAsync(void** annotations) noexcept final try
        {
            clear_abi(annotations);
            typename D::abi_guard guard(this->shim());
            *annotations = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAnnotationAsync(void* annotation, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAnnotationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation const*>(&annotation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore>
    {
        int32_t __stdcall FindContactIdsByEmailAsync(void* emailAddress, void** contactIds) noexcept final try
        {
            clear_abi(contactIds);
            typename D::abi_guard guard(this->shim());
            *contactIds = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().FindContactIdsByEmailAsync(*reinterpret_cast<hstring const*>(&emailAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindContactIdsByPhoneNumberAsync(void* phoneNumber, void** contactIds) noexcept final try
        {
            clear_abi(contactIds);
            typename D::abi_guard guard(this->shim());
            *contactIds = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().FindContactIdsByPhoneNumberAsync(*reinterpret_cast<hstring const*>(&phoneNumber)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAnnotationsForContactAsync(void* contact, void** annotations) noexcept final try
        {
            clear_abi(annotations);
            typename D::abi_guard guard(this->shim());
            *annotations = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsForContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableAnnotationAsync(void* annotation, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DisableAnnotationAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation const*>(&annotation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAnnotationListAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>>(this->shim().CreateAnnotationListAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAnnotationListInAccountAsync(void* userDataAccountId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>>(this->shim().CreateAnnotationListAsync(*reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotationListAsync(void* annotationListId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>>(this->shim().GetAnnotationListAsync(*reinterpret_cast<hstring const*>(&annotationListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAnnotationListsAsync(void** lists) noexcept final try
        {
            clear_abi(lists);
            typename D::abi_guard guard(this->shim());
            *lists = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList>>>(this->shim().FindAnnotationListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore2>
    {
        int32_t __stdcall FindAnnotationsForContactListAsync(void* contactListId, void** annotations) noexcept final try
        {
            clear_abi(annotations);
            typename D::abi_guard guard(this->shim());
            *annotations = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation>>>(this->shim().FindAnnotationsForContactListAsync(*reinterpret_cast<hstring const*>(&contactListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactBatch> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactBatch>
    {
        int32_t __stdcall get_Contacts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().Contacts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactBatchStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader>
    {
        int32_t __stdcall SetData(void* contact) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetData(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactCardOptions> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactCardOptions>
    {
        int32_t __stdcall get_HeaderKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactCardHeaderKind>(this->shim().HeaderKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HeaderKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HeaderKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactCardHeaderKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InitialTabKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactCardTabKind>(this->shim().InitialTabKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InitialTabKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InitialTabKind(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactCardTabKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2>
    {
        int32_t __stdcall get_ServerSearchContactListIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ServerSearchContactListIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactChange> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactChange>
    {
        int32_t __stdcall get_ChangeType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Contact(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::Contact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactChangeReader> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactChangeReader>
    {
        int32_t __stdcall AcceptChanges() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceptChanges();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcceptChangesThrough(void* lastChangeToAccept) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceptChangesThrough(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactChange const*>(&lastChangeToAccept));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBatchAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker>
    {
        int32_t __stdcall Enable() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChangeReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangeReader>(this->shim().GetChangeReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reset() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker2>
    {
        int32_t __stdcall get_IsTracking(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTracking());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactChangedDeferral> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactChangedDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactChangedEventArgs>
    {
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServiceName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServiceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactDate> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactDate>
    {
        int32_t __stdcall get_Day(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().Day());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Day(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Day(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Month(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().Month());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Month(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Month(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Year(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Year(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Year(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactDateKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactDateKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactEmail> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactEmail>
    {
        int32_t __stdcall get_Address(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Address(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Address(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactEmailKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactEmailKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactField> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactField>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Category(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory>
    {
        int32_t __stdcall CreateField_Default(void* value, int32_t type, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactField>(this->shim().CreateField(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateField_Category(void* value, int32_t type, int32_t category, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactField>(this->shim().CreateField(*reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateField_Custom(void* name, void* value, int32_t type, int32_t category, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactField>(this->shim().CreateField(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactGroup> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactGroup>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactInformation> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactInformation>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetThumbnailAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().GetThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Emails(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>>(this->shim().Emails());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>>(this->shim().PhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Locations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactLocationField>>(this->shim().Locations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstantMessages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField>>(this->shim().InstantMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomFields(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>>(this->shim().CustomFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall QueryCustomFields(void* customName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactField>>(this->shim().QueryCustomFields(*reinterpret_cast<hstring const*>(&customName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField>
    {
        int32_t __stdcall get_UserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Service(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Service());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LaunchUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().LaunchUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory>
    {
        int32_t __stdcall CreateInstantMessage_Default(void* userName, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField>(this->shim().CreateInstantMessage(*reinterpret_cast<hstring const*>(&userName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstantMessage_Category(void* userName, int32_t category, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField>(this->shim().CreateInstantMessage(*reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstantMessage_All(void* userName, int32_t category, void* service, void* displayText, void* verb, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField>(this->shim().CreateInstantMessage(*reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category), *reinterpret_cast<hstring const*>(&service), *reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&verb)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactJobInfo> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactJobInfo>
    {
        int32_t __stdcall get_CompanyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CompanyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompanyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompanyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompanyYomiName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CompanyYomiName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompanyYomiName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompanyYomiName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Department(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Department());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Department(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Department(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Manager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Manager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Manager(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Manager(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Office(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Office());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Office(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Office(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompanyAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CompanyAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompanyAddress(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompanyAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics>
    {
        int32_t __stdcall get_Call(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Call());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Map(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Map());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Post(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Post());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoCall(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoCall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactList> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactList>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SourceDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHidden(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHidden());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsHidden(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsHidden(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OtherAppReadAccess(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OtherAppReadAccess(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OtherAppReadAccess(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppReadAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OtherAppWriteAccess(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess>(this->shim().OtherAppWriteAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OtherAppWriteAccess(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OtherAppWriteAccess(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactListOtherAppWriteAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChangeTracker(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SyncManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager>(this->shim().SyncManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsServerSearch(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsServerSearch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserDataAccountId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ContactChanged(void* value, winrt::event_token* returnValue) noexcept final try
        {
            zero_abi<winrt::event_token>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::event_token>(this->shim().ContactChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactList, winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContactChanged(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactChanged(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall SaveAsync(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactFromRemoteIdAsync(void* remoteId, void** contact) noexcept final try
        {
            clear_abi(contact);
            typename D::abi_guard guard(this->shim());
            *contact = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetContactFromRemoteIdAsync(*reinterpret_cast<hstring const*>(&remoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMeContactAsync(void** meContact) noexcept final try
        {
            clear_abi(meContact);
            typename D::abi_guard guard(this->shim());
            *meContact = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetMeContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactReaderWithOptions(void* options, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveContactAsync(void* contact, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SaveContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteContactAsync(void* contact, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactAsync(void* contactId, void** contacts) noexcept final try
        {
            clear_abi(contacts);
            typename D::abi_guard guard(this->shim());
            *contacts = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetContactAsync(*reinterpret_cast<hstring const*>(&contactId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactList2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactList2>
    {
        int32_t __stdcall RegisterSyncManagerAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RegisterSyncManagerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SupportsServerSearch(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportsServerSearch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SyncConstraints(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactListSyncConstraints>(this->shim().SyncConstraints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactList3> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactList3>
    {
        int32_t __stdcall get_LimitedWriteOperations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations>(this->shim().LimitedWriteOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChangeTracker(void* identity, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().GetChangeTracker(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations>
    {
        int32_t __stdcall TryCreateOrUpdateContactAsync(void* contact, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCreateOrUpdateContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDeleteContactAsync(void* contactId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDeleteContactAsync(*reinterpret_cast<hstring const*>(&contactId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints>
    {
        int32_t __stdcall get_CanSyncDescriptions(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSyncDescriptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanSyncDescriptions(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanSyncDescriptions(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHomePhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxHomePhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxHomePhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxHomePhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxMobilePhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxMobilePhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxMobilePhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxMobilePhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxWorkPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxWorkPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxWorkPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxWorkPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxOtherPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxOtherPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxOtherPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxPagerPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxPagerPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxPagerPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPagerPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBusinessFaxPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxBusinessFaxPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxBusinessFaxPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxBusinessFaxPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHomeFaxPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxHomeFaxPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxHomeFaxPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxHomeFaxPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxCompanyPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxCompanyPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxCompanyPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxCompanyPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAssistantPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxAssistantPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxAssistantPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxAssistantPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxRadioPhoneNumbers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxRadioPhoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxRadioPhoneNumbers(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxRadioPhoneNumbers(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxPersonalEmailAddresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxPersonalEmailAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxPersonalEmailAddresses(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPersonalEmailAddresses(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxWorkEmailAddresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxWorkEmailAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxWorkEmailAddresses(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxWorkEmailAddresses(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxOtherEmailAddresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherEmailAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxOtherEmailAddresses(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxOtherEmailAddresses(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxHomeAddresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxHomeAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxHomeAddresses(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxHomeAddresses(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxWorkAddresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxWorkAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxWorkAddresses(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxWorkAddresses(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxOtherAddresses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxOtherAddresses(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxOtherAddresses(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBirthdayDates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxBirthdayDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxBirthdayDates(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxBirthdayDates(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAnniversaryDates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxAnniversaryDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxAnniversaryDates(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxAnniversaryDates(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxOtherDates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherDates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxOtherDates(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxOtherDates(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxOtherRelationships(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxOtherRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxOtherRelationships(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxOtherRelationships(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSpouseRelationships(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxSpouseRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxSpouseRelationships(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxSpouseRelationships(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxPartnerRelationships(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxPartnerRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxPartnerRelationships(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPartnerRelationships(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSiblingRelationships(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxSiblingRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxSiblingRelationships(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxSiblingRelationships(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxParentRelationships(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxParentRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxParentRelationships(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxParentRelationships(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxChildRelationships(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxChildRelationships());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxChildRelationships(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxChildRelationships(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxJobInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxJobInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxJobInfo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxJobInfo(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxWebsites(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().MaxWebsites());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxWebsites(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxWebsites(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactListSyncStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastSuccessfulSyncTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastSuccessfulSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastAttemptedSyncTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastAttemptedSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SyncAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SyncAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SyncStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SyncStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SyncStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SyncStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2>
    {
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactListSyncStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastSuccessfulSyncTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastSuccessfulSyncTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastAttemptedSyncTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastAttemptedSyncTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactLocationField> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactLocationField>
    {
        int32_t __stdcall get_UnstructuredAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnstructuredAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Street(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Street());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_City(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().City());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Region(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Country(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Country());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PostalCode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PostalCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory>
    {
        int32_t __stdcall CreateLocation_Default(void* unstructuredAddress, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactLocationField>(this->shim().CreateLocation(*reinterpret_cast<hstring const*>(&unstructuredAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateLocation_Category(void* unstructuredAddress, int32_t category, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactLocationField>(this->shim().CreateLocation(*reinterpret_cast<hstring const*>(&unstructuredAddress), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateLocation_All(void* unstructuredAddress, int32_t category, void* street, void* city, void* region, void* country, void* postalCode, void** field) noexcept final try
        {
            clear_abi(field);
            typename D::abi_guard guard(this->shim());
            *field = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactLocationField>(this->shim().CreateLocation(*reinterpret_cast<hstring const*>(&unstructuredAddress), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const*>(&category), *reinterpret_cast<hstring const*>(&street), *reinterpret_cast<hstring const*>(&city), *reinterpret_cast<hstring const*>(&region), *reinterpret_cast<hstring const*>(&country), *reinterpret_cast<hstring const*>(&postalCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser>
    {
        int32_t __stdcall ConvertContactToVCardAsync(void* contact, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertContactToVCardAsyncWithMaxBytes(void* contact, uint32_t maxBytes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), maxBytes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertVCardToContactAsync(void* vCard, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().ConvertVCardToContactAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&vCard)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestStoreAsync(int32_t accessType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAnnotationStoreAsync(int32_t accessType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore>>(this->shim().RequestAnnotationStoreAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemDisplayNameOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemDisplayNameOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemDisplayNameOrder(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemDisplayNameOrder(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemSortOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemSortOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemSortOrder(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemSortOrder(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser2>
    {
        int32_t __stdcall ShowFullContactCard(void* contact, void* fullContactCardOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowFullContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions const*>(&fullContactCardOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics>
    {
        int32_t __stdcall ShowContactCard(void* contact, winrt::Windows::Foundation::Rect selection) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowContactCardWithPlacement(void* contact, winrt::Windows::Foundation::Rect selection, int32_t preferredPlacement) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&preferredPlacement));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowDelayLoadedContactCard(void* contact, winrt::Windows::Foundation::Rect selection, int32_t preferredPlacement, void** dataLoader) noexcept final try
        {
            clear_abi(dataLoader);
            typename D::abi_guard guard(this->shim());
            *dataLoader = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>(this->shim().ShowDelayLoadedContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&preferredPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2>
    {
        int32_t __stdcall RequestStoreAsync(void** store) noexcept final try
        {
            clear_abi(store);
            typename D::abi_guard guard(this->shim());
            *store = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3>
    {
        int32_t __stdcall ConvertContactToVCardAsync(void* contact, void** vCard) noexcept final try
        {
            clear_abi(vCard);
            typename D::abi_guard guard(this->shim());
            *vCard = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertContactToVCardAsyncWithMaxBytes(void* contact, uint32_t maxBytes, void** vCard) noexcept final try
        {
            clear_abi(vCard);
            typename D::abi_guard guard(this->shim());
            *vCard = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ConvertContactToVCardAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), maxBytes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertVCardToContactAsync(void* vCard, void** contact) noexcept final try
        {
            clear_abi(contact);
            typename D::abi_guard guard(this->shim());
            *contact = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().ConvertVCardToContactAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&vCard)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestStoreAsyncWithAccessType(int32_t accessType, void** store) noexcept final try
        {
            clear_abi(store);
            typename D::abi_guard guard(this->shim());
            *store = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAnnotationStoreAsync(int32_t accessType, void** store) noexcept final try
        {
            clear_abi(store);
            typename D::abi_guard guard(this->shim());
            *store = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore>>(this->shim().RequestAnnotationStoreAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsShowContactCardSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsShowContactCardSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowContactCardWithOptions(void* contact, winrt::Windows::Foundation::Rect selection, int32_t preferredPlacement, void* contactCardOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&preferredPlacement), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactCardOptions const*>(&contactCardOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsShowDelayLoadedContactCardSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsShowDelayLoadedContactCardSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowDelayLoadedContactCardWithOptions(void* contact, winrt::Windows::Foundation::Rect selection, int32_t preferredPlacement, void* contactCardOptions, void** dataLoader) noexcept final try
        {
            clear_abi(dataLoader);
            typename D::abi_guard guard(this->shim());
            *dataLoader = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader>(this->shim().ShowDelayLoadedContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<winrt::Windows::UI::Popups::Placement const*>(&preferredPlacement), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactCardOptions const*>(&contactCardOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowFullContactCard(void* contact, void* fullContactCardOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowFullContactCard(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions const*>(&fullContactCardOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemDisplayNameOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemDisplayNameOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemDisplayNameOrder(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemDisplayNameOrder(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemSortOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder>(this->shim().SystemSortOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemSortOrder(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemSortOrder(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics4> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics4>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactManagerForUser>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5>
    {
        int32_t __stdcall IsShowFullContactCardSupportedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsShowFullContactCardSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeMiddleNameInSystemDisplayAndSort(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IncludeMiddleNameInSystemDisplayAndSort());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncludeMiddleNameInSystemDisplayAndSort(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncludeMiddleNameInSystemDisplayAndSort(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactMatchReason> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactMatchReason>
    {
        int32_t __stdcall get_Field(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactMatchReasonKind>(this->shim().Field());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Segments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::TextSegment>>(this->shim().Segments());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactName> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactName>
    {
        int32_t __stdcall get_FirstName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FirstName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FirstName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LastName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MiddleName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MiddleName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MiddleName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MiddleName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YomiGivenName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().YomiGivenName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_YomiGivenName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().YomiGivenName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YomiFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().YomiFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_YomiFamilyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().YomiFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HonorificNameSuffix(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HonorificNameSuffix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HonorificNameSuffix(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HonorificNameSuffix(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HonorificNamePrefix(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HonorificNamePrefix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HonorificNamePrefix(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HonorificNamePrefix(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YomiDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().YomiDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPanel> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPanel>
    {
        int32_t __stdcall ClosePanel() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosePanel();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeaderColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().HeaderColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HeaderColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HeaderColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_LaunchFullAppRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LaunchFullAppRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactPanel, winrt::Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LaunchFullAppRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LaunchFullAppRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closing(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactPanel, winrt::Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closing(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closing(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs>
    {
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPhone> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPhone>
    {
        int32_t __stdcall get_Number(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Number());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Number(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Number(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactPhoneKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Kind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Kind(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactPhoneKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPicker> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPicker>
    {
        int32_t __stdcall get_CommitButtonText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CommitButtonText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommitButtonText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommitButtonText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode>(this->shim().SelectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionMode(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredFields(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().DesiredFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleContactAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactInformation>>(this->shim().PickSingleContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickMultipleContactsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactInformation>>>(this->shim().PickMultipleContactsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPicker2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPicker2>
    {
        int32_t __stdcall get_DesiredFieldsWithContactFieldType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>>(this->shim().DesiredFieldsWithContactFieldType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickContactAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().PickContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickContactsAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::Contact>>>(this->shim().PickContactsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPicker3> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPicker3>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics>
    {
        int32_t __stdcall CreateForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactPicker>(this->shim().CreateForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSupportedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions>
    {
        int32_t __stdcall get_TextSearch(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactQueryTextSearch>(this->shim().TextSearch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContactListIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ContactListIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeContactsFromHiddenLists(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IncludeContactsFromHiddenLists());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncludeContactsFromHiddenLists(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncludeContactsFromHiddenLists(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredFields(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactQueryDesiredFields>(this->shim().DesiredFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredFields(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredFields(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactQueryDesiredFields const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredOperations(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations>(this->shim().DesiredOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredOperations(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredOperations(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationOperations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AnnotationListIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().AnnotationListIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory>
    {
        int32_t __stdcall CreateWithText(void* text, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions>(this->shim().CreateWithText(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTextAndFields(void* text, uint32_t fields, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions>(this->shim().CreateWithTextAndFields(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields const*>(&fields)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch>
    {
        int32_t __stdcall get_Fields(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields>(this->shim().Fields());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Fields(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Fields(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SearchScope(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchScope>(this->shim().SearchScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SearchScope(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SearchScope(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchScope const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactReader> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactReader>
    {
        int32_t __stdcall ReadBatchAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMatchingPropertiesWithMatchReason(void* contact, void** ppRetVal) noexcept final try
        {
            clear_abi(ppRetVal);
            typename D::abi_guard guard(this->shim());
            *ppRetVal = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactMatchReason>>(this->shim().GetMatchingPropertiesWithMatchReason(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2>
    {
        int32_t __stdcall get_Relationship(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactRelationship>(this->shim().Relationship());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Relationship(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Relationship(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactRelationship const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactStore> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactStore>
    {
        int32_t __stdcall FindContactsAsync(void** contacts) noexcept final try
        {
            clear_abi(contacts);
            typename D::abi_guard guard(this->shim());
            *contacts = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>>(this->shim().FindContactsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindContactsWithSearchTextAsync(void* searchText, void** contacts) noexcept final try
        {
            clear_abi(contacts);
            typename D::abi_guard guard(this->shim());
            *contacts = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>>>(this->shim().FindContactsAsync(*reinterpret_cast<hstring const*>(&searchText)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactAsync(void* contactId, void** contacts) noexcept final try
        {
            clear_abi(contacts);
            typename D::abi_guard guard(this->shim());
            *contacts = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetContactAsync(*reinterpret_cast<hstring const*>(&contactId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactStore2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactStore2>
    {
        int32_t __stdcall get_ChangeTracker(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ContactChanged(void* value, winrt::event_token* returnValue) noexcept final try
        {
            zero_abi<winrt::event_token>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::event_token>(this->shim().ContactChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::ContactStore, winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContactChanged(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactChanged(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall get_AggregateContactManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::AggregateContactManager>(this->shim().AggregateContactManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindContactListsAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::ContactList>>>(this->shim().FindContactListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactListAsync(void* contactListId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>>(this->shim().GetContactListAsync(*reinterpret_cast<hstring const*>(&contactListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateContactListAsync(void* displayName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>>(this->shim().CreateContactListAsync(*reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMeContactAsync(void** meContact) noexcept final try
        {
            clear_abi(meContact);
            typename D::abi_guard guard(this->shim());
            *meContact = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::Contact>>(this->shim().GetMeContactAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContactReaderWithOptions(void* options, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactReader>(this->shim().GetContactReader(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateContactListInAccountAsync(void* displayName, void* userDataAccountId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactList>>(this->shim().CreateContactListAsync(*reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactStore3> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactStore3>
    {
        int32_t __stdcall GetChangeTracker(void* identity, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker>(this->shim().GetChangeTracker(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactWebsite> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactWebsite>
    {
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Uri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IContactWebsite2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IContactWebsite2>
    {
        int32_t __stdcall get_RawValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RawValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RawValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RawValue(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions>
    {
        int32_t __stdcall get_DesiredRemainingView(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::ViewManagement::ViewSizePreference>(this->shim().DesiredRemainingView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredRemainingView(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredRemainingView(*reinterpret_cast<winrt::Windows::UI::ViewManagement::ViewSizePreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics>
    {
        int32_t __stdcall get_Email(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Email());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhoneNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Location(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstantMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InstantMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertNameToType(void* name, int32_t* type) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *type = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>(this->shim().ConvertNameToType(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertTypeToName(int32_t type, void** name) noexcept final try
        {
            clear_abi(name);
            typename D::abi_guard guard(this->shim());
            *name = detach_from<hstring>(this->shim().ConvertTypeToName(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::ContactFieldType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult>
    {
        int32_t __stdcall get_ContactIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().ContactIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager>
    {
        int32_t __stdcall get_User(void** user) noexcept final try
        {
            clear_abi(user);
            typename D::abi_guard guard(this->shim());
            *user = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPinSurfaceSupported(int32_t surface, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPinSurfaceSupported(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsContactPinned(void* contact, int32_t surface, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsContactPinned(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinContactAsync(void* contact, int32_t surface, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPinContactsAsync(void* contacts, int32_t surface, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestPinContactsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Contacts::Contact> const*>(&contacts), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestUnpinContactAsync(void* contact, int32_t surface, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestUnpinContactAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::PinnedContactSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SignalContactActivity(void* contact) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignalContactActivity(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPinnedContactIdsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult>>(this->shim().GetPinnedContactIdsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::PinnedContactManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::PinnedContactManager>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts
{
    constexpr auto operator|(ContactAnnotationOperations const left, ContactAnnotationOperations const right) noexcept
    {
        return static_cast<ContactAnnotationOperations>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ContactAnnotationOperations& left, ContactAnnotationOperations const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ContactAnnotationOperations const left, ContactAnnotationOperations const right) noexcept
    {
        return static_cast<ContactAnnotationOperations>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ContactAnnotationOperations& left, ContactAnnotationOperations const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ContactAnnotationOperations const value) noexcept
    {
        return static_cast<ContactAnnotationOperations>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ContactAnnotationOperations const left, ContactAnnotationOperations const right) noexcept
    {
        return static_cast<ContactAnnotationOperations>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ContactAnnotationOperations& left, ContactAnnotationOperations const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(ContactQueryDesiredFields const left, ContactQueryDesiredFields const right) noexcept
    {
        return static_cast<ContactQueryDesiredFields>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ContactQueryDesiredFields& left, ContactQueryDesiredFields const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ContactQueryDesiredFields const left, ContactQueryDesiredFields const right) noexcept
    {
        return static_cast<ContactQueryDesiredFields>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ContactQueryDesiredFields& left, ContactQueryDesiredFields const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ContactQueryDesiredFields const value) noexcept
    {
        return static_cast<ContactQueryDesiredFields>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ContactQueryDesiredFields const left, ContactQueryDesiredFields const right) noexcept
    {
        return static_cast<ContactQueryDesiredFields>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ContactQueryDesiredFields& left, ContactQueryDesiredFields const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(ContactQuerySearchFields const left, ContactQuerySearchFields const right) noexcept
    {
        return static_cast<ContactQuerySearchFields>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(ContactQuerySearchFields& left, ContactQuerySearchFields const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(ContactQuerySearchFields const left, ContactQuerySearchFields const right) noexcept
    {
        return static_cast<ContactQuerySearchFields>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(ContactQuerySearchFields& left, ContactQuerySearchFields const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(ContactQuerySearchFields const value) noexcept
    {
        return static_cast<ContactQuerySearchFields>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(ContactQuerySearchFields const left, ContactQuerySearchFields const right) noexcept
    {
        return static_cast<ContactQuerySearchFields>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(ContactQuerySearchFields& left, ContactQuerySearchFields const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline Contact::Contact() :
        Contact(impl::call_factory_cast<Contact(*)(winrt::Windows::Foundation::IActivationFactory const&), Contact>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Contact>(); }))
    {
    }
    inline ContactAddress::ContactAddress() :
        ContactAddress(impl::call_factory_cast<ContactAddress(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactAddress>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactAddress>(); }))
    {
    }
    inline ContactAnnotation::ContactAnnotation() :
        ContactAnnotation(impl::call_factory_cast<ContactAnnotation(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactAnnotation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactAnnotation>(); }))
    {
    }
    inline ContactCardOptions::ContactCardOptions() :
        ContactCardOptions(impl::call_factory_cast<ContactCardOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactCardOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactCardOptions>(); }))
    {
    }
    inline ContactConnectedServiceAccount::ContactConnectedServiceAccount() :
        ContactConnectedServiceAccount(impl::call_factory_cast<ContactConnectedServiceAccount(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactConnectedServiceAccount>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactConnectedServiceAccount>(); }))
    {
    }
    inline ContactDate::ContactDate() :
        ContactDate(impl::call_factory_cast<ContactDate(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactDate>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactDate>(); }))
    {
    }
    inline ContactEmail::ContactEmail() :
        ContactEmail(impl::call_factory_cast<ContactEmail(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactEmail>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactEmail>(); }))
    {
    }
    inline ContactField::ContactField(param::hstring const& value, winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type) :
        ContactField(impl::call_factory<ContactField, IContactFieldFactory>([&](IContactFieldFactory const& f) { return f.CreateField(value, type); }))
    {
    }
    inline ContactField::ContactField(param::hstring const& value, winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
        ContactField(impl::call_factory<ContactField, IContactFieldFactory>([&](IContactFieldFactory const& f) { return f.CreateField(value, type, category); }))
    {
    }
    inline ContactField::ContactField(param::hstring const& name, param::hstring const& value, winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
        ContactField(impl::call_factory<ContactField, IContactFieldFactory>([&](IContactFieldFactory const& f) { return f.CreateField(name, value, type, category); }))
    {
    }
    inline ContactFieldFactory::ContactFieldFactory() :
        ContactFieldFactory(impl::call_factory_cast<ContactFieldFactory(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactFieldFactory>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactFieldFactory>(); }))
    {
    }
    inline ContactInstantMessageField::ContactInstantMessageField(param::hstring const& userName) :
        ContactInstantMessageField(impl::call_factory<ContactInstantMessageField, IContactInstantMessageFieldFactory>([&](IContactInstantMessageFieldFactory const& f) { return f.CreateInstantMessage(userName); }))
    {
    }
    inline ContactInstantMessageField::ContactInstantMessageField(param::hstring const& userName, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
        ContactInstantMessageField(impl::call_factory<ContactInstantMessageField, IContactInstantMessageFieldFactory>([&](IContactInstantMessageFieldFactory const& f) { return f.CreateInstantMessage(userName, category); }))
    {
    }
    inline ContactInstantMessageField::ContactInstantMessageField(param::hstring const& userName, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& service, param::hstring const& displayText, winrt::Windows::Foundation::Uri const& verb) :
        ContactInstantMessageField(impl::call_factory<ContactInstantMessageField, IContactInstantMessageFieldFactory>([&](IContactInstantMessageFieldFactory const& f) { return f.CreateInstantMessage(userName, category, service, displayText, verb); }))
    {
    }
    inline ContactJobInfo::ContactJobInfo() :
        ContactJobInfo(impl::call_factory_cast<ContactJobInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactJobInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactJobInfo>(); }))
    {
    }
    inline auto ContactLaunchActionVerbs::Call()
    {
        return impl::call_factory_cast<hstring(*)(IContactLaunchActionVerbsStatics const&), ContactLaunchActionVerbs, IContactLaunchActionVerbsStatics>([](IContactLaunchActionVerbsStatics const& f) { return f.Call(); });
    }
    inline auto ContactLaunchActionVerbs::Message()
    {
        return impl::call_factory_cast<hstring(*)(IContactLaunchActionVerbsStatics const&), ContactLaunchActionVerbs, IContactLaunchActionVerbsStatics>([](IContactLaunchActionVerbsStatics const& f) { return f.Message(); });
    }
    inline auto ContactLaunchActionVerbs::Map()
    {
        return impl::call_factory_cast<hstring(*)(IContactLaunchActionVerbsStatics const&), ContactLaunchActionVerbs, IContactLaunchActionVerbsStatics>([](IContactLaunchActionVerbsStatics const& f) { return f.Map(); });
    }
    inline auto ContactLaunchActionVerbs::Post()
    {
        return impl::call_factory_cast<hstring(*)(IContactLaunchActionVerbsStatics const&), ContactLaunchActionVerbs, IContactLaunchActionVerbsStatics>([](IContactLaunchActionVerbsStatics const& f) { return f.Post(); });
    }
    inline auto ContactLaunchActionVerbs::VideoCall()
    {
        return impl::call_factory_cast<hstring(*)(IContactLaunchActionVerbsStatics const&), ContactLaunchActionVerbs, IContactLaunchActionVerbsStatics>([](IContactLaunchActionVerbsStatics const& f) { return f.VideoCall(); });
    }
    inline ContactLocationField::ContactLocationField(param::hstring const& unstructuredAddress) :
        ContactLocationField(impl::call_factory<ContactLocationField, IContactLocationFieldFactory>([&](IContactLocationFieldFactory const& f) { return f.CreateLocation(unstructuredAddress); }))
    {
    }
    inline ContactLocationField::ContactLocationField(param::hstring const& unstructuredAddress, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category) :
        ContactLocationField(impl::call_factory<ContactLocationField, IContactLocationFieldFactory>([&](IContactLocationFieldFactory const& f) { return f.CreateLocation(unstructuredAddress, category); }))
    {
    }
    inline ContactLocationField::ContactLocationField(param::hstring const& unstructuredAddress, winrt::Windows::ApplicationModel::Contacts::ContactFieldCategory const& category, param::hstring const& street, param::hstring const& city, param::hstring const& region, param::hstring const& country, param::hstring const& postalCode) :
        ContactLocationField(impl::call_factory<ContactLocationField, IContactLocationFieldFactory>([&](IContactLocationFieldFactory const& f) { return f.CreateLocation(unstructuredAddress, category, street, city, region, country, postalCode); }))
    {
    }
    inline auto ContactManager::ShowContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection)
    {
        impl::call_factory<ContactManager, IContactManagerStatics>([&](IContactManagerStatics const& f) { return f.ShowContactCard(contact, selection); });
    }
    inline auto ContactManager::ShowContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement)
    {
        impl::call_factory<ContactManager, IContactManagerStatics>([&](IContactManagerStatics const& f) { return f.ShowContactCard(contact, selection, preferredPlacement); });
    }
    inline auto ContactManager::ShowDelayLoadedContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics>([&](IContactManagerStatics const& f) { return f.ShowDelayLoadedContactCard(contact, selection, preferredPlacement); });
    }
    inline auto ContactManager::RequestStoreAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Contacts::ContactStore>(*)(IContactManagerStatics2 const&), ContactManager, IContactManagerStatics2>([](IContactManagerStatics2 const& f) { return f.RequestStoreAsync(); });
    }
    inline auto ContactManager::ConvertContactToVCardAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.ConvertContactToVCardAsync(contact); });
    }
    inline auto ContactManager::ConvertContactToVCardAsync(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, uint32_t maxBytes)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.ConvertContactToVCardAsync(contact, maxBytes); });
    }
    inline auto ContactManager::ConvertVCardToContactAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& vCard)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.ConvertVCardToContactAsync(vCard); });
    }
    inline auto ContactManager::RequestStoreAsync(winrt::Windows::ApplicationModel::Contacts::ContactStoreAccessType const& accessType)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.RequestStoreAsync(accessType); });
    }
    inline auto ContactManager::RequestAnnotationStoreAsync(winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStoreAccessType const& accessType)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.RequestAnnotationStoreAsync(accessType); });
    }
    inline auto ContactManager::IsShowContactCardSupported()
    {
        return impl::call_factory_cast<bool(*)(IContactManagerStatics3 const&), ContactManager, IContactManagerStatics3>([](IContactManagerStatics3 const& f) { return f.IsShowContactCardSupported(); });
    }
    inline auto ContactManager::ShowContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement, winrt::Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions)
    {
        impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.ShowContactCard(contact, selection, preferredPlacement, contactCardOptions); });
    }
    inline auto ContactManager::IsShowDelayLoadedContactCardSupported()
    {
        return impl::call_factory_cast<bool(*)(IContactManagerStatics3 const&), ContactManager, IContactManagerStatics3>([](IContactManagerStatics3 const& f) { return f.IsShowDelayLoadedContactCardSupported(); });
    }
    inline auto ContactManager::ShowDelayLoadedContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& preferredPlacement, winrt::Windows::ApplicationModel::Contacts::ContactCardOptions const& contactCardOptions)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.ShowDelayLoadedContactCard(contact, selection, preferredPlacement, contactCardOptions); });
    }
    inline auto ContactManager::ShowFullContactCard(winrt::Windows::ApplicationModel::Contacts::Contact const& contact, winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions const& fullContactCardOptions)
    {
        impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.ShowFullContactCard(contact, fullContactCardOptions); });
    }
    inline auto ContactManager::SystemDisplayNameOrder()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder(*)(IContactManagerStatics3 const&), ContactManager, IContactManagerStatics3>([](IContactManagerStatics3 const& f) { return f.SystemDisplayNameOrder(); });
    }
    inline auto ContactManager::SystemDisplayNameOrder(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const& value)
    {
        impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.SystemDisplayNameOrder(value); });
    }
    inline auto ContactManager::SystemSortOrder()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Contacts::ContactNameOrder(*)(IContactManagerStatics3 const&), ContactManager, IContactManagerStatics3>([](IContactManagerStatics3 const& f) { return f.SystemSortOrder(); });
    }
    inline auto ContactManager::SystemSortOrder(winrt::Windows::ApplicationModel::Contacts::ContactNameOrder const& value)
    {
        impl::call_factory<ContactManager, IContactManagerStatics3>([&](IContactManagerStatics3 const& f) { return f.SystemSortOrder(value); });
    }
    inline auto ContactManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<ContactManager, IContactManagerStatics4>([&](IContactManagerStatics4 const& f) { return f.GetForUser(user); });
    }
    inline auto ContactManager::IsShowFullContactCardSupportedAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<bool>(*)(IContactManagerStatics5 const&), ContactManager, IContactManagerStatics5>([](IContactManagerStatics5 const& f) { return f.IsShowFullContactCardSupportedAsync(); });
    }
    inline auto ContactManager::IncludeMiddleNameInSystemDisplayAndSort()
    {
        return impl::call_factory_cast<bool(*)(IContactManagerStatics5 const&), ContactManager, IContactManagerStatics5>([](IContactManagerStatics5 const& f) { return f.IncludeMiddleNameInSystemDisplayAndSort(); });
    }
    inline auto ContactManager::IncludeMiddleNameInSystemDisplayAndSort(bool value)
    {
        impl::call_factory<ContactManager, IContactManagerStatics5>([&](IContactManagerStatics5 const& f) { return f.IncludeMiddleNameInSystemDisplayAndSort(value); });
    }
    inline ContactPhone::ContactPhone() :
        ContactPhone(impl::call_factory_cast<ContactPhone(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactPhone>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactPhone>(); }))
    {
    }
    inline ContactPicker::ContactPicker() :
        ContactPicker(impl::call_factory_cast<ContactPicker(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactPicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactPicker>(); }))
    {
    }
    inline auto ContactPicker::CreateForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<ContactPicker, IContactPickerStatics>([&](IContactPickerStatics const& f) { return f.CreateForUser(user); });
    }
    inline auto ContactPicker::IsSupportedAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<bool>(*)(IContactPickerStatics const&), ContactPicker, IContactPickerStatics>([](IContactPickerStatics const& f) { return f.IsSupportedAsync(); });
    }
    inline ContactQueryOptions::ContactQueryOptions() :
        ContactQueryOptions(impl::call_factory_cast<ContactQueryOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactQueryOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactQueryOptions>(); }))
    {
    }
    inline ContactQueryOptions::ContactQueryOptions(param::hstring const& text) :
        ContactQueryOptions(impl::call_factory<ContactQueryOptions, IContactQueryOptionsFactory>([&](IContactQueryOptionsFactory const& f) { return f.CreateWithText(text); }))
    {
    }
    inline ContactQueryOptions::ContactQueryOptions(param::hstring const& text, winrt::Windows::ApplicationModel::Contacts::ContactQuerySearchFields const& fields) :
        ContactQueryOptions(impl::call_factory<ContactQueryOptions, IContactQueryOptionsFactory>([&](IContactQueryOptionsFactory const& f) { return f.CreateWithTextAndFields(text, fields); }))
    {
    }
    inline ContactSignificantOther::ContactSignificantOther() :
        ContactSignificantOther(impl::call_factory_cast<ContactSignificantOther(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactSignificantOther>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactSignificantOther>(); }))
    {
    }
    inline ContactWebsite::ContactWebsite() :
        ContactWebsite(impl::call_factory_cast<ContactWebsite(*)(winrt::Windows::Foundation::IActivationFactory const&), ContactWebsite>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContactWebsite>(); }))
    {
    }
    inline FullContactCardOptions::FullContactCardOptions() :
        FullContactCardOptions(impl::call_factory_cast<FullContactCardOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), FullContactCardOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FullContactCardOptions>(); }))
    {
    }
    inline auto KnownContactField::Email()
    {
        return impl::call_factory_cast<hstring(*)(IKnownContactFieldStatics const&), KnownContactField, IKnownContactFieldStatics>([](IKnownContactFieldStatics const& f) { return f.Email(); });
    }
    inline auto KnownContactField::PhoneNumber()
    {
        return impl::call_factory_cast<hstring(*)(IKnownContactFieldStatics const&), KnownContactField, IKnownContactFieldStatics>([](IKnownContactFieldStatics const& f) { return f.PhoneNumber(); });
    }
    inline auto KnownContactField::Location()
    {
        return impl::call_factory_cast<hstring(*)(IKnownContactFieldStatics const&), KnownContactField, IKnownContactFieldStatics>([](IKnownContactFieldStatics const& f) { return f.Location(); });
    }
    inline auto KnownContactField::InstantMessage()
    {
        return impl::call_factory_cast<hstring(*)(IKnownContactFieldStatics const&), KnownContactField, IKnownContactFieldStatics>([](IKnownContactFieldStatics const& f) { return f.InstantMessage(); });
    }
    inline auto KnownContactField::ConvertNameToType(param::hstring const& name)
    {
        return impl::call_factory<KnownContactField, IKnownContactFieldStatics>([&](IKnownContactFieldStatics const& f) { return f.ConvertNameToType(name); });
    }
    inline auto KnownContactField::ConvertTypeToName(winrt::Windows::ApplicationModel::Contacts::ContactFieldType const& type)
    {
        return impl::call_factory<KnownContactField, IKnownContactFieldStatics>([&](IKnownContactFieldStatics const& f) { return f.ConvertTypeToName(type); });
    }
    inline auto PinnedContactManager::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Contacts::PinnedContactManager(*)(IPinnedContactManagerStatics const&), PinnedContactManager, IPinnedContactManagerStatics>([](IPinnedContactManagerStatics const& f) { return f.GetDefault(); });
    }
    inline auto PinnedContactManager::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<PinnedContactManager, IPinnedContactManagerStatics>([&](IPinnedContactManagerStatics const& f) { return f.GetForUser(user); });
    }
    inline auto PinnedContactManager::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IPinnedContactManagerStatics const&), PinnedContactManager, IPinnedContactManagerStatics>([](IPinnedContactManagerStatics const& f) { return f.IsSupported(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IAggregateContactManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContact> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContact2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContact3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAddress> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactAnnotationStore2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactBatch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactCardDelayedDataLoader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactCardOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangeTracker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactConnectedServiceAccount> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactDate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactEmail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactFieldFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactInstantMessageFieldFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactJobInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactLaunchActionVerbsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactList2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactList3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListLimitedWriteOperations> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListSyncConstraints> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactListSyncManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactLocationField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactLocationFieldFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerForUser2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactManagerStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactMatchReason> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactName> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPanelClosingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPanelLaunchFullAppRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPhone> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPicker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPicker3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactPickerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactQueryOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactQueryOptionsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactQueryTextSearch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactSignificantOther2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStore2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStore3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactStoreNotificationTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactWebsite> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IContactWebsite2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IFullContactCardOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IKnownContactFieldStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IPinnedContactIdsQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IPinnedContactManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::IPinnedContactManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::AggregateContactManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Contact> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAddress> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAnnotation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactAnnotationStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactBatch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactCardDelayedDataLoader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactCardOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactConnectedServiceAccount> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactDate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactEmail> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactFieldFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactInstantMessageField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactJobInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactLaunchActionVerbs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactListLimitedWriteOperations> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactListSyncConstraints> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactListSyncManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactLocationField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactManagerForUser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactMatchReason> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPanel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPanelClosingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPanelLaunchFullAppRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPhone> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactQueryOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactQueryTextSearch> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactSignificantOther> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactStoreNotificationTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::ContactWebsite> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::FullContactCardOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::KnownContactField> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::PinnedContactIdsQueryResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::PinnedContactManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
