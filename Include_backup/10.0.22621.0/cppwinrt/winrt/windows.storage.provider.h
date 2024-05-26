// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Provider_H
#define WINRT_Windows_Storage_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Storage.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Storage.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_ICachedFileUpdaterStatics<D>::SetUpdateInformation(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contentId, winrt::Windows::Storage::Provider::ReadActivationMode const& readMode, winrt::Windows::Storage::Provider::WriteActivationMode const& writeMode, winrt::Windows::Storage::Provider::CachedFileOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics)->SetUpdateInformation(*(void**)(&file), *(void**)(&contentId), static_cast<int32_t>(readMode), static_cast<int32_t>(writeMode), static_cast<uint32_t>(options)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::CachedFileTarget) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UpdateTarget() const
    {
        winrt::Windows::Storage::Provider::CachedFileTarget value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->get_UpdateTarget(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->add_FileUpdateRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested_revoker consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FileUpdateRequested_revoker>(this, FileUpdateRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->remove_FileUpdateRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->add_UIRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested_revoker consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UIRequested_revoker>(this, UIRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->remove_UIRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::UIStatus) consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIStatus() const
    {
        winrt::Windows::Storage::Provider::UIStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI)->get_UIStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequest) consume_Windows_Storage_Provider_ICachedFileUpdaterUI2<D>::UpdateRequest() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2)->get_UpdateRequest(&value));
        return winrt::Windows::Storage::Provider::FileUpdateRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequestDeferral) consume_Windows_Storage_Provider_ICachedFileUpdaterUI2<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2)->GetDeferral(&value));
        return winrt::Windows::Storage::Provider::FileUpdateRequestDeferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IFileUpdateRequest<D>::ContentId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest)->get_ContentId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Storage_Provider_IFileUpdateRequest<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest)->get_File(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateStatus) consume_Windows_Storage_Provider_IFileUpdateRequest<D>::Status() const
    {
        winrt::Windows::Storage::Provider::FileUpdateStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IFileUpdateRequest<D>::Status(winrt::Windows::Storage::Provider::FileUpdateStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequestDeferral) consume_Windows_Storage_Provider_IFileUpdateRequest<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest)->GetDeferral(&value));
        return winrt::Windows::Storage::Provider::FileUpdateRequestDeferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IFileUpdateRequest<D>::UpdateLocalFile(winrt::Windows::Storage::IStorageFile const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest)->UpdateLocalFile(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IFileUpdateRequest2<D>::UserInputNeededMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest2)->get_UserInputNeededMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IFileUpdateRequest2<D>::UserInputNeededMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequest2)->put_UserInputNeededMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IFileUpdateRequestDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequest) consume_Windows_Storage_Provider_IFileUpdateRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::Storage::Provider::FileUpdateRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderFileTypeInfo<D>::FileExtension() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo)->get_FileExtension(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderFileTypeInfo<D>::IconResource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo)->get_IconResource(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo) consume_Windows_Storage_Provider_IStorageProviderFileTypeInfoFactory<D>::CreateInstance(param::hstring const& fileExtension, param::hstring const& iconResource) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory)->CreateInstance(*(void**)(&fileExtension), *(void**)(&iconResource), &value));
        return winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus) consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::Status() const
    {
        winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::Status(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->get_ContentUri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentUri(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->put_ContentUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->get_ContentId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->put_ContentId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus) consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Status() const
    {
        winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Status(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->get_Path(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Path(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->put_Path(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_Provider_IStorageProviderItemPropertiesStatics<D>::SetAsync(winrt::Windows::Storage::IStorageItem const& item, param::async_iterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty> const& itemProperties) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics)->SetAsync(*(void**)(&item), *(void**)(&itemProperties), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Id(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemProperty)->put_Id(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Id() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemProperty)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Value(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemProperty)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemProperty)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::IconResource(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemProperty)->put_IconResource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::IconResource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemProperty)->get_IconResource(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::Id() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::Id(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->put_Id(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::DisplayNameResource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->get_DisplayNameResource(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::DisplayNameResource(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->put_DisplayNameResource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty>) consume_Windows_Storage_Provider_IStorageProviderItemPropertySource<D>::GetItemProperties(param::hstring const& itemPath) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource)->GetItemProperties(*(void**)(&itemPath), &result));
        return winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Storage_Provider_IStorageProviderKnownFolderEntry<D>::KnownFolderId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry)->get_KnownFolderId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderKnownFolderEntry<D>::KnownFolderId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry)->put_KnownFolderId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus) consume_Windows_Storage_Provider_IStorageProviderKnownFolderEntry<D>::Status() const
    {
        winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderKnownFolderEntry<D>::Status(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry)->put_Status(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo<D>::ProviderDisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo)->get_ProviderDisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo<D>::ProviderDisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo)->put_ProviderDisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry>) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo<D>::KnownFolderEntries() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo)->get_KnownFolderEntries(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo<D>::SyncRequested() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo)->get_SyncRequested(&value));
        return winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo<D>::SyncRequested(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo)->put_SyncRequested(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource<D>::GetKnownFolderSyncInfo() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource)->GetKnownFolderSyncInfo(&result));
        return winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource<D>::KnownFolderSyncInfoChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource)->add_KnownFolderSyncInfoChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource<D>::KnownFolderSyncInfoChanged_revoker consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource<D>::KnownFolderSyncInfoChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, KnownFolderSyncInfoChanged_revoker>(this, KnownFolderSyncInfoChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource<D>::KnownFolderSyncInfoChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource)->remove_KnownFolderSyncInfoChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSourceFactory<D>::GetKnownFolderSyncInfoSource() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory)->GetKnownFolderSyncInfoSource(&result));
        return winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncRequestArgs<D>::KnownFolders() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs)->get_KnownFolders(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncRequestArgs<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs)->get_Source(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderMoreInfoUI<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderMoreInfoUI<D>::Message(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI)->put_Message(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderUICommand) consume_Windows_Storage_Provider_IStorageProviderMoreInfoUI<D>::Command() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI)->get_Command(&value));
        return winrt::Windows::Storage::Provider::IStorageProviderUICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderMoreInfoUI<D>::Command(winrt::Windows::Storage::Provider::IStorageProviderUICommand const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI)->put_Command(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Provider_IStorageProviderPropertyCapabilities<D>::IsPropertySupported(param::hstring const& propertyCanonicalName) const
    {
        bool isSupported{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities)->IsPropertySupported(*(void**)(&propertyCanonicalName), &isSupported));
        return isSupported;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaTotalInBytes() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->get_QuotaTotalInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaTotalInBytes(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->put_QuotaTotalInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaUsedInBytes() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->get_QuotaUsedInBytes(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaUsedInBytes(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->put_QuotaUsedInBytes(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaUsedLabel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->get_QuotaUsedLabel(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaUsedLabel(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->put_QuotaUsedLabel(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaUsedColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->get_QuotaUsedColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>::QuotaUsedColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderQuotaUI)->put_QuotaUsedColor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderState) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderState() const
    {
        winrt::Windows::Storage::Provider::StorageProviderState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_ProviderState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderState(winrt::Windows::Storage::Provider::StorageProviderState const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_ProviderState(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderStateLabel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_ProviderStateLabel(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderStateLabel(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_ProviderStateLabel(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderStateIcon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_ProviderStateIcon(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderStateIcon(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_ProviderStateIcon(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderUICommand) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::SyncStatusCommand() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_SyncStatusCommand(&value));
        return winrt::Windows::Storage::Provider::IStorageProviderUICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::SyncStatusCommand(winrt::Windows::Storage::Provider::IStorageProviderUICommand const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_SyncStatusCommand(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderQuotaUI) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::QuotaUI() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_QuotaUI(&value));
        return winrt::Windows::Storage::Provider::StorageProviderQuotaUI{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::QuotaUI(winrt::Windows::Storage::Provider::StorageProviderQuotaUI const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_QuotaUI(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::MoreInfoUI() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_MoreInfoUI(&value));
        return winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::MoreInfoUI(winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_MoreInfoUI(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderUICommand) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderPrimaryCommand() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_ProviderPrimaryCommand(&value));
        return winrt::Windows::Storage::Provider::IStorageProviderUICommand{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderPrimaryCommand(winrt::Windows::Storage::Provider::IStorageProviderUICommand const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_ProviderPrimaryCommand(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::IStorageProviderUICommand>) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderSecondaryCommands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->get_ProviderSecondaryCommands(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::IStorageProviderUICommand>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>::ProviderSecondaryCommands(param::vector<winrt::Windows::Storage::Provider::IStorageProviderUICommand> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUI)->put_ProviderSecondaryCommands(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderStatusUI) consume_Windows_Storage_Provider_IStorageProviderStatusUISource<D>::GetStatusUI() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUISource)->GetStatusUI(&result));
        return winrt::Windows::Storage::Provider::StorageProviderStatusUI{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Provider_IStorageProviderStatusUISource<D>::StatusUIChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUISource)->add_StatusUIChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Provider_IStorageProviderStatusUISource<D>::StatusUIChanged_revoker consume_Windows_Storage_Provider_IStorageProviderStatusUISource<D>::StatusUIChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StatusUIChanged_revoker>(this, StatusUIChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderStatusUISource<D>::StatusUIChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUISource)->remove_StatusUIChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderStatusUISource) consume_Windows_Storage_Provider_IStorageProviderStatusUISourceFactory<D>::GetStatusUISource(param::hstring const& syncRootId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory)->GetStatusUISource(*(void**)(&syncRootId), &result));
        return winrt::Windows::Storage::Provider::IStorageProviderStatusUISource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Context() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Context(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Context(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Context(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFolder) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Path(&value));
        return winrt::Windows::Storage::IStorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Path(winrt::Windows::Storage::IStorageFolder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Path(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::DisplayNameResource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_DisplayNameResource(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::DisplayNameResource(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_DisplayNameResource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::IconResource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_IconResource(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::IconResource(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_IconResource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicy() const
    {
        winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_HydrationPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicy(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_HydrationPolicy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicyModifier() const
    {
        winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_HydrationPolicyModifier(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicyModifier(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_HydrationPolicyModifier(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::PopulationPolicy() const
    {
        winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_PopulationPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::PopulationPolicy(winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_PopulationPolicy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::InSyncPolicy() const
    {
        winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_InSyncPolicy(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::InSyncPolicy(winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_InSyncPolicy(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HardlinkPolicy() const
    {
        winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_HardlinkPolicy(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HardlinkPolicy(winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_HardlinkPolicy(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ShowSiblingsAsGroup() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_ShowSiblingsAsGroup(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ShowSiblingsAsGroup(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_ShowSiblingsAsGroup(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Version() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Version(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Version(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Version(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderProtectionMode) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ProtectionMode() const
    {
        winrt::Windows::Storage::Provider::StorageProviderProtectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_ProtectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ProtectionMode(winrt::Windows::Storage::Provider::StorageProviderProtectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_ProtectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::AllowPinning() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_AllowPinning(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::AllowPinning(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_AllowPinning(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition>) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::StorageProviderItemPropertyDefinitions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_StorageProviderItemPropertyDefinitions(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::RecycleBinUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_RecycleBinUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::RecycleBinUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_RecycleBinUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2<D>::ProviderId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2)->get_ProviderId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2<D>::ProviderId(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2)->put_ProviderId(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>) consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo3<D>::FallbackFileTypeInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3)->get_FallbackFileTypeInfo(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::Register(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo const& syncRootInformation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->Register(*(void**)(&syncRootInformation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::Unregister(param::hstring const& id) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->Unregister(*(void**)(&id)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo) consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::GetSyncRootInformationForFolder(winrt::Windows::Storage::IStorageFolder const& folder) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->GetSyncRootInformationForFolder(*(void**)(&folder), &result));
        return winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo) consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::GetSyncRootInformationForId(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->GetSyncRootInformationForId(*(void**)(&id), &result));
        return winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>) consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::GetCurrentSyncRoots() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->GetCurrentSyncRoots(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics2<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderUICommand<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUICommand)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Provider_IStorageProviderUICommand<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUICommand)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Storage_Provider_IStorageProviderUICommand<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUICommand)->get_Icon(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderUICommandState) consume_Windows_Storage_Provider_IStorageProviderUICommand<D>::State() const
    {
        winrt::Windows::Storage::Provider::StorageProviderUICommandState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUICommand)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderUICommand<D>::Invoke() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUICommand)->Invoke());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderUriSource<D>::GetPathForContentUri(param::hstring const& contentUri, winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const& result) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUriSource)->GetPathForContentUri(*(void**)(&contentUri), *(void**)(&result)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Provider_IStorageProviderUriSource<D>::GetContentInfoForPath(param::hstring const& path, winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const& result) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Provider::IStorageProviderUriSource)->GetContentInfoForPath(*(void**)(&path), *(void**)(&result)));
    }
    template <typename H> struct delegate<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler, H> final : implements_delegate<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* args) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics> : produce_base<D, winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics>
    {
        int32_t __stdcall SetUpdateInformation(void* file, void* contentId, int32_t readMode, int32_t writeMode, uint32_t options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetUpdateInformation(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contentId), *reinterpret_cast<winrt::Windows::Storage::Provider::ReadActivationMode const*>(&readMode), *reinterpret_cast<winrt::Windows::Storage::Provider::WriteActivationMode const*>(&writeMode), *reinterpret_cast<winrt::Windows::Storage::Provider::CachedFileOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::ICachedFileUpdaterUI> : produce_base<D, winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>
    {
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
        int32_t __stdcall get_UpdateTarget(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::CachedFileTarget>(this->shim().UpdateTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FileUpdateRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FileUpdateRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FileUpdateRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FileUpdateRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UIRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UIRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UIRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UIRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_UIStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::UIStatus>(this->shim().UIStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2> : produce_base<D, winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2>
    {
        int32_t __stdcall get_UpdateRequest(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::FileUpdateRequest>(this->shim().UpdateRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IFileUpdateRequest> : produce_base<D, winrt::Windows::Storage::Provider::IFileUpdateRequest>
    {
        int32_t __stdcall get_ContentId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::FileUpdateStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::Storage::Provider::FileUpdateStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateLocalFile(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateLocalFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IFileUpdateRequest2> : produce_base<D, winrt::Windows::Storage::Provider::IFileUpdateRequest2>
    {
        int32_t __stdcall get_UserInputNeededMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserInputNeededMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UserInputNeededMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserInputNeededMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral> : produce_base<D, winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral>
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
    struct produce<D, winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs> : produce_base<D, winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::FileUpdateRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo>
    {
        int32_t __stdcall get_FileExtension(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FileExtension());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconResource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IconResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory>
    {
        int32_t __stdcall CreateInstance(void* fileExtension, void* iconResource, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&fileExtension), *reinterpret_cast<hstring const*>(&iconResource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentUri(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Path(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Path(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>
    {
        int32_t __stdcall SetAsync(void* item, void* itemProperties, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageItem const*>(&item), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty> const*>(&itemProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderItemProperty> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderItemProperty>
    {
        int32_t __stdcall put_Id(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<hstring const*>(&value));
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
        int32_t __stdcall put_IconResource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IconResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconResource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IconResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>
    {
        int32_t __stdcall get_Id(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayNameResource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayNameResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayNameResource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayNameResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource>
    {
        int32_t __stdcall GetItemProperties(void* itemPath, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty>>(this->shim().GetItemProperties(*reinterpret_cast<hstring const*>(&itemPath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry>
    {
        int32_t __stdcall get_KnownFolderId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().KnownFolderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KnownFolderId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KnownFolderId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Status(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Status(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo>
    {
        int32_t __stdcall get_ProviderDisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProviderDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderDisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KnownFolderEntries(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry>>(this->shim().KnownFolderEntries());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SyncRequested(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler>(this->shim().SyncRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SyncRequested(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SyncRequested(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>
    {
        int32_t __stdcall GetKnownFolderSyncInfo(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo>(this->shim().GetKnownFolderSyncInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_KnownFolderSyncInfoChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().KnownFolderSyncInfoChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KnownFolderSyncInfoChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KnownFolderSyncInfoChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory>
    {
        int32_t __stdcall GetKnownFolderSyncInfoSource(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>(this->shim().GetKnownFolderSyncInfoSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs>
    {
        int32_t __stdcall get_KnownFolders(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>>(this->shim().KnownFolders());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Message(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Message(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Command(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::IStorageProviderUICommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Command(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Command(*reinterpret_cast<winrt::Windows::Storage::Provider::IStorageProviderUICommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities>
    {
        int32_t __stdcall IsPropertySupported(void* propertyCanonicalName, bool* isSupported) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isSupported = detach_from<bool>(this->shim().IsPropertySupported(*reinterpret_cast<hstring const*>(&propertyCanonicalName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderQuotaUI> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderQuotaUI>
    {
        int32_t __stdcall get_QuotaTotalInBytes(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().QuotaTotalInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QuotaTotalInBytes(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuotaTotalInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QuotaUsedInBytes(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().QuotaUsedInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QuotaUsedInBytes(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuotaUsedInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QuotaUsedLabel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().QuotaUsedLabel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QuotaUsedLabel(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuotaUsedLabel(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QuotaUsedColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().QuotaUsedColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QuotaUsedColor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuotaUsedColor(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderStatusUI> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderStatusUI>
    {
        int32_t __stdcall get_ProviderState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderState>(this->shim().ProviderState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderState(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderState(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderStateLabel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProviderStateLabel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderStateLabel(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderStateLabel(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderStateIcon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ProviderStateIcon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderStateIcon(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderStateIcon(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SyncStatusCommand(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::IStorageProviderUICommand>(this->shim().SyncStatusCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SyncStatusCommand(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SyncStatusCommand(*reinterpret_cast<winrt::Windows::Storage::Provider::IStorageProviderUICommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QuotaUI(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderQuotaUI>(this->shim().QuotaUI());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QuotaUI(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuotaUI(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderQuotaUI const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MoreInfoUI(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI>(this->shim().MoreInfoUI());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MoreInfoUI(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MoreInfoUI(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderPrimaryCommand(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::IStorageProviderUICommand>(this->shim().ProviderPrimaryCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderPrimaryCommand(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderPrimaryCommand(*reinterpret_cast<winrt::Windows::Storage::Provider::IStorageProviderUICommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderSecondaryCommands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::IStorageProviderUICommand>>(this->shim().ProviderSecondaryCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderSecondaryCommands(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderSecondaryCommands(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::IStorageProviderUICommand> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderStatusUISource> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>
    {
        int32_t __stdcall GetStatusUI(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Provider::StorageProviderStatusUI>(this->shim().GetStatusUI());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusUIChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusUIChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusUIChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusUIChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory>
    {
        int32_t __stdcall GetStatusUISource(void* syncRootId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>(this->shim().GetStatusUISource(*reinterpret_cast<hstring const*>(&syncRootId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo>
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
        int32_t __stdcall get_Context(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Context(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Context(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::IStorageFolder>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Path(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Path(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayNameResource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayNameResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayNameResource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayNameResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconResource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IconResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IconResource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IconResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HydrationPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy>(this->shim().HydrationPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HydrationPolicy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HydrationPolicy(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HydrationPolicyModifier(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier>(this->shim().HydrationPolicyModifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HydrationPolicyModifier(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HydrationPolicyModifier(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PopulationPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy>(this->shim().PopulationPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PopulationPolicy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PopulationPolicy(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InSyncPolicy(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy>(this->shim().InSyncPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InSyncPolicy(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InSyncPolicy(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardlinkPolicy(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy>(this->shim().HardlinkPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HardlinkPolicy(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HardlinkPolicy(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShowSiblingsAsGroup(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShowSiblingsAsGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShowSiblingsAsGroup(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowSiblingsAsGroup(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Version(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Version(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Version(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProtectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderProtectionMode>(this->shim().ProtectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProtectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProtectionMode(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderProtectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowPinning(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowPinning());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowPinning(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowPinning(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StorageProviderItemPropertyDefinitions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition>>(this->shim().StorageProviderItemPropertyDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecycleBinUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().RecycleBinUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RecycleBinUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecycleBinUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2>
    {
        int32_t __stdcall get_ProviderId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProviderId(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProviderId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3>
    {
        int32_t __stdcall get_FallbackFileTypeInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>>(this->shim().FallbackFileTypeInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>
    {
        int32_t __stdcall Register(void* syncRootInformation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Register(*reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo const*>(&syncRootInformation));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Unregister(void* id) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Unregister(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSyncRootInformationForFolder(void* folder, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>(this->shim().GetSyncRootInformationForFolder(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSyncRootInformationForId(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>(this->shim().GetSyncRootInformationForId(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentSyncRoots(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>>(this->shim().GetCurrentSyncRoots());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2>
    {
        int32_t __stdcall IsSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderUICommand> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderUICommand>
    {
        int32_t __stdcall get_Label(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Label());
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
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Provider::StorageProviderUICommandState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Invoke() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Invoke();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Provider::IStorageProviderUriSource> : produce_base<D, winrt::Windows::Storage::Provider::IStorageProviderUriSource>
    {
        int32_t __stdcall GetPathForContentUri(void* contentUri, void* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GetPathForContentUri(*reinterpret_cast<hstring const*>(&contentUri), *reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const*>(&result));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetContentInfoForPath(void* path, void* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GetContentInfoForPath(*reinterpret_cast<hstring const*>(&path), *reinterpret_cast<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const*>(&result));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Storage::Provider
{
    constexpr auto operator|(CachedFileOptions const left, CachedFileOptions const right) noexcept
    {
        return static_cast<CachedFileOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(CachedFileOptions& left, CachedFileOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(CachedFileOptions const left, CachedFileOptions const right) noexcept
    {
        return static_cast<CachedFileOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(CachedFileOptions& left, CachedFileOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(CachedFileOptions const value) noexcept
    {
        return static_cast<CachedFileOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(CachedFileOptions const left, CachedFileOptions const right) noexcept
    {
        return static_cast<CachedFileOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(CachedFileOptions& left, CachedFileOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(StorageProviderHardlinkPolicy const left, StorageProviderHardlinkPolicy const right) noexcept
    {
        return static_cast<StorageProviderHardlinkPolicy>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(StorageProviderHardlinkPolicy& left, StorageProviderHardlinkPolicy const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(StorageProviderHardlinkPolicy const left, StorageProviderHardlinkPolicy const right) noexcept
    {
        return static_cast<StorageProviderHardlinkPolicy>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(StorageProviderHardlinkPolicy& left, StorageProviderHardlinkPolicy const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(StorageProviderHardlinkPolicy const value) noexcept
    {
        return static_cast<StorageProviderHardlinkPolicy>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(StorageProviderHardlinkPolicy const left, StorageProviderHardlinkPolicy const right) noexcept
    {
        return static_cast<StorageProviderHardlinkPolicy>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(StorageProviderHardlinkPolicy& left, StorageProviderHardlinkPolicy const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(StorageProviderHydrationPolicyModifier const left, StorageProviderHydrationPolicyModifier const right) noexcept
    {
        return static_cast<StorageProviderHydrationPolicyModifier>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(StorageProviderHydrationPolicyModifier& left, StorageProviderHydrationPolicyModifier const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(StorageProviderHydrationPolicyModifier const left, StorageProviderHydrationPolicyModifier const right) noexcept
    {
        return static_cast<StorageProviderHydrationPolicyModifier>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(StorageProviderHydrationPolicyModifier& left, StorageProviderHydrationPolicyModifier const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(StorageProviderHydrationPolicyModifier const value) noexcept
    {
        return static_cast<StorageProviderHydrationPolicyModifier>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(StorageProviderHydrationPolicyModifier const left, StorageProviderHydrationPolicyModifier const right) noexcept
    {
        return static_cast<StorageProviderHydrationPolicyModifier>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(StorageProviderHydrationPolicyModifier& left, StorageProviderHydrationPolicyModifier const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(StorageProviderInSyncPolicy const left, StorageProviderInSyncPolicy const right) noexcept
    {
        return static_cast<StorageProviderInSyncPolicy>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(StorageProviderInSyncPolicy& left, StorageProviderInSyncPolicy const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(StorageProviderInSyncPolicy const left, StorageProviderInSyncPolicy const right) noexcept
    {
        return static_cast<StorageProviderInSyncPolicy>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(StorageProviderInSyncPolicy& left, StorageProviderInSyncPolicy const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(StorageProviderInSyncPolicy const value) noexcept
    {
        return static_cast<StorageProviderInSyncPolicy>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(StorageProviderInSyncPolicy const left, StorageProviderInSyncPolicy const right) noexcept
    {
        return static_cast<StorageProviderInSyncPolicy>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(StorageProviderInSyncPolicy& left, StorageProviderInSyncPolicy const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto CachedFileUpdater::SetUpdateInformation(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contentId, winrt::Windows::Storage::Provider::ReadActivationMode const& readMode, winrt::Windows::Storage::Provider::WriteActivationMode const& writeMode, winrt::Windows::Storage::Provider::CachedFileOptions const& options)
    {
        impl::call_factory<CachedFileUpdater, ICachedFileUpdaterStatics>([&](ICachedFileUpdaterStatics const& f) { return f.SetUpdateInformation(file, contentId, readMode, writeMode, options); });
    }
    inline StorageProviderFileTypeInfo::StorageProviderFileTypeInfo(param::hstring const& fileExtension, param::hstring const& iconResource) :
        StorageProviderFileTypeInfo(impl::call_factory<StorageProviderFileTypeInfo, IStorageProviderFileTypeInfoFactory>([&](IStorageProviderFileTypeInfoFactory const& f) { return f.CreateInstance(fileExtension, iconResource); }))
    {
    }
    inline StorageProviderGetContentInfoForPathResult::StorageProviderGetContentInfoForPathResult() :
        StorageProviderGetContentInfoForPathResult(impl::call_factory_cast<StorageProviderGetContentInfoForPathResult(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderGetContentInfoForPathResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderGetContentInfoForPathResult>(); }))
    {
    }
    inline StorageProviderGetPathForContentUriResult::StorageProviderGetPathForContentUriResult() :
        StorageProviderGetPathForContentUriResult(impl::call_factory_cast<StorageProviderGetPathForContentUriResult(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderGetPathForContentUriResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderGetPathForContentUriResult>(); }))
    {
    }
    inline auto StorageProviderItemProperties::SetAsync(winrt::Windows::Storage::IStorageItem const& item, param::async_iterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty> const& itemProperties)
    {
        return impl::call_factory<StorageProviderItemProperties, IStorageProviderItemPropertiesStatics>([&](IStorageProviderItemPropertiesStatics const& f) { return f.SetAsync(item, itemProperties); });
    }
    inline StorageProviderItemProperty::StorageProviderItemProperty() :
        StorageProviderItemProperty(impl::call_factory_cast<StorageProviderItemProperty(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderItemProperty>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderItemProperty>(); }))
    {
    }
    inline StorageProviderItemPropertyDefinition::StorageProviderItemPropertyDefinition() :
        StorageProviderItemPropertyDefinition(impl::call_factory_cast<StorageProviderItemPropertyDefinition(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderItemPropertyDefinition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderItemPropertyDefinition>(); }))
    {
    }
    inline StorageProviderKnownFolderEntry::StorageProviderKnownFolderEntry() :
        StorageProviderKnownFolderEntry(impl::call_factory_cast<StorageProviderKnownFolderEntry(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderKnownFolderEntry>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderKnownFolderEntry>(); }))
    {
    }
    inline StorageProviderKnownFolderSyncInfo::StorageProviderKnownFolderSyncInfo() :
        StorageProviderKnownFolderSyncInfo(impl::call_factory_cast<StorageProviderKnownFolderSyncInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderKnownFolderSyncInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderKnownFolderSyncInfo>(); }))
    {
    }
    inline StorageProviderMoreInfoUI::StorageProviderMoreInfoUI() :
        StorageProviderMoreInfoUI(impl::call_factory_cast<StorageProviderMoreInfoUI(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderMoreInfoUI>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderMoreInfoUI>(); }))
    {
    }
    inline StorageProviderQuotaUI::StorageProviderQuotaUI() :
        StorageProviderQuotaUI(impl::call_factory_cast<StorageProviderQuotaUI(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderQuotaUI>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderQuotaUI>(); }))
    {
    }
    inline StorageProviderStatusUI::StorageProviderStatusUI() :
        StorageProviderStatusUI(impl::call_factory_cast<StorageProviderStatusUI(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderStatusUI>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderStatusUI>(); }))
    {
    }
    inline StorageProviderSyncRootInfo::StorageProviderSyncRootInfo() :
        StorageProviderSyncRootInfo(impl::call_factory_cast<StorageProviderSyncRootInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageProviderSyncRootInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageProviderSyncRootInfo>(); }))
    {
    }
    inline auto StorageProviderSyncRootManager::Register(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo const& syncRootInformation)
    {
        impl::call_factory<StorageProviderSyncRootManager, IStorageProviderSyncRootManagerStatics>([&](IStorageProviderSyncRootManagerStatics const& f) { return f.Register(syncRootInformation); });
    }
    inline auto StorageProviderSyncRootManager::Unregister(param::hstring const& id)
    {
        impl::call_factory<StorageProviderSyncRootManager, IStorageProviderSyncRootManagerStatics>([&](IStorageProviderSyncRootManagerStatics const& f) { return f.Unregister(id); });
    }
    inline auto StorageProviderSyncRootManager::GetSyncRootInformationForFolder(winrt::Windows::Storage::IStorageFolder const& folder)
    {
        return impl::call_factory<StorageProviderSyncRootManager, IStorageProviderSyncRootManagerStatics>([&](IStorageProviderSyncRootManagerStatics const& f) { return f.GetSyncRootInformationForFolder(folder); });
    }
    inline auto StorageProviderSyncRootManager::GetSyncRootInformationForId(param::hstring const& id)
    {
        return impl::call_factory<StorageProviderSyncRootManager, IStorageProviderSyncRootManagerStatics>([&](IStorageProviderSyncRootManagerStatics const& f) { return f.GetSyncRootInformationForId(id); });
    }
    inline auto StorageProviderSyncRootManager::GetCurrentSyncRoots()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>(*)(IStorageProviderSyncRootManagerStatics const&), StorageProviderSyncRootManager, IStorageProviderSyncRootManagerStatics>([](IStorageProviderSyncRootManagerStatics const& f) { return f.GetCurrentSyncRoots(); });
    }
    inline auto StorageProviderSyncRootManager::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IStorageProviderSyncRootManagerStatics2 const&), StorageProviderSyncRootManager, IStorageProviderSyncRootManagerStatics2>([](IStorageProviderSyncRootManagerStatics2 const& f) { return f.IsSupported(); });
    }
    template <typename L> StorageProviderKnownFolderSyncRequestedHandler::StorageProviderKnownFolderSyncRequestedHandler(L handler) :
        StorageProviderKnownFolderSyncRequestedHandler(impl::make_delegate<StorageProviderKnownFolderSyncRequestedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> StorageProviderKnownFolderSyncRequestedHandler::StorageProviderKnownFolderSyncRequestedHandler(F* handler) :
        StorageProviderKnownFolderSyncRequestedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> StorageProviderKnownFolderSyncRequestedHandler::StorageProviderKnownFolderSyncRequestedHandler(O* object, M method) :
        StorageProviderKnownFolderSyncRequestedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> StorageProviderKnownFolderSyncRequestedHandler::StorageProviderKnownFolderSyncRequestedHandler(com_ptr<O>&& object, M method) :
        StorageProviderKnownFolderSyncRequestedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> StorageProviderKnownFolderSyncRequestedHandler::StorageProviderKnownFolderSyncRequestedHandler(weak_ref<O>&& object, M method) :
        StorageProviderKnownFolderSyncRequestedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto StorageProviderKnownFolderSyncRequestedHandler::operator()(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestArgs const& args) const
    {
        check_hresult((*(impl::abi_t<StorageProviderKnownFolderSyncRequestedHandler>**)this)->Invoke(*(void**)(&args)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderQuotaUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderStatusUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderUICommand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderUriSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::CachedFileUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::CachedFileUpdaterUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::FileUpdateRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderItemProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderItemProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderQuotaUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderStatusUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderSyncRootManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
