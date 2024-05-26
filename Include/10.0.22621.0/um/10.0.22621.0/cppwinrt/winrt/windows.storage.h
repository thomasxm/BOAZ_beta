// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_H
#define WINRT_Windows_Storage_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/impl/Windows.Storage.Provider.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Storage.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::Cookies() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_Cookies(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::Desktop() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_Desktop(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::Documents() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_Documents(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::Favorites() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_Favorites(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::History() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_History(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::InternetCache() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_InternetCache(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::LocalAppData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_LocalAppData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::ProgramData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_ProgramData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IAppDataPaths<D>::RoamingAppData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPaths)->get_RoamingAppData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::AppDataPaths) consume_Windows_Storage_IAppDataPathsStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPathsStatics)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::Storage::AppDataPaths{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::AppDataPaths) consume_Windows_Storage_IAppDataPathsStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IAppDataPathsStatics)->GetDefault(&result));
        return winrt::Windows::Storage::AppDataPaths{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_IApplicationData<D>::Version() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_Version(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IApplicationData<D>::SetVersionAsync(uint32_t desiredVersion, winrt::Windows::Storage::ApplicationDataSetVersionHandler const& handler) const
    {
        void* setVersionOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->SetVersionAsync(desiredVersion, *(void**)(&handler), &setVersionOperation));
        return winrt::Windows::Foundation::IAsyncAction{ setVersionOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IApplicationData<D>::ClearAsync() const
    {
        void* clearOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->ClearAllAsync(&clearOperation));
        return winrt::Windows::Foundation::IAsyncAction{ clearOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IApplicationData<D>::ClearAsync(winrt::Windows::Storage::ApplicationDataLocality const& locality) const
    {
        void* clearOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->ClearAsync(static_cast<int32_t>(locality), &clearOperation));
        return winrt::Windows::Foundation::IAsyncAction{ clearOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataContainer) consume_Windows_Storage_IApplicationData<D>::LocalSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_LocalSettings(&value));
        return winrt::Windows::Storage::ApplicationDataContainer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataContainer) consume_Windows_Storage_IApplicationData<D>::RoamingSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_RoamingSettings(&value));
        return winrt::Windows::Storage::ApplicationDataContainer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IApplicationData<D>::LocalFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_LocalFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IApplicationData<D>::RoamingFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_RoamingFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IApplicationData<D>::TemporaryFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_TemporaryFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_IApplicationData<D>::DataChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::ApplicationData, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->add_DataChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_IApplicationData<D>::DataChanged_revoker consume_Windows_Storage_IApplicationData<D>::DataChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::ApplicationData, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DataChanged_revoker>(this, DataChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IApplicationData<D>::DataChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->remove_DataChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IApplicationData<D>::SignalDataChanged() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->SignalDataChanged());
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_IApplicationData<D>::RoamingStorageQuota() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData)->get_RoamingStorageQuota(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IApplicationData2<D>::LocalCacheFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData2)->get_LocalCacheFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IApplicationData3<D>::GetPublisherCacheFolder(param::hstring const& folderName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData3)->GetPublisherCacheFolder(*(void**)(&folderName), &value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IApplicationData3<D>::ClearPublisherCacheFolderAsync(param::hstring const& folderName) const
    {
        void* clearOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData3)->ClearPublisherCacheFolderAsync(*(void**)(&folderName), &clearOperation));
        return winrt::Windows::Foundation::IAsyncAction{ clearOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IApplicationData3<D>::SharedLocalFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationData3)->get_SharedLocalFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IApplicationDataContainer<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataContainer)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataLocality) consume_Windows_Storage_IApplicationDataContainer<D>::Locality() const
    {
        winrt::Windows::Storage::ApplicationDataLocality value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataContainer)->get_Locality(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Storage_IApplicationDataContainer<D>::Values() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataContainer)->get_Values(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::ApplicationDataContainer>) consume_Windows_Storage_IApplicationDataContainer<D>::Containers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataContainer)->get_Containers(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::ApplicationDataContainer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataContainer) consume_Windows_Storage_IApplicationDataContainer<D>::CreateContainer(param::hstring const& name, winrt::Windows::Storage::ApplicationDataCreateDisposition const& disposition) const
    {
        void* container{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataContainer)->CreateContainer(*(void**)(&name), static_cast<int32_t>(disposition), &container));
        return winrt::Windows::Storage::ApplicationDataContainer{ container, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IApplicationDataContainer<D>::DeleteContainer(param::hstring const& name) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataContainer)->DeleteContainer(*(void**)(&name)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationData) consume_Windows_Storage_IApplicationDataStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataStatics)->get_Current(&value));
        return winrt::Windows::Storage::ApplicationData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::ApplicationData>) consume_Windows_Storage_IApplicationDataStatics2<D>::GetForUserAsync(winrt::Windows::System::User const& user) const
    {
        void* getForUserOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IApplicationDataStatics2)->GetForUserAsync(*(void**)(&user), &getForUserOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::ApplicationData>{ getForUserOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_ICachedFileManagerStatics<D>::DeferUpdates(winrt::Windows::Storage::IStorageFile const& file) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ICachedFileManagerStatics)->DeferUpdates(*(void**)(&file)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Provider::FileUpdateStatus>) consume_Windows_Storage_ICachedFileManagerStatics<D>::CompleteUpdatesAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ICachedFileManagerStatics)->CompleteUpdatesAsync(*(void**)(&file), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Provider::FileUpdateStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFileAsync(param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics)->CreateFileAsync(*(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFolderAsync(param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics)->CreateFolderAsync(*(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFileAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics)->CreateFileWithCollisionOptionAsync(*(void**)(&desiredName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFolderAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics)->CreateFolderWithCollisionOptionAsync(*(void**)(&desiredName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFileForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics2)->CreateFileForUserAsync(*(void**)(&user), *(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFolderForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics2)->CreateFolderForUserAsync(*(void**)(&user), *(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFileForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics2)->CreateFileForUserWithCollisionOptionAsync(*(void**)(&user), *(void**)(&desiredName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFolderForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IDownloadsFolderStatics2)->CreateFolderForUserWithCollisionOptionAsync(*(void**)(&user), *(void**)(&desiredName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Storage_IFileIOStatics<D>::ReadTextAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->ReadTextAsync(*(void**)(&file), &textOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Storage_IFileIOStatics<D>::ReadTextAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->ReadTextWithEncodingAsync(*(void**)(&file), static_cast<int32_t>(encoding), &textOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::WriteTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->WriteTextAsync(*(void**)(&file), *(void**)(&contents), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::WriteTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->WriteTextWithEncodingAsync(*(void**)(&file), *(void**)(&contents), static_cast<int32_t>(encoding), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::AppendTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->AppendTextAsync(*(void**)(&file), *(void**)(&contents), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::AppendTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->AppendTextWithEncodingAsync(*(void**)(&file), *(void**)(&contents), static_cast<int32_t>(encoding), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) consume_Windows_Storage_IFileIOStatics<D>::ReadLinesAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* linesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->ReadLinesAsync(*(void**)(&file), &linesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>{ linesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) consume_Windows_Storage_IFileIOStatics<D>::ReadLinesAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* linesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->ReadLinesWithEncodingAsync(*(void**)(&file), static_cast<int32_t>(encoding), &linesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>{ linesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::WriteLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->WriteLinesAsync(*(void**)(&file), *(void**)(&lines), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::WriteLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->WriteLinesWithEncodingAsync(*(void**)(&file), *(void**)(&lines), static_cast<int32_t>(encoding), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::AppendLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->AppendLinesAsync(*(void**)(&file), *(void**)(&lines), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::AppendLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->AppendLinesWithEncodingAsync(*(void**)(&file), *(void**)(&lines), static_cast<int32_t>(encoding), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Storage_IFileIOStatics<D>::ReadBufferAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->ReadBufferAsync(*(void**)(&file), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::WriteBufferAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->WriteBufferAsync(*(void**)(&file), *(void**)(&buffer), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IFileIOStatics<D>::WriteBytesAsync(winrt::Windows::Storage::IStorageFile const& file, array_view<uint8_t const> buffer) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IFileIOStatics)->WriteBytesAsync(*(void**)(&file), buffer.size(), get_abi(buffer), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersCameraRollStatics<D>::CameraRoll() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersCameraRollStatics)->get_CameraRoll(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersPlaylistsStatics<D>::Playlists() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersPlaylistsStatics)->get_Playlists(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersSavedPicturesStatics<D>::SavedPictures() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics)->get_SavedPictures(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::MusicLibrary() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_MusicLibrary(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::PicturesLibrary() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_PicturesLibrary(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::VideosLibrary() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_VideosLibrary(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::DocumentsLibrary() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_DocumentsLibrary(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::HomeGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_HomeGroup(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::RemovableDevices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_RemovableDevices(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics<D>::MediaServerDevices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics)->get_MediaServerDevices(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics2<D>::Objects3D() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics2)->get_Objects3D(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics2<D>::AppCaptures() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics2)->get_AppCaptures(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IKnownFoldersStatics2<D>::RecordedCalls() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics2)->get_RecordedCalls(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IKnownFoldersStatics3<D>::GetFolderForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownFolderId const& folderId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics3)->GetFolderForUserAsync(*(void**)(&user), static_cast<int32_t>(folderId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>) consume_Windows_Storage_IKnownFoldersStatics4<D>::RequestAccessAsync(winrt::Windows::Storage::KnownFolderId const& folderId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics4)->RequestAccessAsync(static_cast<int32_t>(folderId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>) consume_Windows_Storage_IKnownFoldersStatics4<D>::RequestAccessForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownFolderId const& folderId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics4)->RequestAccessForUserAsync(*(void**)(&user), static_cast<int32_t>(folderId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IKnownFoldersStatics4<D>::GetFolderAsync(winrt::Windows::Storage::KnownFolderId const& folderId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IKnownFoldersStatics4)->GetFolderAsync(static_cast<int32_t>(folderId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Storage_IPathIOStatics<D>::ReadTextAsync(param::hstring const& absolutePath) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->ReadTextAsync(*(void**)(&absolutePath), &textOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Storage_IPathIOStatics<D>::ReadTextAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->ReadTextWithEncodingAsync(*(void**)(&absolutePath), static_cast<int32_t>(encoding), &textOperation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->WriteTextAsync(*(void**)(&absolutePath), *(void**)(&contents), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->WriteTextWithEncodingAsync(*(void**)(&absolutePath), *(void**)(&contents), static_cast<int32_t>(encoding), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->AppendTextAsync(*(void**)(&absolutePath), *(void**)(&contents), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* textOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->AppendTextWithEncodingAsync(*(void**)(&absolutePath), *(void**)(&contents), static_cast<int32_t>(encoding), &textOperation));
        return winrt::Windows::Foundation::IAsyncAction{ textOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) consume_Windows_Storage_IPathIOStatics<D>::ReadLinesAsync(param::hstring const& absolutePath) const
    {
        void* linesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->ReadLinesAsync(*(void**)(&absolutePath), &linesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>{ linesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) consume_Windows_Storage_IPathIOStatics<D>::ReadLinesAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* linesOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->ReadLinesWithEncodingAsync(*(void**)(&absolutePath), static_cast<int32_t>(encoding), &linesOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>{ linesOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->WriteLinesAsync(*(void**)(&absolutePath), *(void**)(&lines), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->WriteLinesWithEncodingAsync(*(void**)(&absolutePath), *(void**)(&lines), static_cast<int32_t>(encoding), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->AppendLinesAsync(*(void**)(&absolutePath), *(void**)(&lines), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->AppendLinesWithEncodingAsync(*(void**)(&absolutePath), *(void**)(&lines), static_cast<int32_t>(encoding), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Storage_IPathIOStatics<D>::ReadBufferAsync(param::hstring const& absolutePath) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->ReadBufferAsync(*(void**)(&absolutePath), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::WriteBufferAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->WriteBufferAsync(*(void**)(&absolutePath), *(void**)(&buffer), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IPathIOStatics<D>::WriteBytesAsync(param::hstring const& absolutePath, array_view<uint8_t const> buffer) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IPathIOStatics)->WriteBytesAsync(*(void**)(&absolutePath), buffer.size(), get_abi(buffer), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_ISetVersionDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISetVersionDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_ISetVersionRequest<D>::CurrentVersion() const
    {
        uint32_t currentVersion{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISetVersionRequest)->get_CurrentVersion(&currentVersion));
        return currentVersion;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_ISetVersionRequest<D>::DesiredVersion() const
    {
        uint32_t desiredVersion{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISetVersionRequest)->get_DesiredVersion(&desiredVersion));
        return desiredVersion;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SetVersionDeferral) consume_Windows_Storage_ISetVersionRequest<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISetVersionRequest)->GetDeferral(&deferral));
        return winrt::Windows::Storage::SetVersionDeferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageFile<D>::FileType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->get_FileType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageFile<D>::ContentType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->get_ContentType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Storage_IStorageFile<D>::OpenAsync(winrt::Windows::Storage::FileAccessMode const& accessMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->OpenAsync(static_cast<int32_t>(accessMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) consume_Windows_Storage_IStorageFile<D>::OpenTransactedWriteAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->OpenTransactedWriteAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFile<D>::CopyAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->CopyOverloadDefaultNameAndOptions(*(void**)(&destinationFolder), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFile<D>::CopyAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->CopyOverloadDefaultOptions(*(void**)(&destinationFolder), *(void**)(&desiredNewName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFile<D>::CopyAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName, winrt::Windows::Storage::NameCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->CopyOverload(*(void**)(&destinationFolder), *(void**)(&desiredNewName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageFile<D>::CopyAndReplaceAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->CopyAndReplaceAsync(*(void**)(&fileToReplace), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageFile<D>::MoveAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->MoveOverloadDefaultNameAndOptions(*(void**)(&destinationFolder), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageFile<D>::MoveAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->MoveOverloadDefaultOptions(*(void**)(&destinationFolder), *(void**)(&desiredNewName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageFile<D>::MoveAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName, winrt::Windows::Storage::NameCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->MoveOverload(*(void**)(&destinationFolder), *(void**)(&desiredNewName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageFile<D>::MoveAndReplaceAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile)->MoveAndReplaceAsync(*(void**)(&fileToReplace), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Storage_IStorageFile2<D>::OpenAsync(winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile2)->OpenWithOptionsAsync(static_cast<int32_t>(accessMode), static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) consume_Windows_Storage_IStorageFile2<D>::OpenTransactedWriteAsync(winrt::Windows::Storage::StorageOpenOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFile2)->OpenTransactedWriteWithOptionsAsync(static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_IStorageFilePropertiesWithAvailability<D>::IsAvailable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFilePropertiesWithAvailability)->get_IsAvailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics<D>::GetFileFromPathAsync(param::hstring const& path) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics)->GetFileFromPathAsync(*(void**)(&path), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics<D>::GetFileFromApplicationUriAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics)->GetFileFromApplicationUriAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics<D>::CreateStreamedFileAsync(param::hstring const& displayNameWithExtension, winrt::Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics)->CreateStreamedFileAsync(*(void**)(&displayNameWithExtension), *(void**)(&dataRequested), *(void**)(&thumbnail), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics<D>::ReplaceWithStreamedFileAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace, winrt::Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics)->ReplaceWithStreamedFileAsync(*(void**)(&fileToReplace), *(void**)(&dataRequested), *(void**)(&thumbnail), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics<D>::CreateStreamedFileFromUriAsync(param::hstring const& displayNameWithExtension, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics)->CreateStreamedFileFromUriAsync(*(void**)(&displayNameWithExtension), *(void**)(&uri), *(void**)(&thumbnail), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics<D>::ReplaceWithStreamedFileFromUriAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics)->ReplaceWithStreamedFileFromUriAsync(*(void**)(&fileToReplace), *(void**)(&uri), *(void**)(&thumbnail), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFileStatics2<D>::GetFileFromPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFileStatics2)->GetFileFromPathForUserAsync(*(void**)(&user), *(void**)(&path), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFolder<D>::CreateFileAsync(param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->CreateFileAsyncOverloadDefaultOptions(*(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFolder<D>::CreateFileAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->CreateFileAsync(*(void**)(&desiredName), static_cast<int32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageFolder<D>::CreateFolderAsync(param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->CreateFolderAsyncOverloadDefaultOptions(*(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageFolder<D>::CreateFolderAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->CreateFolderAsync(*(void**)(&desiredName), static_cast<int32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_IStorageFolder<D>::GetFileAsync(param::hstring const& name) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->GetFileAsync(*(void**)(&name), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageFolder<D>::GetFolderAsync(param::hstring const& name) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->GetFolderAsync(*(void**)(&name), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>) consume_Windows_Storage_IStorageFolder<D>::GetItemAsync(param::hstring const& name) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->GetItemAsync(*(void**)(&name), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>) consume_Windows_Storage_IStorageFolder<D>::GetFilesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->GetFilesAsyncOverloadDefaultOptionsStartAndCount(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFolder>>) consume_Windows_Storage_IStorageFolder<D>::GetFoldersAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->GetFoldersAsyncOverloadDefaultOptionsStartAndCount(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFolder>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>) consume_Windows_Storage_IStorageFolder<D>::GetItemsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder)->GetItemsAsyncOverloadDefaultStartAndCount(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>) consume_Windows_Storage_IStorageFolder2<D>::TryGetItemAsync(param::hstring const& name) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder2)->TryGetItemAsync(*(void**)(&name), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeTracker) consume_Windows_Storage_IStorageFolder3<D>::TryGetChangeTracker() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolder3)->TryGetChangeTracker(&result));
        return winrt::Windows::Storage::StorageLibraryChangeTracker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageFolderStatics<D>::GetFolderFromPathAsync(param::hstring const& path) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolderStatics)->GetFolderFromPathAsync(*(void**)(&path), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageFolderStatics2<D>::GetFolderFromPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageFolderStatics2)->GetFolderFromPathForUserAsync(*(void**)(&user), *(void**)(&path), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageItem<D>::RenameAsync(param::hstring const& desiredName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->RenameAsyncOverloadDefaultOptions(*(void**)(&desiredName), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageItem<D>::RenameAsync(param::hstring const& desiredName, winrt::Windows::Storage::NameCollisionOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->RenameAsync(*(void**)(&desiredName), static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageItem<D>::DeleteAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->DeleteAsyncOverloadDefaultOptions(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageItem<D>::DeleteAsync(winrt::Windows::Storage::StorageDeleteOption const& option) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->DeleteAsync(static_cast<int32_t>(option), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::BasicProperties>) consume_Windows_Storage_IStorageItem<D>::GetBasicPropertiesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->GetBasicPropertiesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::BasicProperties>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageItem<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageItem<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->get_Path(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::FileAttributes) consume_Windows_Storage_IStorageItem<D>::Attributes() const
    {
        winrt::Windows::Storage::FileAttributes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->get_Attributes(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Storage_IStorageItem<D>::DateCreated() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->get_DateCreated(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_IStorageItem<D>::IsOfType(winrt::Windows::Storage::StorageItemTypes const& type) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem)->IsOfType(static_cast<uint32_t>(type), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageItem2<D>::GetParentAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem2)->GetParentAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_IStorageItem2<D>::IsEqual(winrt::Windows::Storage::IStorageItem const& item) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItem2)->IsEqual(*(void**)(&item), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) consume_Windows_Storage_IStorageItemProperties<D>::GetThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->GetThumbnailAsyncOverloadDefaultSizeDefaultOptions(static_cast<int32_t>(mode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) consume_Windows_Storage_IStorageItemProperties<D>::GetThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->GetThumbnailAsyncOverloadDefaultOptions(static_cast<int32_t>(mode), requestedSize, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) consume_Windows_Storage_IStorageItemProperties<D>::GetThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->GetThumbnailAsync(static_cast<int32_t>(mode), requestedSize, static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageItemProperties<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageItemProperties<D>::DisplayType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->get_DisplayType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageItemProperties<D>::FolderRelativeId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->get_FolderRelativeId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::StorageItemContentProperties) consume_Windows_Storage_IStorageItemProperties<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties)->get_Properties(&value));
        return winrt::Windows::Storage::FileProperties::StorageItemContentProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) consume_Windows_Storage_IStorageItemProperties2<D>::GetScaledImageAsThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties2)->GetScaledImageAsThumbnailAsyncOverloadDefaultSizeDefaultOptions(static_cast<int32_t>(mode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) consume_Windows_Storage_IStorageItemProperties2<D>::GetScaledImageAsThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties2)->GetScaledImageAsThumbnailAsyncOverloadDefaultOptions(static_cast<int32_t>(mode), requestedSize, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) consume_Windows_Storage_IStorageItemProperties2<D>::GetScaledImageAsThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemProperties2)->GetScaledImageAsThumbnailAsync(static_cast<int32_t>(mode), requestedSize, static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageProvider) consume_Windows_Storage_IStorageItemPropertiesWithProvider<D>::Provider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageItemPropertiesWithProvider)->get_Provider(&value));
        return winrt::Windows::Storage::StorageProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageLibrary<D>::RequestAddFolderAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary)->RequestAddFolderAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Storage_IStorageLibrary<D>::RequestRemoveFolderAsync(winrt::Windows::Storage::StorageFolder const& folder) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary)->RequestRemoveFolderAsync(*(void**)(&folder), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_IStorageLibrary<D>::Folders() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary)->get_Folders(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Storage::StorageFolder>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) consume_Windows_Storage_IStorageLibrary<D>::SaveFolder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary)->get_SaveFolder(&value));
        return winrt::Windows::Storage::StorageFolder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::StorageLibrary, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary)->add_DefinitionChanged(*(void**)(&handler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged_revoker consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::StorageLibrary, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DefinitionChanged_revoker>(this, DefinitionChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary)->remove_DefinitionChanged(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeTracker) consume_Windows_Storage_IStorageLibrary2<D>::ChangeTracker() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary2)->get_ChangeTracker(&value));
        return winrt::Windows::Storage::StorageLibraryChangeTracker{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Storage_IStorageLibrary3<D>::AreFolderSuggestionsAvailableAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibrary3)->AreFolderSuggestionsAvailableAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeType) consume_Windows_Storage_IStorageLibraryChange<D>::ChangeType() const
    {
        winrt::Windows::Storage::StorageLibraryChangeType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChange)->get_ChangeType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageLibraryChange<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChange)->get_Path(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageLibraryChange<D>::PreviousPath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChange)->get_PreviousPath(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_IStorageLibraryChange<D>::IsOfType(winrt::Windows::Storage::StorageItemTypes const& type) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChange)->IsOfType(static_cast<uint32_t>(type), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>) consume_Windows_Storage_IStorageLibraryChange<D>::GetStorageItemAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChange)->GetStorageItemAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageLibraryChange>>) consume_Windows_Storage_IStorageLibraryChangeReader<D>::ReadBatchAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeReader)->ReadBatchAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageLibraryChange>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageLibraryChangeReader<D>::AcceptChangesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeReader)->AcceptChangesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_IStorageLibraryChangeReader2<D>::GetLastChangeId() const
    {
        uint64_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeReader2)->GetLastChangeId(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeReader) consume_Windows_Storage_IStorageLibraryChangeTracker<D>::GetChangeReader() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTracker)->GetChangeReader(&value));
        return winrt::Windows::Storage::StorageLibraryChangeReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStorageLibraryChangeTracker<D>::Enable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTracker)->Enable());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStorageLibraryChangeTracker<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTracker)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStorageLibraryChangeTracker2<D>::Enable(winrt::Windows::Storage::StorageLibraryChangeTrackerOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTracker2)->EnableWithOptions(*(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStorageLibraryChangeTracker2<D>::Disable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTracker2)->Disable());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_IStorageLibraryChangeTrackerOptions<D>::TrackChangeDetails() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions)->get_TrackChangeDetails(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStorageLibraryChangeTrackerOptions<D>::TrackChangeDetails(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions)->put_TrackChangeDetails(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_IStorageLibraryLastChangeIdStatics<D>::Unknown() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics)->get_Unknown(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>) consume_Windows_Storage_IStorageLibraryStatics<D>::GetLibraryAsync(winrt::Windows::Storage::KnownLibraryId const& libraryId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryStatics)->GetLibraryAsync(static_cast<int32_t>(libraryId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>) consume_Windows_Storage_IStorageLibraryStatics2<D>::GetLibraryForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownLibraryId const& libraryId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageLibraryStatics2)->GetLibraryForUserAsync(*(void**)(&user), static_cast<int32_t>(libraryId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageProvider<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageProvider)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IStorageProvider<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageProvider)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Storage_IStorageProvider2<D>::IsPropertySupportedForPartialFileAsync(param::hstring const& propertyCanonicalName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageProvider2)->IsPropertySupportedForPartialFileAsync(*(void**)(&propertyCanonicalName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) consume_Windows_Storage_IStorageStreamTransaction<D>::Stream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageStreamTransaction)->get_Stream(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Storage_IStorageStreamTransaction<D>::CommitAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStorageStreamTransaction)->CommitAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_IStreamedFileDataRequest<D>::FailAndClose(winrt::Windows::Storage::StreamedFileFailureMode const& failureMode) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IStreamedFileDataRequest)->FailAndClose(static_cast<int32_t>(failureMode)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemAudioProperties<D>::EncodingBitrate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemAudioProperties)->get_EncodingBitrate(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::Fonts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_Fonts(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::ProgramData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_ProgramData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::Public() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_Public(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::PublicDesktop() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_PublicDesktop(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::PublicDocuments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_PublicDocuments(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::PublicDownloads() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_PublicDownloads(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::PublicMusic() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_PublicMusic(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::PublicPictures() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_PublicPictures(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::PublicVideos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_PublicVideos(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::System() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_System(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::SystemHost() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_SystemHost(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::SystemX86() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_SystemX86(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::SystemX64() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_SystemX64(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::SystemArm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_SystemArm(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::UserProfiles() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_UserProfiles(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemDataPaths<D>::Windows() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPaths)->get_Windows(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemDataPaths) consume_Windows_Storage_ISystemDataPathsStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemDataPathsStatics)->GetDefault(&result));
        return winrt::Windows::Storage::SystemDataPaths{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemGPSProperties<D>::LatitudeDecimal() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemGPSProperties)->get_LatitudeDecimal(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemGPSProperties<D>::LongitudeDecimal() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemGPSProperties)->get_LongitudeDecimal(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemImageProperties<D>::HorizontalSize() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemImageProperties)->get_HorizontalSize(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemImageProperties<D>::VerticalSize() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemImageProperties)->get_VerticalSize(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMediaProperties<D>::Duration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMediaProperties)->get_Duration(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMediaProperties<D>::Producer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMediaProperties)->get_Producer(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMediaProperties<D>::Publisher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMediaProperties)->get_Publisher(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMediaProperties<D>::SubTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMediaProperties)->get_SubTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMediaProperties<D>::Writer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMediaProperties)->get_Writer(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMediaProperties<D>::Year() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMediaProperties)->get_Year(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::AlbumArtist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_AlbumArtist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::AlbumTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_AlbumTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::Artist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_Artist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::Composer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_Composer(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::Conductor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_Conductor(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::DisplayArtist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_DisplayArtist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::Genre() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_Genre(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemMusicProperties<D>::TrackNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemMusicProperties)->get_TrackNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemPhotoProperties<D>::CameraManufacturer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemPhotoProperties)->get_CameraManufacturer(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemPhotoProperties<D>::CameraModel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemPhotoProperties)->get_CameraModel(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemPhotoProperties<D>::DateTaken() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemPhotoProperties)->get_DateTaken(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemPhotoProperties<D>::Orientation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemPhotoProperties)->get_Orientation(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemPhotoProperties<D>::PeopleNames() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemPhotoProperties)->get_PeopleNames(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemProperties<D>::Author() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Author(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemProperties<D>::Comment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Comment(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemProperties<D>::ItemNameDisplay() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_ItemNameDisplay(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemProperties<D>::Keywords() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Keywords(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemProperties<D>::Rating() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Rating(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemProperties<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemAudioProperties) consume_Windows_Storage_ISystemProperties<D>::Audio() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Audio(&value));
        return winrt::Windows::Storage::SystemAudioProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemGPSProperties) consume_Windows_Storage_ISystemProperties<D>::GPS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_GPS(&value));
        return winrt::Windows::Storage::SystemGPSProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemMediaProperties) consume_Windows_Storage_ISystemProperties<D>::Media() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Media(&value));
        return winrt::Windows::Storage::SystemMediaProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemMusicProperties) consume_Windows_Storage_ISystemProperties<D>::Music() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Music(&value));
        return winrt::Windows::Storage::SystemMusicProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemPhotoProperties) consume_Windows_Storage_ISystemProperties<D>::Photo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Photo(&value));
        return winrt::Windows::Storage::SystemPhotoProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemVideoProperties) consume_Windows_Storage_ISystemProperties<D>::Video() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Video(&value));
        return winrt::Windows::Storage::SystemVideoProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemImageProperties) consume_Windows_Storage_ISystemProperties<D>::Image() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemProperties)->get_Image(&value));
        return winrt::Windows::Storage::SystemImageProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemVideoProperties<D>::Director() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemVideoProperties)->get_Director(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemVideoProperties<D>::FrameHeight() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemVideoProperties)->get_FrameHeight(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemVideoProperties<D>::FrameWidth() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemVideoProperties)->get_FrameWidth(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemVideoProperties<D>::Orientation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemVideoProperties)->get_Orientation(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_ISystemVideoProperties<D>::TotalBitrate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::ISystemVideoProperties)->get_TotalBitrate(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::CameraRoll() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_CameraRoll(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Cookies() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Cookies(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Desktop() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Desktop(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Documents() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Documents(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Downloads() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Downloads(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Favorites() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Favorites(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::History() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_History(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::InternetCache() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_InternetCache(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::LocalAppData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_LocalAppData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::LocalAppDataLow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_LocalAppDataLow(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Music() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Music(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Pictures() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Pictures(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Profile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Profile(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Recent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Recent(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::RoamingAppData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_RoamingAppData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::SavedPictures() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_SavedPictures(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Screenshots() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Screenshots(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Templates() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Templates(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_IUserDataPaths<D>::Videos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPaths)->get_Videos(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::UserDataPaths) consume_Windows_Storage_IUserDataPathsStatics<D>::GetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPathsStatics)->GetForUser(*(void**)(&user), &result));
        return winrt::Windows::Storage::UserDataPaths{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::UserDataPaths) consume_Windows_Storage_IUserDataPathsStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::IUserDataPathsStatics)->GetDefault(&result));
        return winrt::Windows::Storage::UserDataPaths{ result, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Storage::ApplicationDataSetVersionHandler, H> final : implements_delegate<winrt::Windows::Storage::ApplicationDataSetVersionHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Storage::ApplicationDataSetVersionHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* setVersionRequest) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Storage::SetVersionRequest const*>(&setVersionRequest));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::Storage::StreamedFileDataRequestedHandler, H> final : implements_delegate<winrt::Windows::Storage::StreamedFileDataRequestedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Storage::StreamedFileDataRequestedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* stream) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Storage::StreamedFileDataRequest const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IAppDataPaths> : produce_base<D, winrt::Windows::Storage::IAppDataPaths>
    {
        int32_t __stdcall get_Cookies(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Cookies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Desktop(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Desktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Documents(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Documents());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Favorites(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Favorites());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_History(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().History());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InternetCache(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InternetCache());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalAppData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProgramData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProgramData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoamingAppData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RoamingAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IAppDataPathsStatics> : produce_base<D, winrt::Windows::Storage::IAppDataPathsStatics>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::AppDataPaths>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::AppDataPaths>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IApplicationData> : produce_base<D, winrt::Windows::Storage::IApplicationData>
    {
        int32_t __stdcall get_Version(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetVersionAsync(uint32_t desiredVersion, void* handler, void** setVersionOperation) noexcept final try
        {
            clear_abi(setVersionOperation);
            typename D::abi_guard guard(this->shim());
            *setVersionOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetVersionAsync(desiredVersion, *reinterpret_cast<winrt::Windows::Storage::ApplicationDataSetVersionHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearAllAsync(void** clearOperation) noexcept final try
        {
            clear_abi(clearOperation);
            typename D::abi_guard guard(this->shim());
            *clearOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ClearAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearAsync(int32_t locality, void** clearOperation) noexcept final try
        {
            clear_abi(clearOperation);
            typename D::abi_guard guard(this->shim());
            *clearOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ClearAsync(*reinterpret_cast<winrt::Windows::Storage::ApplicationDataLocality const*>(&locality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::ApplicationDataContainer>(this->shim().LocalSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoamingSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::ApplicationDataContainer>(this->shim().RoamingSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().LocalFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoamingFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().RoamingFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TemporaryFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().TemporaryFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DataChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DataChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::ApplicationData, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DataChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall SignalDataChanged() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignalDataChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoamingStorageQuota(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().RoamingStorageQuota());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IApplicationData2> : produce_base<D, winrt::Windows::Storage::IApplicationData2>
    {
        int32_t __stdcall get_LocalCacheFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().LocalCacheFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IApplicationData3> : produce_base<D, winrt::Windows::Storage::IApplicationData3>
    {
        int32_t __stdcall GetPublisherCacheFolder(void* folderName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().GetPublisherCacheFolder(*reinterpret_cast<hstring const*>(&folderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearPublisherCacheFolderAsync(void* folderName, void** clearOperation) noexcept final try
        {
            clear_abi(clearOperation);
            typename D::abi_guard guard(this->shim());
            *clearOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ClearPublisherCacheFolderAsync(*reinterpret_cast<hstring const*>(&folderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharedLocalFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().SharedLocalFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IApplicationDataContainer> : produce_base<D, winrt::Windows::Storage::IApplicationDataContainer>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Locality(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::ApplicationDataLocality>(this->shim().Locality());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Values(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Containers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::ApplicationDataContainer>>(this->shim().Containers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateContainer(void* name, int32_t disposition, void** container) noexcept final try
        {
            clear_abi(container);
            typename D::abi_guard guard(this->shim());
            *container = detach_from<winrt::Windows::Storage::ApplicationDataContainer>(this->shim().CreateContainer(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Storage::ApplicationDataCreateDisposition const*>(&disposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteContainer(void* name) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeleteContainer(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IApplicationDataStatics> : produce_base<D, winrt::Windows::Storage::IApplicationDataStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::ApplicationData>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IApplicationDataStatics2> : produce_base<D, winrt::Windows::Storage::IApplicationDataStatics2>
    {
        int32_t __stdcall GetForUserAsync(void* user, void** getForUserOperation) noexcept final try
        {
            clear_abi(getForUserOperation);
            typename D::abi_guard guard(this->shim());
            *getForUserOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::ApplicationData>>(this->shim().GetForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ICachedFileManagerStatics> : produce_base<D, winrt::Windows::Storage::ICachedFileManagerStatics>
    {
        int32_t __stdcall DeferUpdates(void* file) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeferUpdates(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CompleteUpdatesAsync(void* file, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Provider::FileUpdateStatus>>(this->shim().CompleteUpdatesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IDownloadsFolderStatics> : produce_base<D, winrt::Windows::Storage::IDownloadsFolderStatics>
    {
        int32_t __stdcall CreateFileAsync(void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderAsync(void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileWithCollisionOptionAsync(void* desiredName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderWithCollisionOptionAsync(void* desiredName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IDownloadsFolderStatics2> : produce_base<D, winrt::Windows::Storage::IDownloadsFolderStatics2>
    {
        int32_t __stdcall CreateFileForUserAsync(void* user, void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateFileForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderForUserAsync(void* user, void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().CreateFolderForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileForUserWithCollisionOptionAsync(void* user, void* desiredName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateFileForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderForUserWithCollisionOptionAsync(void* user, void* desiredName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().CreateFolderForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IFileIOStatics> : produce_base<D, winrt::Windows::Storage::IFileIOStatics>
    {
        int32_t __stdcall ReadTextAsync(void* file, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadTextWithEncodingAsync(void* file, int32_t encoding, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteTextAsync(void* file, void* contents, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteTextWithEncodingAsync(void* file, void* contents, int32_t encoding, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendTextAsync(void* file, void* contents, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendTextWithEncodingAsync(void* file, void* contents, int32_t encoding, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadLinesAsync(void* file, void** linesOperation) noexcept final try
        {
            clear_abi(linesOperation);
            typename D::abi_guard guard(this->shim());
            *linesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadLinesWithEncodingAsync(void* file, int32_t encoding, void** linesOperation) noexcept final try
        {
            clear_abi(linesOperation);
            typename D::abi_guard guard(this->shim());
            *linesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteLinesAsync(void* file, void* lines, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteLinesWithEncodingAsync(void* file, void* lines, int32_t encoding, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendLinesAsync(void* file, void* lines, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendLinesWithEncodingAsync(void* file, void* lines, int32_t encoding, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBufferAsync(void* file, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().ReadBufferAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBufferAsync(void* file, void* buffer, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteBufferAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBytesAsync(void* file, uint32_t __bufferSize, uint8_t* buffer, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteBytesAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersCameraRollStatics> : produce_base<D, winrt::Windows::Storage::IKnownFoldersCameraRollStatics>
    {
        int32_t __stdcall get_CameraRoll(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().CameraRoll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersPlaylistsStatics> : produce_base<D, winrt::Windows::Storage::IKnownFoldersPlaylistsStatics>
    {
        int32_t __stdcall get_Playlists(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().Playlists());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics> : produce_base<D, winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics>
    {
        int32_t __stdcall get_SavedPictures(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().SavedPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersStatics> : produce_base<D, winrt::Windows::Storage::IKnownFoldersStatics>
    {
        int32_t __stdcall get_MusicLibrary(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().MusicLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PicturesLibrary(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().PicturesLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideosLibrary(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().VideosLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentsLibrary(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().DocumentsLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HomeGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().HomeGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemovableDevices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().RemovableDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaServerDevices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().MediaServerDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersStatics2> : produce_base<D, winrt::Windows::Storage::IKnownFoldersStatics2>
    {
        int32_t __stdcall get_Objects3D(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().Objects3D());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppCaptures(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().AppCaptures());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecordedCalls(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().RecordedCalls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersStatics3> : produce_base<D, winrt::Windows::Storage::IKnownFoldersStatics3>
    {
        int32_t __stdcall GetFolderForUserAsync(void* user, int32_t folderId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetFolderForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Storage::KnownFolderId const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IKnownFoldersStatics4> : produce_base<D, winrt::Windows::Storage::IKnownFoldersStatics4>
    {
        int32_t __stdcall RequestAccessAsync(int32_t folderId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>>(this->shim().RequestAccessAsync(*reinterpret_cast<winrt::Windows::Storage::KnownFolderId const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessForUserAsync(void* user, int32_t folderId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>>(this->shim().RequestAccessForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Storage::KnownFolderId const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFolderAsync(int32_t folderId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<winrt::Windows::Storage::KnownFolderId const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IPathIOStatics> : produce_base<D, winrt::Windows::Storage::IPathIOStatics>
    {
        int32_t __stdcall ReadTextAsync(void* absolutePath, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<hstring const*>(&absolutePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadTextWithEncodingAsync(void* absolutePath, int32_t encoding, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteTextAsync(void* absolutePath, void* contents, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteTextWithEncodingAsync(void* absolutePath, void* contents, int32_t encoding, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendTextAsync(void* absolutePath, void* contents, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendTextWithEncodingAsync(void* absolutePath, void* contents, int32_t encoding, void** textOperation) noexcept final try
        {
            clear_abi(textOperation);
            typename D::abi_guard guard(this->shim());
            *textOperation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadLinesAsync(void* absolutePath, void** linesOperation) noexcept final try
        {
            clear_abi(linesOperation);
            typename D::abi_guard guard(this->shim());
            *linesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadLinesWithEncodingAsync(void* absolutePath, int32_t encoding, void** linesOperation) noexcept final try
        {
            clear_abi(linesOperation);
            typename D::abi_guard guard(this->shim());
            *linesOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteLinesAsync(void* absolutePath, void* lines, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteLinesWithEncodingAsync(void* absolutePath, void* lines, int32_t encoding, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendLinesAsync(void* absolutePath, void* lines, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendLinesWithEncodingAsync(void* absolutePath, void* lines, int32_t encoding, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBufferAsync(void* absolutePath, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().ReadBufferAsync(*reinterpret_cast<hstring const*>(&absolutePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBufferAsync(void* absolutePath, void* buffer, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteBufferAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBytesAsync(void* absolutePath, uint32_t __bufferSize, uint8_t* buffer, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WriteBytesAsync(*reinterpret_cast<hstring const*>(&absolutePath), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISetVersionDeferral> : produce_base<D, winrt::Windows::Storage::ISetVersionDeferral>
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
    struct produce<D, winrt::Windows::Storage::ISetVersionRequest> : produce_base<D, winrt::Windows::Storage::ISetVersionRequest>
    {
        int32_t __stdcall get_CurrentVersion(uint32_t* currentVersion) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *currentVersion = detach_from<uint32_t>(this->shim().CurrentVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredVersion(uint32_t* desiredVersion) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *desiredVersion = detach_from<uint32_t>(this->shim().DesiredVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Storage::SetVersionDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFile> : produce_base<D, winrt::Windows::Storage::IStorageFile>
    {
        int32_t __stdcall get_FileType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FileType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenAsync(int32_t accessMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<winrt::Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenTransactedWriteAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyOverloadDefaultNameAndOptions(void* destinationFolder, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CopyAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&destinationFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyOverloadDefaultOptions(void* destinationFolder, void* desiredNewName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CopyAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyOverload(void* destinationFolder, void* desiredNewName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CopyAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName), *reinterpret_cast<winrt::Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyAndReplaceAsync(void* fileToReplace, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CopyAndReplaceAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&fileToReplace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveOverloadDefaultNameAndOptions(void* destinationFolder, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MoveAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&destinationFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveOverloadDefaultOptions(void* destinationFolder, void* desiredNewName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MoveAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveOverload(void* destinationFolder, void* desiredNewName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MoveAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName), *reinterpret_cast<winrt::Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveAndReplaceAsync(void* fileToReplace, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().MoveAndReplaceAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&fileToReplace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFile2> : produce_base<D, winrt::Windows::Storage::IStorageFile2>
    {
        int32_t __stdcall OpenWithOptionsAsync(int32_t accessMode, uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<winrt::Windows::Storage::FileAccessMode const*>(&accessMode), *reinterpret_cast<winrt::Windows::Storage::StorageOpenOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenTransactedWriteWithOptionsAsync(uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync(*reinterpret_cast<winrt::Windows::Storage::StorageOpenOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFilePropertiesWithAvailability> : produce_base<D, winrt::Windows::Storage::IStorageFilePropertiesWithAvailability>
    {
        int32_t __stdcall get_IsAvailable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFileStatics> : produce_base<D, winrt::Windows::Storage::IStorageFileStatics>
    {
        int32_t __stdcall GetFileFromPathAsync(void* path, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().GetFileFromPathAsync(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFileFromApplicationUriAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().GetFileFromApplicationUriAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStreamedFileAsync(void* displayNameWithExtension, void* dataRequested, void* thumbnail, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateStreamedFileAsync(*reinterpret_cast<hstring const*>(&displayNameWithExtension), *reinterpret_cast<winrt::Windows::Storage::StreamedFileDataRequestedHandler const*>(&dataRequested), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReplaceWithStreamedFileAsync(void* fileToReplace, void* dataRequested, void* thumbnail, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().ReplaceWithStreamedFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&fileToReplace), *reinterpret_cast<winrt::Windows::Storage::StreamedFileDataRequestedHandler const*>(&dataRequested), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStreamedFileFromUriAsync(void* displayNameWithExtension, void* uri, void* thumbnail, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateStreamedFileFromUriAsync(*reinterpret_cast<hstring const*>(&displayNameWithExtension), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReplaceWithStreamedFileFromUriAsync(void* fileToReplace, void* uri, void* thumbnail, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().ReplaceWithStreamedFileFromUriAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&fileToReplace), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFileStatics2> : produce_base<D, winrt::Windows::Storage::IStorageFileStatics2>
    {
        int32_t __stdcall GetFileFromPathForUserAsync(void* user, void* path, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().GetFileFromPathForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFolder> : produce_base<D, winrt::Windows::Storage::IStorageFolder>
    {
        int32_t __stdcall CreateFileAsyncOverloadDefaultOptions(void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileAsync(void* desiredName, int32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::CreationCollisionOption const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderAsyncOverloadDefaultOptions(void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFolderAsync(void* desiredName, int32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::CreationCollisionOption const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFileAsync(void* name, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().GetFileAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFolderAsync(void* name, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemAsync(void* name, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>>(this->shim().GetItemAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFilesAsyncOverloadDefaultOptionsStartAndCount(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>>(this->shim().GetFilesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFoldersAsyncOverloadDefaultOptionsStartAndCount(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFolder>>>(this->shim().GetFoldersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemsAsyncOverloadDefaultStartAndCount(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>>(this->shim().GetItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFolder2> : produce_base<D, winrt::Windows::Storage::IStorageFolder2>
    {
        int32_t __stdcall TryGetItemAsync(void* name, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>>(this->shim().TryGetItemAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFolder3> : produce_base<D, winrt::Windows::Storage::IStorageFolder3>
    {
        int32_t __stdcall TryGetChangeTracker(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::StorageLibraryChangeTracker>(this->shim().TryGetChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFolderStatics> : produce_base<D, winrt::Windows::Storage::IStorageFolderStatics>
    {
        int32_t __stdcall GetFolderFromPathAsync(void* path, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetFolderFromPathAsync(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageFolderStatics2> : produce_base<D, winrt::Windows::Storage::IStorageFolderStatics2>
    {
        int32_t __stdcall GetFolderFromPathForUserAsync(void* user, void* path, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetFolderFromPathForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageItem> : produce_base<D, winrt::Windows::Storage::IStorageItem>
    {
        int32_t __stdcall RenameAsyncOverloadDefaultOptions(void* desiredName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenameAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RenameAsync(void* desiredName, int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenameAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<winrt::Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsyncOverloadDefaultOptions(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(int32_t option, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<winrt::Windows::Storage::StorageDeleteOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBasicPropertiesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::BasicProperties>>(this->shim().GetBasicPropertiesAsync());
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
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Attributes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::FileAttributes>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DateCreated(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().DateCreated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsOfType(uint32_t type, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOfType(*reinterpret_cast<winrt::Windows::Storage::StorageItemTypes const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageItem2> : produce_base<D, winrt::Windows::Storage::IStorageItem2>
    {
        int32_t __stdcall GetParentAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().GetParentAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEqual(void* item, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<winrt::Windows::Storage::IStorageItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageItemProperties> : produce_base<D, winrt::Windows::Storage::IStorageItemProperties>
    {
        int32_t __stdcall GetThumbnailAsyncOverloadDefaultSizeDefaultOptions(int32_t mode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetThumbnailAsyncOverloadDefaultOptions(int32_t mode, uint32_t requestedSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetThumbnailAsync(int32_t mode, uint32_t requestedSize, uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize, *reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailOptions const*>(&options)));
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
        int32_t __stdcall get_DisplayType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FolderRelativeId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FolderRelativeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::FileProperties::StorageItemContentProperties>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageItemProperties2> : produce_base<D, winrt::Windows::Storage::IStorageItemProperties2>
    {
        int32_t __stdcall GetScaledImageAsThumbnailAsyncOverloadDefaultSizeDefaultOptions(int32_t mode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetScaledImageAsThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScaledImageAsThumbnailAsyncOverloadDefaultOptions(int32_t mode, uint32_t requestedSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetScaledImageAsThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScaledImageAsThumbnailAsync(int32_t mode, uint32_t requestedSize, uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetScaledImageAsThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize, *reinterpret_cast<winrt::Windows::Storage::FileProperties::ThumbnailOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageItemPropertiesWithProvider> : produce_base<D, winrt::Windows::Storage::IStorageItemPropertiesWithProvider>
    {
        int32_t __stdcall get_Provider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageProvider>(this->shim().Provider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibrary> : produce_base<D, winrt::Windows::Storage::IStorageLibrary>
    {
        int32_t __stdcall RequestAddFolderAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().RequestAddFolderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestRemoveFolderAsync(void* folder, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestRemoveFolderAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Folders(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Storage::StorageFolder>>(this->shim().Folders());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SaveFolder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFolder>(this->shim().SaveFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DefinitionChanged(void* handler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().DefinitionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::StorageLibrary, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DefinitionChanged(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefinitionChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibrary2> : produce_base<D, winrt::Windows::Storage::IStorageLibrary2>
    {
        int32_t __stdcall get_ChangeTracker(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageLibraryChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibrary3> : produce_base<D, winrt::Windows::Storage::IStorageLibrary3>
    {
        int32_t __stdcall AreFolderSuggestionsAvailableAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().AreFolderSuggestionsAvailableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryChange> : produce_base<D, winrt::Windows::Storage::IStorageLibraryChange>
    {
        int32_t __stdcall get_ChangeType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageLibraryChangeType>(this->shim().ChangeType());
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
        int32_t __stdcall get_PreviousPath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PreviousPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsOfType(uint32_t type, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOfType(*reinterpret_cast<winrt::Windows::Storage::StorageItemTypes const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStorageItemAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>>(this->shim().GetStorageItemAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryChangeReader> : produce_base<D, winrt::Windows::Storage::IStorageLibraryChangeReader>
    {
        int32_t __stdcall ReadBatchAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageLibraryChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcceptChangesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AcceptChangesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryChangeReader2> : produce_base<D, winrt::Windows::Storage::IStorageLibraryChangeReader2>
    {
        int32_t __stdcall GetLastChangeId(uint64_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<uint64_t>(this->shim().GetLastChangeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryChangeTracker> : produce_base<D, winrt::Windows::Storage::IStorageLibraryChangeTracker>
    {
        int32_t __stdcall GetChangeReader(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageLibraryChangeReader>(this->shim().GetChangeReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Enable() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enable();
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
    struct produce<D, winrt::Windows::Storage::IStorageLibraryChangeTracker2> : produce_base<D, winrt::Windows::Storage::IStorageLibraryChangeTracker2>
    {
        int32_t __stdcall EnableWithOptions(void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enable(*reinterpret_cast<winrt::Windows::Storage::StorageLibraryChangeTrackerOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Disable() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions> : produce_base<D, winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions>
    {
        int32_t __stdcall get_TrackChangeDetails(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TrackChangeDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TrackChangeDetails(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TrackChangeDetails(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryLastChangeId> : produce_base<D, winrt::Windows::Storage::IStorageLibraryLastChangeId>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics> : produce_base<D, winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics>
    {
        int32_t __stdcall get_Unknown(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Unknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryStatics> : produce_base<D, winrt::Windows::Storage::IStorageLibraryStatics>
    {
        int32_t __stdcall GetLibraryAsync(int32_t libraryId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>>(this->shim().GetLibraryAsync(*reinterpret_cast<winrt::Windows::Storage::KnownLibraryId const*>(&libraryId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageLibraryStatics2> : produce_base<D, winrt::Windows::Storage::IStorageLibraryStatics2>
    {
        int32_t __stdcall GetLibraryForUserAsync(void* user, int32_t libraryId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>>(this->shim().GetLibraryForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Storage::KnownLibraryId const*>(&libraryId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageProvider> : produce_base<D, winrt::Windows::Storage::IStorageProvider>
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageProvider2> : produce_base<D, winrt::Windows::Storage::IStorageProvider2>
    {
        int32_t __stdcall IsPropertySupportedForPartialFileAsync(void* propertyCanonicalName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsPropertySupportedForPartialFileAsync(*reinterpret_cast<hstring const*>(&propertyCanonicalName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStorageStreamTransaction> : produce_base<D, winrt::Windows::Storage::IStorageStreamTransaction>
    {
        int32_t __stdcall get_Stream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStream>(this->shim().Stream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CommitAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CommitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IStreamedFileDataRequest> : produce_base<D, winrt::Windows::Storage::IStreamedFileDataRequest>
    {
        int32_t __stdcall FailAndClose(int32_t failureMode) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailAndClose(*reinterpret_cast<winrt::Windows::Storage::StreamedFileFailureMode const*>(&failureMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemAudioProperties> : produce_base<D, winrt::Windows::Storage::ISystemAudioProperties>
    {
        int32_t __stdcall get_EncodingBitrate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemDataPaths> : produce_base<D, winrt::Windows::Storage::ISystemDataPaths>
    {
        int32_t __stdcall get_Fonts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Fonts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProgramData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProgramData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Public(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Public());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicDesktop(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicDesktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicDocuments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicDocuments());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicDownloads(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicDownloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicMusic(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicMusic());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicPictures(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicVideos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PublicVideos());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_System(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().System());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemHost(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemHost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemX86(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemX86());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemX64(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemX64());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemArm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SystemArm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserProfiles(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Windows(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Windows());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemDataPathsStatics> : produce_base<D, winrt::Windows::Storage::ISystemDataPathsStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::SystemDataPaths>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemGPSProperties> : produce_base<D, winrt::Windows::Storage::ISystemGPSProperties>
    {
        int32_t __stdcall get_LatitudeDecimal(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LatitudeDecimal());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LongitudeDecimal(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LongitudeDecimal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemImageProperties> : produce_base<D, winrt::Windows::Storage::ISystemImageProperties>
    {
        int32_t __stdcall get_HorizontalSize(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HorizontalSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalSize(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VerticalSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemMediaProperties> : produce_base<D, winrt::Windows::Storage::ISystemMediaProperties>
    {
        int32_t __stdcall get_Duration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Producer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Producer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Publisher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Publisher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SubTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Writer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Writer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Year(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemMusicProperties> : produce_base<D, winrt::Windows::Storage::ISystemMusicProperties>
    {
        int32_t __stdcall get_AlbumArtist(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AlbumArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlbumTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AlbumTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Artist(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Artist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Composer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Composer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Conductor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Conductor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayArtist(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Genre(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Genre());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrackNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemPhotoProperties> : produce_base<D, winrt::Windows::Storage::ISystemPhotoProperties>
    {
        int32_t __stdcall get_CameraManufacturer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CameraManufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraModel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CameraModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DateTaken(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DateTaken());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PeopleNames(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PeopleNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemProperties> : produce_base<D, winrt::Windows::Storage::ISystemProperties>
    {
        int32_t __stdcall get_Author(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Comment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemNameDisplay(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ItemNameDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Keywords(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rating(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Rating());
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
        int32_t __stdcall get_Audio(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemAudioProperties>(this->shim().Audio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GPS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemGPSProperties>(this->shim().GPS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Media(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemMediaProperties>(this->shim().Media());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Music(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemMusicProperties>(this->shim().Music());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Photo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemPhotoProperties>(this->shim().Photo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Video(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemVideoProperties>(this->shim().Video());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Image(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::SystemImageProperties>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::ISystemVideoProperties> : produce_base<D, winrt::Windows::Storage::ISystemVideoProperties>
    {
        int32_t __stdcall get_Director(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Director());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameHeight(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FrameHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameWidth(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FrameWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TotalBitrate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TotalBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IUserDataPaths> : produce_base<D, winrt::Windows::Storage::IUserDataPaths>
    {
        int32_t __stdcall get_CameraRoll(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CameraRoll());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cookies(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Cookies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Desktop(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Desktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Documents(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Documents());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Downloads(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Downloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Favorites(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Favorites());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_History(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().History());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InternetCache(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().InternetCache());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalAppData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalAppDataLow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalAppDataLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Music(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Music());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pictures(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Pictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Profile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Profile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Recent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Recent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoamingAppData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RoamingAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SavedPictures(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SavedPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Screenshots(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Screenshots());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Templates(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Templates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Videos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Videos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::IUserDataPathsStatics> : produce_base<D, winrt::Windows::Storage::IUserDataPathsStatics>
    {
        int32_t __stdcall GetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::UserDataPaths>(this->shim().GetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::UserDataPaths>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    constexpr auto operator|(FileAttributes const left, FileAttributes const right) noexcept
    {
        return static_cast<FileAttributes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(FileAttributes& left, FileAttributes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(FileAttributes const left, FileAttributes const right) noexcept
    {
        return static_cast<FileAttributes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(FileAttributes& left, FileAttributes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(FileAttributes const value) noexcept
    {
        return static_cast<FileAttributes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(FileAttributes const left, FileAttributes const right) noexcept
    {
        return static_cast<FileAttributes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(FileAttributes& left, FileAttributes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(StorageItemTypes const left, StorageItemTypes const right) noexcept
    {
        return static_cast<StorageItemTypes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(StorageItemTypes& left, StorageItemTypes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(StorageItemTypes const left, StorageItemTypes const right) noexcept
    {
        return static_cast<StorageItemTypes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(StorageItemTypes& left, StorageItemTypes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(StorageItemTypes const value) noexcept
    {
        return static_cast<StorageItemTypes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(StorageItemTypes const left, StorageItemTypes const right) noexcept
    {
        return static_cast<StorageItemTypes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(StorageItemTypes& left, StorageItemTypes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(StorageOpenOptions const left, StorageOpenOptions const right) noexcept
    {
        return static_cast<StorageOpenOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(StorageOpenOptions& left, StorageOpenOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(StorageOpenOptions const left, StorageOpenOptions const right) noexcept
    {
        return static_cast<StorageOpenOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(StorageOpenOptions& left, StorageOpenOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(StorageOpenOptions const value) noexcept
    {
        return static_cast<StorageOpenOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(StorageOpenOptions const left, StorageOpenOptions const right) noexcept
    {
        return static_cast<StorageOpenOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(StorageOpenOptions& left, StorageOpenOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto AppDataPaths::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<AppDataPaths, IAppDataPathsStatics>([&](IAppDataPathsStatics const& f) { return f.GetForUser(user); });
    }
    inline auto AppDataPaths::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::AppDataPaths(*)(IAppDataPathsStatics const&), AppDataPaths, IAppDataPathsStatics>([](IAppDataPathsStatics const& f) { return f.GetDefault(); });
    }
    inline auto ApplicationData::Current()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::ApplicationData(*)(IApplicationDataStatics const&), ApplicationData, IApplicationDataStatics>([](IApplicationDataStatics const& f) { return f.Current(); });
    }
    inline auto ApplicationData::GetForUserAsync(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<ApplicationData, IApplicationDataStatics2>([&](IApplicationDataStatics2 const& f) { return f.GetForUserAsync(user); });
    }
    inline ApplicationDataCompositeValue::ApplicationDataCompositeValue() :
        ApplicationDataCompositeValue(impl::call_factory_cast<ApplicationDataCompositeValue(*)(winrt::Windows::Foundation::IActivationFactory const&), ApplicationDataCompositeValue>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ApplicationDataCompositeValue>(); }))
    {
    }
    inline auto CachedFileManager::DeferUpdates(winrt::Windows::Storage::IStorageFile const& file)
    {
        impl::call_factory<CachedFileManager, ICachedFileManagerStatics>([&](ICachedFileManagerStatics const& f) { return f.DeferUpdates(file); });
    }
    inline auto CachedFileManager::CompleteUpdatesAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<CachedFileManager, ICachedFileManagerStatics>([&](ICachedFileManagerStatics const& f) { return f.CompleteUpdatesAsync(file); });
    }
    inline auto DownloadsFolder::CreateFileAsync(param::hstring const& desiredName)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics>([&](IDownloadsFolderStatics const& f) { return f.CreateFileAsync(desiredName); });
    }
    inline auto DownloadsFolder::CreateFolderAsync(param::hstring const& desiredName)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics>([&](IDownloadsFolderStatics const& f) { return f.CreateFolderAsync(desiredName); });
    }
    inline auto DownloadsFolder::CreateFileAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics>([&](IDownloadsFolderStatics const& f) { return f.CreateFileAsync(desiredName, option); });
    }
    inline auto DownloadsFolder::CreateFolderAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics>([&](IDownloadsFolderStatics const& f) { return f.CreateFolderAsync(desiredName, option); });
    }
    inline auto DownloadsFolder::CreateFileForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics2>([&](IDownloadsFolderStatics2 const& f) { return f.CreateFileForUserAsync(user, desiredName); });
    }
    inline auto DownloadsFolder::CreateFolderForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics2>([&](IDownloadsFolderStatics2 const& f) { return f.CreateFolderForUserAsync(user, desiredName); });
    }
    inline auto DownloadsFolder::CreateFileForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics2>([&](IDownloadsFolderStatics2 const& f) { return f.CreateFileForUserAsync(user, desiredName, option); });
    }
    inline auto DownloadsFolder::CreateFolderForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option)
    {
        return impl::call_factory<DownloadsFolder, IDownloadsFolderStatics2>([&](IDownloadsFolderStatics2 const& f) { return f.CreateFolderForUserAsync(user, desiredName, option); });
    }
    inline auto FileIO::ReadTextAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.ReadTextAsync(file); });
    }
    inline auto FileIO::ReadTextAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.ReadTextAsync(file, encoding); });
    }
    inline auto FileIO::WriteTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.WriteTextAsync(file, contents); });
    }
    inline auto FileIO::WriteTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.WriteTextAsync(file, contents, encoding); });
    }
    inline auto FileIO::AppendTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.AppendTextAsync(file, contents); });
    }
    inline auto FileIO::AppendTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.AppendTextAsync(file, contents, encoding); });
    }
    inline auto FileIO::ReadLinesAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.ReadLinesAsync(file); });
    }
    inline auto FileIO::ReadLinesAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.ReadLinesAsync(file, encoding); });
    }
    inline auto FileIO::WriteLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.WriteLinesAsync(file, lines); });
    }
    inline auto FileIO::WriteLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.WriteLinesAsync(file, lines, encoding); });
    }
    inline auto FileIO::AppendLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.AppendLinesAsync(file, lines); });
    }
    inline auto FileIO::AppendLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.AppendLinesAsync(file, lines, encoding); });
    }
    inline auto FileIO::ReadBufferAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.ReadBufferAsync(file); });
    }
    inline auto FileIO::WriteBufferAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::IBuffer const& buffer)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.WriteBufferAsync(file, buffer); });
    }
    inline auto FileIO::WriteBytesAsync(winrt::Windows::Storage::IStorageFile const& file, array_view<uint8_t const> buffer)
    {
        return impl::call_factory<FileIO, IFileIOStatics>([&](IFileIOStatics const& f) { return f.WriteBytesAsync(file, buffer); });
    }
    inline auto KnownFolders::CameraRoll()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersCameraRollStatics const&), KnownFolders, IKnownFoldersCameraRollStatics>([](IKnownFoldersCameraRollStatics const& f) { return f.CameraRoll(); });
    }
    inline auto KnownFolders::Playlists()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersPlaylistsStatics const&), KnownFolders, IKnownFoldersPlaylistsStatics>([](IKnownFoldersPlaylistsStatics const& f) { return f.Playlists(); });
    }
    inline auto KnownFolders::SavedPictures()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersSavedPicturesStatics const&), KnownFolders, IKnownFoldersSavedPicturesStatics>([](IKnownFoldersSavedPicturesStatics const& f) { return f.SavedPictures(); });
    }
    inline auto KnownFolders::MusicLibrary()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.MusicLibrary(); });
    }
    inline auto KnownFolders::PicturesLibrary()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.PicturesLibrary(); });
    }
    inline auto KnownFolders::VideosLibrary()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.VideosLibrary(); });
    }
    inline auto KnownFolders::DocumentsLibrary()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.DocumentsLibrary(); });
    }
    inline auto KnownFolders::HomeGroup()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.HomeGroup(); });
    }
    inline auto KnownFolders::RemovableDevices()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.RemovableDevices(); });
    }
    inline auto KnownFolders::MediaServerDevices()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics const&), KnownFolders, IKnownFoldersStatics>([](IKnownFoldersStatics const& f) { return f.MediaServerDevices(); });
    }
    inline auto KnownFolders::Objects3D()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics2 const&), KnownFolders, IKnownFoldersStatics2>([](IKnownFoldersStatics2 const& f) { return f.Objects3D(); });
    }
    inline auto KnownFolders::AppCaptures()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics2 const&), KnownFolders, IKnownFoldersStatics2>([](IKnownFoldersStatics2 const& f) { return f.AppCaptures(); });
    }
    inline auto KnownFolders::RecordedCalls()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::StorageFolder(*)(IKnownFoldersStatics2 const&), KnownFolders, IKnownFoldersStatics2>([](IKnownFoldersStatics2 const& f) { return f.RecordedCalls(); });
    }
    inline auto KnownFolders::GetFolderForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownFolderId const& folderId)
    {
        return impl::call_factory<KnownFolders, IKnownFoldersStatics3>([&](IKnownFoldersStatics3 const& f) { return f.GetFolderForUserAsync(user, folderId); });
    }
    inline auto KnownFolders::RequestAccessAsync(winrt::Windows::Storage::KnownFolderId const& folderId)
    {
        return impl::call_factory<KnownFolders, IKnownFoldersStatics4>([&](IKnownFoldersStatics4 const& f) { return f.RequestAccessAsync(folderId); });
    }
    inline auto KnownFolders::RequestAccessForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownFolderId const& folderId)
    {
        return impl::call_factory<KnownFolders, IKnownFoldersStatics4>([&](IKnownFoldersStatics4 const& f) { return f.RequestAccessForUserAsync(user, folderId); });
    }
    inline auto KnownFolders::GetFolderAsync(winrt::Windows::Storage::KnownFolderId const& folderId)
    {
        return impl::call_factory<KnownFolders, IKnownFoldersStatics4>([&](IKnownFoldersStatics4 const& f) { return f.GetFolderAsync(folderId); });
    }
    inline auto PathIO::ReadTextAsync(param::hstring const& absolutePath)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.ReadTextAsync(absolutePath); });
    }
    inline auto PathIO::ReadTextAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.ReadTextAsync(absolutePath, encoding); });
    }
    inline auto PathIO::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.WriteTextAsync(absolutePath, contents); });
    }
    inline auto PathIO::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.WriteTextAsync(absolutePath, contents, encoding); });
    }
    inline auto PathIO::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.AppendTextAsync(absolutePath, contents); });
    }
    inline auto PathIO::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.AppendTextAsync(absolutePath, contents, encoding); });
    }
    inline auto PathIO::ReadLinesAsync(param::hstring const& absolutePath)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.ReadLinesAsync(absolutePath); });
    }
    inline auto PathIO::ReadLinesAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.ReadLinesAsync(absolutePath, encoding); });
    }
    inline auto PathIO::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.WriteLinesAsync(absolutePath, lines); });
    }
    inline auto PathIO::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.WriteLinesAsync(absolutePath, lines, encoding); });
    }
    inline auto PathIO::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.AppendLinesAsync(absolutePath, lines); });
    }
    inline auto PathIO::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.AppendLinesAsync(absolutePath, lines, encoding); });
    }
    inline auto PathIO::ReadBufferAsync(param::hstring const& absolutePath)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.ReadBufferAsync(absolutePath); });
    }
    inline auto PathIO::WriteBufferAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::IBuffer const& buffer)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.WriteBufferAsync(absolutePath, buffer); });
    }
    inline auto PathIO::WriteBytesAsync(param::hstring const& absolutePath, array_view<uint8_t const> buffer)
    {
        return impl::call_factory<PathIO, IPathIOStatics>([&](IPathIOStatics const& f) { return f.WriteBytesAsync(absolutePath, buffer); });
    }
    inline auto StorageFile::GetFileFromPathAsync(param::hstring const& path)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics>([&](IStorageFileStatics const& f) { return f.GetFileFromPathAsync(path); });
    }
    inline auto StorageFile::GetFileFromApplicationUriAsync(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics>([&](IStorageFileStatics const& f) { return f.GetFileFromApplicationUriAsync(uri); });
    }
    inline auto StorageFile::CreateStreamedFileAsync(param::hstring const& displayNameWithExtension, winrt::Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics>([&](IStorageFileStatics const& f) { return f.CreateStreamedFileAsync(displayNameWithExtension, dataRequested, thumbnail); });
    }
    inline auto StorageFile::ReplaceWithStreamedFileAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace, winrt::Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics>([&](IStorageFileStatics const& f) { return f.ReplaceWithStreamedFileAsync(fileToReplace, dataRequested, thumbnail); });
    }
    inline auto StorageFile::CreateStreamedFileFromUriAsync(param::hstring const& displayNameWithExtension, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics>([&](IStorageFileStatics const& f) { return f.CreateStreamedFileFromUriAsync(displayNameWithExtension, uri, thumbnail); });
    }
    inline auto StorageFile::ReplaceWithStreamedFileFromUriAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics>([&](IStorageFileStatics const& f) { return f.ReplaceWithStreamedFileFromUriAsync(fileToReplace, uri, thumbnail); });
    }
    inline auto StorageFile::GetFileFromPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path)
    {
        return impl::call_factory<StorageFile, IStorageFileStatics2>([&](IStorageFileStatics2 const& f) { return f.GetFileFromPathForUserAsync(user, path); });
    }
    inline auto StorageFolder::GetFolderFromPathAsync(param::hstring const& path)
    {
        return impl::call_factory<StorageFolder, IStorageFolderStatics>([&](IStorageFolderStatics const& f) { return f.GetFolderFromPathAsync(path); });
    }
    inline auto StorageFolder::GetFolderFromPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path)
    {
        return impl::call_factory<StorageFolder, IStorageFolderStatics2>([&](IStorageFolderStatics2 const& f) { return f.GetFolderFromPathForUserAsync(user, path); });
    }
    inline auto StorageLibrary::GetLibraryAsync(winrt::Windows::Storage::KnownLibraryId const& libraryId)
    {
        return impl::call_factory<StorageLibrary, IStorageLibraryStatics>([&](IStorageLibraryStatics const& f) { return f.GetLibraryAsync(libraryId); });
    }
    inline auto StorageLibrary::GetLibraryForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownLibraryId const& libraryId)
    {
        return impl::call_factory<StorageLibrary, IStorageLibraryStatics2>([&](IStorageLibraryStatics2 const& f) { return f.GetLibraryForUserAsync(user, libraryId); });
    }
    inline StorageLibraryChangeTrackerOptions::StorageLibraryChangeTrackerOptions() :
        StorageLibraryChangeTrackerOptions(impl::call_factory_cast<StorageLibraryChangeTrackerOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), StorageLibraryChangeTrackerOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<StorageLibraryChangeTrackerOptions>(); }))
    {
    }
    inline auto StorageLibraryLastChangeId::Unknown()
    {
        return impl::call_factory_cast<uint64_t(*)(IStorageLibraryLastChangeIdStatics const&), StorageLibraryLastChangeId, IStorageLibraryLastChangeIdStatics>([](IStorageLibraryLastChangeIdStatics const& f) { return f.Unknown(); });
    }
    inline auto SystemDataPaths::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemDataPaths(*)(ISystemDataPathsStatics const&), SystemDataPaths, ISystemDataPathsStatics>([](ISystemDataPathsStatics const& f) { return f.GetDefault(); });
    }
    inline auto SystemProperties::Author()
    {
        return impl::call_factory_cast<hstring(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Author(); });
    }
    inline auto SystemProperties::Comment()
    {
        return impl::call_factory_cast<hstring(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Comment(); });
    }
    inline auto SystemProperties::ItemNameDisplay()
    {
        return impl::call_factory_cast<hstring(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.ItemNameDisplay(); });
    }
    inline auto SystemProperties::Keywords()
    {
        return impl::call_factory_cast<hstring(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Keywords(); });
    }
    inline auto SystemProperties::Rating()
    {
        return impl::call_factory_cast<hstring(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Rating(); });
    }
    inline auto SystemProperties::Title()
    {
        return impl::call_factory_cast<hstring(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Title(); });
    }
    inline auto SystemProperties::Audio()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemAudioProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Audio(); });
    }
    inline auto SystemProperties::GPS()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemGPSProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.GPS(); });
    }
    inline auto SystemProperties::Media()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemMediaProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Media(); });
    }
    inline auto SystemProperties::Music()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemMusicProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Music(); });
    }
    inline auto SystemProperties::Photo()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemPhotoProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Photo(); });
    }
    inline auto SystemProperties::Video()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemVideoProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Video(); });
    }
    inline auto SystemProperties::Image()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::SystemImageProperties(*)(ISystemProperties const&), SystemProperties, ISystemProperties>([](ISystemProperties const& f) { return f.Image(); });
    }
    inline auto UserDataPaths::GetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<UserDataPaths, IUserDataPathsStatics>([&](IUserDataPathsStatics const& f) { return f.GetForUser(user); });
    }
    inline auto UserDataPaths::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Storage::UserDataPaths(*)(IUserDataPathsStatics const&), UserDataPaths, IUserDataPathsStatics>([](IUserDataPathsStatics const& f) { return f.GetDefault(); });
    }
    template <typename L> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(L handler) :
        ApplicationDataSetVersionHandler(impl::make_delegate<ApplicationDataSetVersionHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(F* handler) :
        ApplicationDataSetVersionHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(O* object, M method) :
        ApplicationDataSetVersionHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(com_ptr<O>&& object, M method) :
        ApplicationDataSetVersionHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(weak_ref<O>&& object, M method) :
        ApplicationDataSetVersionHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ApplicationDataSetVersionHandler::operator()(winrt::Windows::Storage::SetVersionRequest const& setVersionRequest) const
    {
        check_hresult((*(impl::abi_t<ApplicationDataSetVersionHandler>**)this)->Invoke(*(void**)(&setVersionRequest)));
    }
    template <typename L> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(L handler) :
        StreamedFileDataRequestedHandler(impl::make_delegate<StreamedFileDataRequestedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(F* handler) :
        StreamedFileDataRequestedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(O* object, M method) :
        StreamedFileDataRequestedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(com_ptr<O>&& object, M method) :
        StreamedFileDataRequestedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(weak_ref<O>&& object, M method) :
        StreamedFileDataRequestedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto StreamedFileDataRequestedHandler::operator()(winrt::Windows::Storage::StreamedFileDataRequest const& stream) const
    {
        check_hresult((*(impl::abi_t<StreamedFileDataRequestedHandler>**)this)->Invoke(*(void**)(&stream)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Storage::IAppDataPaths> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IAppDataPathsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IApplicationData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IApplicationData2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IApplicationData3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IApplicationDataContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IApplicationDataStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IApplicationDataStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ICachedFileManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IDownloadsFolderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IDownloadsFolderStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IFileIOStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersCameraRollStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IPathIOStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISetVersionDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISetVersionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFile2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFileStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFileStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFolder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFolder2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFolder3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFolderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageFolderStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageItem2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageItemProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageItemProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageItemPropertiesWithProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibrary> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibrary2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibrary3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeReader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeTracker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryLastChangeId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageLibraryStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageProvider2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStorageStreamTransaction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IStreamedFileDataRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemAudioProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemDataPaths> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemDataPathsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemGPSProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemImageProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemMediaProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemMusicProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemPhotoProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ISystemVideoProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IUserDataPaths> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::IUserDataPathsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::AppDataPaths> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ApplicationData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ApplicationDataCompositeValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ApplicationDataContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::ApplicationDataContainerSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::CachedFileManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::DownloadsFolder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::FileIO> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::KnownFolders> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::PathIO> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SetVersionDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SetVersionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageFile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageFolder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageLibrary> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageLibraryChange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageLibraryChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageLibraryChangeTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageLibraryChangeTrackerOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageLibraryLastChangeId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StorageStreamTransaction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::StreamedFileDataRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemAudioProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemDataPaths> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemGPSProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemImageProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemMediaProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemMusicProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemPhotoProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::SystemVideoProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::UserDataPaths> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
