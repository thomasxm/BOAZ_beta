// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_BackgroundTransfer_H
#define WINRT_Windows_Networking_BackgroundTransfer_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Networking.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Networking.BackgroundTransfer.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::DownloadOperation) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader<D>::CreateDownload(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::IStorageFile const& resultFile) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader)->CreateDownload(*(void**)(&uri), *(void**)(&resultFile), &operation));
        return winrt::Windows::Networking::BackgroundTransfer::DownloadOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::DownloadOperation) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader<D>::CreateDownload(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::IStorageFile const& resultFile, winrt::Windows::Storage::IStorageFile const& requestBodyFile) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader)->CreateDownloadFromFile(*(void**)(&uri), *(void**)(&resultFile), *(void**)(&requestBodyFile), &operation));
        return winrt::Windows::Networking::BackgroundTransfer::DownloadOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader<D>::CreateDownloadAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::IStorageFile const& resultFile, winrt::Windows::Storage::Streams::IInputStream const& requestBodyStream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader)->CreateDownloadAsync(*(void**)(&uri), *(void**)(&resultFile), *(void**)(&requestBodyStream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::TransferGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_TransferGroup(&value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::TransferGroup(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_TransferGroup(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessToastNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_SuccessToastNotification(&value));
        return winrt::Windows::UI::Notifications::ToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessToastNotification(winrt::Windows::UI::Notifications::ToastNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_SuccessToastNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureToastNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_FailureToastNotification(&value));
        return winrt::Windows::UI::Notifications::ToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureToastNotification(winrt::Windows::UI::Notifications::ToastNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_FailureToastNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessTileNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_SuccessTileNotification(&value));
        return winrt::Windows::UI::Notifications::TileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::SuccessTileNotification(winrt::Windows::UI::Notifications::TileNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_SuccessTileNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureTileNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->get_FailureTileNotification(&value));
        return winrt::Windows::UI::Notifications::TileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader2<D>::FailureTileNotification(winrt::Windows::UI::Notifications::TileNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2)->put_FailureTileNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloader3<D>::CompletionGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader3)->get_CompletionGroup(&value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloader) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderFactory<D>::CreateWithCompletionGroup(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) const
    {
        void* backgroundDownloader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory)->CreateWithCompletionGroup(*(void**)(&completionGroup), &backgroundDownloader));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloader{ backgroundDownloader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderStaticMethods<D>::GetCurrentDownloadsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods)->GetCurrentDownloadsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderStaticMethods<D>::GetCurrentDownloadsAsync(param::hstring const& group) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods)->GetCurrentDownloadsForGroupAsync(*(void**)(&group), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderStaticMethods2<D>::GetCurrentDownloadsForTransferGroupAsync(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2)->GetCurrentDownloadsForTransferGroupAsync(*(void**)(&group), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>) consume_Windows_Networking_BackgroundTransfer_IBackgroundDownloaderUserConsent<D>::RequestUnconstrainedDownloadsAsync(param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation> const& operations) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent)->RequestUnconstrainedDownloadsAsync(*(void**)(&operations), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::SetRequestHeader(param::hstring const& headerName, param::hstring const& headerValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->SetRequestHeader(*(void**)(&headerName), *(void**)(&headerValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ServerCredential() const
    {
        void* credential{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_ServerCredential(&credential));
        return winrt::Windows::Security::Credentials::PasswordCredential{ credential, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& credential) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_ServerCredential(*(void**)(&credential)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ProxyCredential() const
    {
        void* credential{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_ProxyCredential(&credential));
        return winrt::Windows::Security::Credentials::PasswordCredential{ credential, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::ProxyCredential(winrt::Windows::Security::Credentials::PasswordCredential const& credential) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_ProxyCredential(*(void**)(&credential)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Method() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_Method(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Method(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_Method(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Group() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_Group(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::Group(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_Group(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::CostPolicy() const
    {
        winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->get_CostPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferBase<D>::CostPolicy(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase)->put_CostPolicy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Background::IBackgroundTrigger) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroup<D>::Trigger() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup)->get_Trigger(&value));
        return winrt::Windows::ApplicationModel::Background::IBackgroundTrigger{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroup<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroup<D>::Enable() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup)->Enable());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroupTriggerDetails<D>::Downloads() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails)->get_Downloads(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferCompletionGroupTriggerDetails<D>::Uploads() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails)->get_Uploads(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPart<D>::SetHeader(param::hstring const& headerName, param::hstring const& headerValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart)->SetHeader(*(void**)(&headerName), *(void**)(&headerValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPart<D>::SetText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart)->SetText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPart<D>::SetFile(winrt::Windows::Storage::IStorageFile const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart)->SetFile(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPartFactory<D>::CreateWithName(param::hstring const& name) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory)->CreateWithName(*(void**)(&name), &value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferContentPartFactory<D>::CreateWithNameAndFileName(param::hstring const& name, param::hstring const& fileName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory)->CreateWithNameAndFileName(*(void**)(&name), *(void**)(&fileName), &value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::WebErrorStatus) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferErrorStaticMethods<D>::GetStatus(int32_t hresult) const
    {
        winrt::Windows::Web::WebErrorStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods)->GetStatus(hresult, reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroup<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroup<D>::TransferBehavior() const
    {
        winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup)->get_TransferBehavior(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroup<D>::TransferBehavior(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup)->put_TransferBehavior(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferGroupStatics<D>::CreateGroup(param::hstring const& name) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics)->CreateGroup(*(void**)(&name), &value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::Guid() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_Guid(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::RequestedUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_RequestedUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::Method() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_Method(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::Group() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_Group(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::CostPolicy() const
    {
        winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->get_CostPolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::CostPolicy(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->put_CostPolicy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::GetResultStreamAt(uint64_t position) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->GetResultStreamAt(position, &value));
        return winrt::Windows::Storage::Streams::IInputStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::ResponseInformation) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperation<D>::GetResponseInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation)->GetResponseInformation(&value));
        return winrt::Windows::Networking::BackgroundTransfer::ResponseInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferPriority) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperationPriority<D>::Priority() const
    {
        winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferPriority value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority)->get_Priority(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferOperationPriority<D>::Priority(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferPriority const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority)->put_Priority(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferRangesDownloadedEventArgs<D>::WasDownloadRestarted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs)->get_WasDownloadRestarted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferRangesDownloadedEventArgs<D>::AddedRanges() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs)->get_AddedRanges(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Networking_BackgroundTransfer_IBackgroundTransferRangesDownloadedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::UploadOperation) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUpload(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::IStorageFile const& sourceFile) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUpload(*(void**)(&uri), *(void**)(&sourceFile), &operation));
        return winrt::Windows::Networking::BackgroundTransfer::UploadOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadFromStreamAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IInputStream const& sourceStream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadFromStreamAsync(*(void**)(&uri), *(void**)(&sourceStream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadAsync(winrt::Windows::Foundation::Uri const& uri, param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const& parts) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadWithFormDataAndAutoBoundaryAsync(*(void**)(&uri), *(void**)(&parts), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadAsync(winrt::Windows::Foundation::Uri const& uri, param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const& parts, param::hstring const& subType) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadWithSubTypeAsync(*(void**)(&uri), *(void**)(&parts), *(void**)(&subType), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader<D>::CreateUploadAsync(winrt::Windows::Foundation::Uri const& uri, param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const& parts, param::hstring const& subType, param::hstring const& boundary) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader)->CreateUploadWithSubTypeAndBoundaryAsync(*(void**)(&uri), *(void**)(&parts), *(void**)(&subType), *(void**)(&boundary), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::TransferGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_TransferGroup(&value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::TransferGroup(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_TransferGroup(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessToastNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_SuccessToastNotification(&value));
        return winrt::Windows::UI::Notifications::ToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessToastNotification(winrt::Windows::UI::Notifications::ToastNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_SuccessToastNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::ToastNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureToastNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_FailureToastNotification(&value));
        return winrt::Windows::UI::Notifications::ToastNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureToastNotification(winrt::Windows::UI::Notifications::ToastNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_FailureToastNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessTileNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_SuccessTileNotification(&value));
        return winrt::Windows::UI::Notifications::TileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::SuccessTileNotification(winrt::Windows::UI::Notifications::TileNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_SuccessTileNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Notifications::TileNotification) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureTileNotification() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->get_FailureTileNotification(&value));
        return winrt::Windows::UI::Notifications::TileNotification{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader2<D>::FailureTileNotification(winrt::Windows::UI::Notifications::TileNotification const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2)->put_FailureTileNotification(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploader3<D>::CompletionGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader3)->get_CompletionGroup(&value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundUploader) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderFactory<D>::CreateWithCompletionGroup(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) const
    {
        void* backgroundUploader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory)->CreateWithCompletionGroup(*(void**)(&completionGroup), &backgroundUploader));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundUploader{ backgroundUploader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderStaticMethods<D>::GetCurrentUploadsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods)->GetCurrentUploadsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderStaticMethods<D>::GetCurrentUploadsAsync(param::hstring const& group) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods)->GetCurrentUploadsForGroupAsync(*(void**)(&group), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderStaticMethods2<D>::GetCurrentUploadsForTransferGroupAsync(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2)->GetCurrentUploadsForTransferGroupAsync(*(void**)(&group), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>) consume_Windows_Networking_BackgroundTransfer_IBackgroundUploaderUserConsent<D>::RequestUnconstrainedUploadsAsync(param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::UploadOperation> const& operations) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent)->RequestUnconstrainedUploadsAsync(*(void**)(&operations), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) consume_Windows_Networking_BackgroundTransfer_IContentPrefetcher<D>::ContentUris() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher)->get_ContentUris(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IContentPrefetcher<D>::IndirectContentUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher)->put_IndirectContentUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Networking_BackgroundTransfer_IContentPrefetcher<D>::IndirectContentUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher)->get_IndirectContentUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Networking_BackgroundTransfer_IContentPrefetcherTime<D>::LastSuccessfulPrefetchTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcherTime)->get_LastSuccessfulPrefetchTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::ResultFile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation)->get_ResultFile(&value));
        return winrt::Windows::Storage::IStorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::Progress() const
    {
        winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation)->get_Progress(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::AttachAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation)->AttachAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation2<D>::TransferGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation2)->get_TransferGroup(&value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::IsRandomAccessRequired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->get_IsRandomAccessRequired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::IsRandomAccessRequired(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->put_IsRandomAccessRequired(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::GetResultRandomAccessStreamReference() const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->GetResultRandomAccessStreamReference(&stream));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::GetDownloadedRanges() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->GetDownloadedRanges(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->add_RangesDownloaded(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded_revoker consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, RangesDownloaded_revoker>(this, RangesDownloaded(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RangesDownloaded(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->remove_RangesDownloaded(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RequestedUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->put_RequestedUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::WebErrorStatus>) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::RecoverableWebErrorStatuses() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->get_RecoverableWebErrorStatuses(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::WebErrorStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Web::WebErrorStatus>) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation3<D>::CurrentWebErrorStatus() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3)->get_CurrentWebErrorStatus(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Web::WebErrorStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation4<D>::MakeCurrentInTransferGroup() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation4)->MakeCurrentInTransferGroup());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation5<D>::SetRequestHeader(param::hstring const& headerName, param::hstring const& headerValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation5)->SetRequestHeader(*(void**)(&headerName), *(void**)(&headerValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IDownloadOperation5<D>::RemoveRequestHeader(param::hstring const& headerName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation5)->RemoveRequestHeader(*(void**)(&headerName)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::IsResumable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IResponseInformation)->get_IsResumable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::ActualUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IResponseInformation)->get_ActualUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::StatusCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IResponseInformation)->get_StatusCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) consume_Windows_Networking_BackgroundTransfer_IResponseInformation<D>::Headers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IResponseInformation)->get_Headers(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_BackgroundTransfer_IUnconstrainedTransferRequestResult<D>::IsUnconstrained() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult)->get_IsUnconstrained(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::SourceFile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation)->get_SourceFile(&value));
        return winrt::Windows::Storage::IStorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundUploadProgress) consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::Progress() const
    {
        winrt::Windows::Networking::BackgroundTransfer::BackgroundUploadProgress value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation)->get_Progress(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::UploadOperation, winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::UploadOperation, winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::UploadOperation, winrt::Windows::Networking::BackgroundTransfer::UploadOperation>) consume_Windows_Networking_BackgroundTransfer_IUploadOperation<D>::AttachAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation)->AttachAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::UploadOperation, winrt::Windows::Networking::BackgroundTransfer::UploadOperation>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup) consume_Windows_Networking_BackgroundTransfer_IUploadOperation2<D>::TransferGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation2)->get_TransferGroup(&value));
        return winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IUploadOperation3<D>::MakeCurrentInTransferGroup() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation3)->MakeCurrentInTransferGroup());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IUploadOperation4<D>::SetRequestHeader(param::hstring const& headerName, param::hstring const& headerValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation4)->SetRequestHeader(*(void**)(&headerName), *(void**)(&headerValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_BackgroundTransfer_IUploadOperation4<D>::RemoveRequestHeader(param::hstring const& headerName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::BackgroundTransfer::IUploadOperation4)->RemoveRequestHeader(*(void**)(&headerName)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader>
    {
        int32_t __stdcall CreateDownload(void* uri, void* resultFile, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>(this->shim().CreateDownload(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&resultFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDownloadFromFile(void* uri, void* resultFile, void* requestBodyFile, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>(this->shim().CreateDownload(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&resultFile), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&requestBodyFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDownloadAsync(void* uri, void* resultFile, void* requestBodyStream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().CreateDownloadAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&resultFile), *reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&requestBodyStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2>
    {
        int32_t __stdcall get_TransferGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransferGroup(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferGroup(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuccessToastNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotification>(this->shim().SuccessToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuccessToastNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuccessToastNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FailureToastNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotification>(this->shim().FailureToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FailureToastNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailureToastNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuccessTileNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileNotification>(this->shim().SuccessTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuccessTileNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuccessTileNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FailureTileNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileNotification>(this->shim().FailureTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FailureTileNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailureTileNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader3> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader3>
    {
        int32_t __stdcall get_CompletionGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup>(this->shim().CompletionGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory>
    {
        int32_t __stdcall CreateWithCompletionGroup(void* completionGroup, void** backgroundDownloader) noexcept final try
        {
            clear_abi(backgroundDownloader);
            typename D::abi_guard guard(this->shim());
            *backgroundDownloader = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloader>(this->shim().CreateWithCompletionGroup(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const*>(&completionGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods>
    {
        int32_t __stdcall GetCurrentDownloadsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>>(this->shim().GetCurrentDownloadsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentDownloadsForGroupAsync(void* group, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>>(this->shim().GetCurrentDownloadsAsync(*reinterpret_cast<hstring const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2>
    {
        int32_t __stdcall GetCurrentDownloadsForTransferGroupAsync(void* group, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>>(this->shim().GetCurrentDownloadsForTransferGroupAsync(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent>
    {
        int32_t __stdcall RequestUnconstrainedDownloadsAsync(void* operations, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>>(this->shim().RequestUnconstrainedDownloadsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation> const*>(&operations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase>
    {
        int32_t __stdcall SetRequestHeader(void* headerName, void* headerValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServerCredential(void** credential) noexcept final try
        {
            clear_abi(credential);
            typename D::abi_guard guard(this->shim());
            *credential = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().ServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServerCredential(void* credential) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProxyCredential(void** credential) noexcept final try
        {
            clear_abi(credential);
            typename D::abi_guard guard(this->shim());
            *credential = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().ProxyCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProxyCredential(void* credential) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProxyCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Method(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Method());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Method(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Method(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Group(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Group(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Group(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CostPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy>(this->shim().CostPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CostPolicy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CostPolicy(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup>
    {
        int32_t __stdcall get_Trigger(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Background::IBackgroundTrigger>(this->shim().Trigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails>
    {
        int32_t __stdcall get_Downloads(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().Downloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uploads(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().Uploads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart>
    {
        int32_t __stdcall SetHeader(void* headerName, void* headerValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFile(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory>
    {
        int32_t __stdcall CreateWithName(void* name, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart>(this->shim().CreateWithName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithNameAndFileName(void* name, void* fileName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart>(this->shim().CreateWithNameAndFileName(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&fileName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods>
    {
        int32_t __stdcall GetStatus(int32_t hresult, int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Web::WebErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransferBehavior(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior>(this->shim().TransferBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransferBehavior(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferBehavior(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics>
    {
        int32_t __stdcall CreateGroup(void* name, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().CreateGroup(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation>
    {
        int32_t __stdcall get_Guid(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Guid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().RequestedUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Method(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Method());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Group(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CostPolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy>(this->shim().CostPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CostPolicy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CostPolicy(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCostPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetResultStreamAt(uint64_t position, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().GetResultStreamAt(position));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetResponseInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::ResponseInformation>(this->shim().GetResponseInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority>
    {
        int32_t __stdcall get_Priority(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferPriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Priority(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Priority(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs>
    {
        int32_t __stdcall get_WasDownloadRestarted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasDownloadRestarted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AddedRanges(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>>(this->shim().AddedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader>
    {
        int32_t __stdcall CreateUpload(void* uri, void* sourceFile, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>(this->shim().CreateUpload(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&sourceFile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUploadFromStreamAsync(void* uri, void* sourceStream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadFromStreamAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&sourceStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUploadWithFormDataAndAutoBoundaryAsync(void* uri, void* parts, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const*>(&parts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUploadWithSubTypeAsync(void* uri, void* parts, void* subType, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const*>(&parts), *reinterpret_cast<hstring const*>(&subType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUploadWithSubTypeAndBoundaryAsync(void* uri, void* parts, void* subType, void* boundary, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().CreateUploadAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> const*>(&parts), *reinterpret_cast<hstring const*>(&subType), *reinterpret_cast<hstring const*>(&boundary)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2>
    {
        int32_t __stdcall get_TransferGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TransferGroup(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TransferGroup(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuccessToastNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotification>(this->shim().SuccessToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuccessToastNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuccessToastNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FailureToastNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::ToastNotification>(this->shim().FailureToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FailureToastNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailureToastNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::ToastNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuccessTileNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileNotification>(this->shim().SuccessTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuccessTileNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuccessTileNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FailureTileNotification(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Notifications::TileNotification>(this->shim().FailureTileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FailureTileNotification(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailureTileNotification(*reinterpret_cast<winrt::Windows::UI::Notifications::TileNotification const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader3> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader3>
    {
        int32_t __stdcall get_CompletionGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup>(this->shim().CompletionGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory>
    {
        int32_t __stdcall CreateWithCompletionGroup(void* completionGroup, void** backgroundUploader) noexcept final try
        {
            clear_abi(backgroundUploader);
            typename D::abi_guard guard(this->shim());
            *backgroundUploader = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundUploader>(this->shim().CreateWithCompletionGroup(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const*>(&completionGroup)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods>
    {
        int32_t __stdcall GetCurrentUploadsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>>(this->shim().GetCurrentUploadsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentUploadsForGroupAsync(void* group, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>>(this->shim().GetCurrentUploadsAsync(*reinterpret_cast<hstring const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2>
    {
        int32_t __stdcall GetCurrentUploadsForTransferGroupAsync(void* group, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>>(this->shim().GetCurrentUploadsForTransferGroupAsync(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const*>(&group)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent>
    {
        int32_t __stdcall RequestUnconstrainedUploadsAsync(void* operations, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult>>(this->shim().RequestUnconstrainedUploadsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::BackgroundTransfer::UploadOperation> const*>(&operations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher>
    {
        int32_t __stdcall get_ContentUris(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>>(this->shim().ContentUris());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IndirectContentUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IndirectContentUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IndirectContentUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().IndirectContentUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcherTime> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcherTime>
    {
        int32_t __stdcall get_LastSuccessfulPrefetchTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().LastSuccessfulPrefetchTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation>
    {
        int32_t __stdcall get_ResultFile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::IStorageFile>(this->shim().ResultFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Progress(struct struct_Windows_Networking_BackgroundTransfer_BackgroundDownloadProgress* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloadProgress>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AttachAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>(this->shim().AttachAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Pause() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resume() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation2> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation2>
    {
        int32_t __stdcall get_TransferGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3>
    {
        int32_t __stdcall get_IsRandomAccessRequired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRandomAccessRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsRandomAccessRequired(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRandomAccessRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetResultRandomAccessStreamReference(void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().GetResultRandomAccessStreamReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDownloadedRanges(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferFileRange>>(this->shim().GetDownloadedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RangesDownloaded(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().RangesDownloaded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation, winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RangesDownloaded(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RangesDownloaded(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall put_RequestedUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestedUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecoverableWebErrorStatuses(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::WebErrorStatus>>(this->shim().RecoverableWebErrorStatuses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentWebErrorStatus(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Web::WebErrorStatus>>(this->shim().CurrentWebErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation4> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation4>
    {
        int32_t __stdcall MakeCurrentInTransferGroup() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MakeCurrentInTransferGroup();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation5> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation5>
    {
        int32_t __stdcall SetRequestHeader(void* headerName, void* headerValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveRequestHeader(void* headerName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveRequestHeader(*reinterpret_cast<hstring const*>(&headerName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IResponseInformation> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IResponseInformation>
    {
        int32_t __stdcall get_IsResumable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsResumable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ActualUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StatusCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().StatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Headers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult>
    {
        int32_t __stdcall get_IsUnconstrained(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUnconstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation>
    {
        int32_t __stdcall get_SourceFile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::IStorageFile>(this->shim().SourceFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Progress(struct struct_Windows_Networking_BackgroundTransfer_BackgroundUploadProgress* value) noexcept final try
        {
            zero_abi<winrt::Windows::Networking::BackgroundTransfer::BackgroundUploadProgress>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundUploadProgress>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::UploadOperation, winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AttachAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Networking::BackgroundTransfer::UploadOperation, winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(this->shim().AttachAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation2> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation2>
    {
        int32_t __stdcall get_TransferGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup>(this->shim().TransferGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation3> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation3>
    {
        int32_t __stdcall MakeCurrentInTransferGroup() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MakeCurrentInTransferGroup();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation4> : produce_base<D, winrt::Windows::Networking::BackgroundTransfer::IUploadOperation4>
    {
        int32_t __stdcall SetRequestHeader(void* headerName, void* headerValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveRequestHeader(void* headerName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveRequestHeader(*reinterpret_cast<hstring const*>(&headerName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Networking::BackgroundTransfer
{
    inline BackgroundDownloader::BackgroundDownloader() :
        BackgroundDownloader(impl::call_factory_cast<BackgroundDownloader(*)(winrt::Windows::Foundation::IActivationFactory const&), BackgroundDownloader>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BackgroundDownloader>(); }))
    {
    }
    inline BackgroundDownloader::BackgroundDownloader(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) :
        BackgroundDownloader(impl::call_factory<BackgroundDownloader, IBackgroundDownloaderFactory>([&](IBackgroundDownloaderFactory const& f) { return f.CreateWithCompletionGroup(completionGroup); }))
    {
    }
    inline auto BackgroundDownloader::GetCurrentDownloadsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>>(*)(IBackgroundDownloaderStaticMethods const&), BackgroundDownloader, IBackgroundDownloaderStaticMethods>([](IBackgroundDownloaderStaticMethods const& f) { return f.GetCurrentDownloadsAsync(); });
    }
    inline auto BackgroundDownloader::GetCurrentDownloadsAsync(param::hstring const& group)
    {
        return impl::call_factory<BackgroundDownloader, IBackgroundDownloaderStaticMethods>([&](IBackgroundDownloaderStaticMethods const& f) { return f.GetCurrentDownloadsAsync(group); });
    }
    inline auto BackgroundDownloader::GetCurrentDownloadsForTransferGroupAsync(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group)
    {
        return impl::call_factory<BackgroundDownloader, IBackgroundDownloaderStaticMethods2>([&](IBackgroundDownloaderStaticMethods2 const& f) { return f.GetCurrentDownloadsForTransferGroupAsync(group); });
    }
    inline auto BackgroundDownloader::RequestUnconstrainedDownloadsAsync(param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation> const& operations)
    {
        return impl::call_factory<BackgroundDownloader, IBackgroundDownloaderUserConsent>([&](IBackgroundDownloaderUserConsent const& f) { return f.RequestUnconstrainedDownloadsAsync(operations); });
    }
    inline BackgroundTransferCompletionGroup::BackgroundTransferCompletionGroup() :
        BackgroundTransferCompletionGroup(impl::call_factory_cast<BackgroundTransferCompletionGroup(*)(winrt::Windows::Foundation::IActivationFactory const&), BackgroundTransferCompletionGroup>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BackgroundTransferCompletionGroup>(); }))
    {
    }
    inline BackgroundTransferContentPart::BackgroundTransferContentPart() :
        BackgroundTransferContentPart(impl::call_factory_cast<BackgroundTransferContentPart(*)(winrt::Windows::Foundation::IActivationFactory const&), BackgroundTransferContentPart>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BackgroundTransferContentPart>(); }))
    {
    }
    inline BackgroundTransferContentPart::BackgroundTransferContentPart(param::hstring const& name) :
        BackgroundTransferContentPart(impl::call_factory<BackgroundTransferContentPart, IBackgroundTransferContentPartFactory>([&](IBackgroundTransferContentPartFactory const& f) { return f.CreateWithName(name); }))
    {
    }
    inline BackgroundTransferContentPart::BackgroundTransferContentPart(param::hstring const& name, param::hstring const& fileName) :
        BackgroundTransferContentPart(impl::call_factory<BackgroundTransferContentPart, IBackgroundTransferContentPartFactory>([&](IBackgroundTransferContentPartFactory const& f) { return f.CreateWithNameAndFileName(name, fileName); }))
    {
    }
    inline auto BackgroundTransferError::GetStatus(int32_t hresult)
    {
        return impl::call_factory<BackgroundTransferError, IBackgroundTransferErrorStaticMethods>([&](IBackgroundTransferErrorStaticMethods const& f) { return f.GetStatus(hresult); });
    }
    inline auto BackgroundTransferGroup::CreateGroup(param::hstring const& name)
    {
        return impl::call_factory<BackgroundTransferGroup, IBackgroundTransferGroupStatics>([&](IBackgroundTransferGroupStatics const& f) { return f.CreateGroup(name); });
    }
    inline BackgroundUploader::BackgroundUploader() :
        BackgroundUploader(impl::call_factory_cast<BackgroundUploader(*)(winrt::Windows::Foundation::IActivationFactory const&), BackgroundUploader>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BackgroundUploader>(); }))
    {
    }
    inline BackgroundUploader::BackgroundUploader(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup const& completionGroup) :
        BackgroundUploader(impl::call_factory<BackgroundUploader, IBackgroundUploaderFactory>([&](IBackgroundUploaderFactory const& f) { return f.CreateWithCompletionGroup(completionGroup); }))
    {
    }
    inline auto BackgroundUploader::GetCurrentUploadsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::BackgroundTransfer::UploadOperation>>(*)(IBackgroundUploaderStaticMethods const&), BackgroundUploader, IBackgroundUploaderStaticMethods>([](IBackgroundUploaderStaticMethods const& f) { return f.GetCurrentUploadsAsync(); });
    }
    inline auto BackgroundUploader::GetCurrentUploadsAsync(param::hstring const& group)
    {
        return impl::call_factory<BackgroundUploader, IBackgroundUploaderStaticMethods>([&](IBackgroundUploaderStaticMethods const& f) { return f.GetCurrentUploadsAsync(group); });
    }
    inline auto BackgroundUploader::GetCurrentUploadsForTransferGroupAsync(winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup const& group)
    {
        return impl::call_factory<BackgroundUploader, IBackgroundUploaderStaticMethods2>([&](IBackgroundUploaderStaticMethods2 const& f) { return f.GetCurrentUploadsForTransferGroupAsync(group); });
    }
    inline auto BackgroundUploader::RequestUnconstrainedUploadsAsync(param::async_iterable<winrt::Windows::Networking::BackgroundTransfer::UploadOperation> const& operations)
    {
        return impl::call_factory<BackgroundUploader, IBackgroundUploaderUserConsent>([&](IBackgroundUploaderUserConsent const& f) { return f.RequestUnconstrainedUploadsAsync(operations); });
    }
    inline auto ContentPrefetcher::ContentUris()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>(*)(IContentPrefetcher const&), ContentPrefetcher, IContentPrefetcher>([](IContentPrefetcher const& f) { return f.ContentUris(); });
    }
    inline auto ContentPrefetcher::IndirectContentUri(winrt::Windows::Foundation::Uri const& value)
    {
        impl::call_factory<ContentPrefetcher, IContentPrefetcher>([&](IContentPrefetcher const& f) { return f.IndirectContentUri(value); });
    }
    inline auto ContentPrefetcher::IndirectContentUri()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Uri(*)(IContentPrefetcher const&), ContentPrefetcher, IContentPrefetcher>([](IContentPrefetcher const& f) { return f.IndirectContentUri(); });
    }
    inline auto ContentPrefetcher::LastSuccessfulPrefetchTime()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>(*)(IContentPrefetcherTime const&), ContentPrefetcher, IContentPrefetcherTime>([](IContentPrefetcherTime const& f) { return f.LastSuccessfulPrefetchTime(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloader3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderStaticMethods2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundDownloaderUserConsent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferCompletionGroupTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPart> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferContentPartFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferErrorStaticMethods> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferGroupStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferOperationPriority> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundTransferRangesDownloadedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploader3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderStaticMethods2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IBackgroundUploaderUserConsent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IContentPrefetcherTime> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IDownloadOperation5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IResponseInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUnconstrainedTransferRequestResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::IUploadOperation4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundDownloader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferCompletionGroupTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferContentPart> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundTransferRangesDownloadedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::BackgroundUploader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::ContentPrefetcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::ResponseInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::UnconstrainedTransferRequestResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::BackgroundTransfer::UploadOperation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
