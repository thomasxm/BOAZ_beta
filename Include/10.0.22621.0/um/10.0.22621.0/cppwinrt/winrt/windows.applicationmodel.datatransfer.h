// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_H
#define WINRT_Windows_ApplicationModel_DataTransfer_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.EnterpriseData.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsRoamable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_IsRoamable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsRoamable(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->put_IsRoamable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsAllowedInHistory() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_IsAllowedInHistory(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::IsAllowedInHistory(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->put_IsAllowedInHistory(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::RoamingFormats() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_RoamingFormats(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_DataTransfer_IClipboardContentOptions<D>::HistoryFormats() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions)->get_HistoryFormats(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItem<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem)->get_Content(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus) consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItemsResult<D>::Status() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>) consume_Windows_ApplicationModel_DataTransfer_IClipboardHistoryItemsResult<D>::Items() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult)->get_Items(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::GetContent() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics)->GetContent(&result));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::SetContent(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& content) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics)->SetContent(*(void**)(&content)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::Flush() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics)->Flush());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics)->add_ContentChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ContentChanged_revoker>(this, ContentChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics<D>::ContentChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics)->remove_ContentChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::GetHistoryItemsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->GetHistoryItemsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::ClearHistory() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->ClearHistory(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::DeleteItemFromHistory(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->DeleteItemFromHistory(*(void**)(&item), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::SetHistoryItemAsContent(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item) const
    {
        winrt::Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->SetHistoryItemAsContent(*(void**)(&item), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::IsHistoryEnabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->IsHistoryEnabled(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::IsRoamingEnabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->IsRoamingEnabled(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::SetContentWithOptions(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& content, winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->SetContentWithOptions(*(void**)(&content), *(void**)(&options), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->add_HistoryChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, HistoryChanged_revoker>(this, HistoryChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->remove_HistoryChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->add_RoamingEnabledChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RoamingEnabledChanged_revoker>(this, RoamingEnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::RoamingEnabledChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->remove_RoamingEnabledChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->add_HistoryEnabledChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged_revoker consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, HistoryEnabledChanged_revoker>(this, HistoryEnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IClipboardStatics2<D>::HistoryEnabledChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2)->remove_HistoryEnabledChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::GetView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->GetView(&result));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySet) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->get_Properties(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::RequestedOperation() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->get_RequestedOperation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::RequestedOperation(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->put_RequestedOperation(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->add_OperationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OperationCompleted_revoker>(this, OperationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::OperationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->remove_OperationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->add_Destroyed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Destroyed_revoker>(this, Destroyed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::Destroyed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->remove_Destroyed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetData(param::hstring const& formatId, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetData(*(void**)(&formatId), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetDataProvider(param::hstring const& formatId, winrt::Windows::ApplicationModel::DataTransfer::DataProviderHandler const& delayRenderer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetDataProvider(*(void**)(&formatId), *(void**)(&delayRenderer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetHtmlFormat(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetHtmlFormat(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Storage::Streams::RandomAccessStreamReference>) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::ResourceMap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->get_ResourceMap(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetRtf(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetRtf(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetBitmap(winrt::Windows::Storage::Streams::RandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetBitmap(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetStorageItems(param::iterable<winrt::Windows::Storage::IStorageItem> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetStorageItemsReadOnly(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage<D>::SetStorageItems(param::iterable<winrt::Windows::Storage::IStorageItem> const& value, bool readOnly) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage)->SetStorageItems(*(void**)(&value), readOnly));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage2<D>::SetApplicationLink(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2)->SetApplicationLink(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage2<D>::SetWebLink(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2)->SetWebLink(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3)->add_ShareCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ShareCompleted_revoker>(this, ShareCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage3<D>::ShareCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3)->remove_ShareCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataPackage4<D>::ShareCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage4)->add_ShareCanceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataPackage4<D>::ShareCanceled_revoker consume_Windows_ApplicationModel_DataTransfer_IDataPackage4<D>::ShareCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ShareCanceled_revoker>(this, ShareCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackage4<D>::ShareCanceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackage4)->remove_ShareCanceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::Thumbnail(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::FileTypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_FileTypes(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_ApplicationName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_ApplicationName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationListingUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->get_ApplicationListingUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet<D>::ApplicationListingUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet)->put_ApplicationListingUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceWebLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_ContentSourceWebLink(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceWebLink(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_ContentSourceWebLink(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceApplicationLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_ContentSourceApplicationLink(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::ContentSourceApplicationLink(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_ContentSourceApplicationLink(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::PackageFamilyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_PackageFamilyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::Square30x30Logo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_Square30x30Logo(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::Square30x30Logo(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_Square30x30Logo(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::LogoBackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->get_LogoBackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet2<D>::LogoBackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2)->put_LogoBackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet3<D>::EnterpriseId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3)->get_EnterpriseId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet3<D>::EnterpriseId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3)->put_EnterpriseId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet4<D>::ContentSourceUserActivityJson() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4)->get_ContentSourceUserActivityJson(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySet4<D>::ContentSourceUserActivityJson(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4)->put_ContentSourceUserActivityJson(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::FileTypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_FileTypes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::ApplicationName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_ApplicationName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView<D>::ApplicationListingUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView)->get_ApplicationListingUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::PackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_PackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::ContentSourceWebLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_ContentSourceWebLink(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::ContentSourceApplicationLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_ContentSourceApplicationLink(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::Square30x30Logo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_Square30x30Logo(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView2<D>::LogoBackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2)->get_LogoBackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView3<D>::EnterpriseId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3)->get_EnterpriseId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView4<D>::ContentSourceUserActivityJson() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4)->get_ContentSourceUserActivityJson(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IDataPackagePropertySetView5<D>::IsFromRoamingClipboard() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5)->get_IsFromRoamingClipboard(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->get_Properties(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::RequestedOperation() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->get_RequestedOperation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::ReportOperationCompleted(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->ReportOperationCompleted(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::AvailableFormats() const
    {
        void* formatIds{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->get_AvailableFormats(&formatIds));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ formatIds, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::Contains(param::hstring const& formatId) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->Contains(*(void**)(&formatId), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetDataAsync(param::hstring const& formatId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetDataAsync(*(void**)(&formatId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetTextAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetTextAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetTextAsync(param::hstring const& formatId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetCustomTextAsync(*(void**)(&formatId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetUriAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetUriAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetHtmlFormatAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetHtmlFormatAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::RandomAccessStreamReference>>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetResourceMapAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetResourceMapAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::RandomAccessStreamReference>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetRtfAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetRtfAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetBitmapAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetBitmapAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView<D>::GetStorageItemsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView)->GetStorageItemsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView2<D>::GetApplicationLinkAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2)->GetApplicationLinkAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView2<D>::GetWebLinkAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2)->GetWebLinkAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>::RequestAccessAsync(param::hstring const& enterpriseId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3)->RequestAccessWithEnterpriseIdAsync(*(void**)(&enterpriseId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView3<D>::UnlockAndAssumeEnterpriseIdentity() const
    {
        winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3)->UnlockAndAssumeEnterpriseIdentity(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataPackageView4<D>::SetAcceptedFormatId(param::hstring const& formatId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4)->SetAcceptedFormatId(*(void**)(&formatId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataProviderDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::FormatId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->get_FormatId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::Deadline() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->get_Deadline(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataProviderDeferral) consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->GetDeferral(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataProviderDeferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataProviderRequest<D>::SetData(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest)->SetData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackage) consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequest)->get_Data(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::Data(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequest)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::Deadline() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequest)->get_Deadline(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::FailWithDisplayText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequest)->FailWithDisplayText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataRequestDeferral) consume_Windows_ApplicationModel_DataTransfer_IDataRequest<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequest)->GetDeferral(&result));
        return winrt::Windows::ApplicationModel::DataTransfer::DataRequestDeferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataRequestDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataRequest) consume_Windows_ApplicationModel_DataTransfer_IDataRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager)->add_DataRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested_revoker consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DataRequested_revoker>(this, DataRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::DataRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager)->remove_DataRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager)->add_TargetApplicationChosen(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen_revoker consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TargetApplicationChosen_revoker>(this, TargetApplicationChosen(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager<D>::TargetApplicationChosen(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager)->remove_TargetApplicationChosen(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2)->add_ShareProvidersRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested_revoker consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ShareProvidersRequested_revoker>(this, ShareProvidersRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManager2<D>::ShareProvidersRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2)->remove_ShareProvidersRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics<D>::ShowShareUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics)->ShowShareUI());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics)->GetForCurrentView(&result));
        return winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics2<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IDataTransferManagerStatics3<D>::ShowShareUI(winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3)->ShowShareUIWithOptions(*(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IHtmlFormatHelperStatics<D>::GetStaticFragment(param::hstring const& htmlFormat) const
    {
        void* htmlFragment{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics)->GetStaticFragment(*(void**)(&htmlFormat), &htmlFragment));
        return hstring{ htmlFragment, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IHtmlFormatHelperStatics<D>::CreateHtmlFormat(param::hstring const& htmlFragment) const
    {
        void* htmlFormat{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics)->CreateHtmlFormat(*(void**)(&htmlFragment), &htmlFormat));
        return hstring{ htmlFormat, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation) consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs<D>::Operation() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs)->get_Operation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IOperationCompletedEventArgs2<D>::AcceptedFormatId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2)->get_AcceptedFormatId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::ShareTargetInfo) consume_Windows_ApplicationModel_DataTransfer_IShareCompletedEventArgs<D>::ShareTarget() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs)->get_ShareTarget(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::ShareTargetInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvider)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::DisplayIcon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvider)->get_DisplayIcon(&value));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::BackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvider)->get_BackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvider)->get_Tag(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IShareProvider<D>::Tag(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvider)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::ShareProvider) consume_Windows_ApplicationModel_DataTransfer_IShareProviderFactory<D>::Create(param::hstring const& title, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, winrt::Windows::UI::Color const& backgroundColor, winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProviderFactory)->Create(*(void**)(&title), *(void**)(&displayIcon), impl::bind_in(backgroundColor), *(void**)(&handler), &result));
        return winrt::Windows::ApplicationModel::DataTransfer::ShareProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation)->get_Data(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::ShareProvider) consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>::Provider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation)->get_Provider(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::ShareProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IShareProviderOperation<D>::ReportCompleted() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation)->ReportCompleted());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider>) consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>::Providers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs)->get_Providers(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs)->get_Data(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::DataPackageView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_ApplicationModel_DataTransfer_IShareProvidersRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IShareTargetInfo<D>::AppUserModelId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo)->get_AppUserModelId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::ShareProvider) consume_Windows_ApplicationModel_DataTransfer_IShareTargetInfo<D>::ShareProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo)->get_ShareProvider(&value));
        return winrt::Windows::ApplicationModel::DataTransfer::ShareProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::ShareUITheme) consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::Theme() const
    {
        winrt::Windows::ApplicationModel::DataTransfer::ShareUITheme value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions)->get_Theme(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::Theme(winrt::Windows::ApplicationModel::DataTransfer::ShareUITheme const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions)->put_Theme(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>) consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::SelectionRect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions)->get_SelectionRect(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_IShareUIOptions<D>::SelectionRect(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions)->put_SelectionRect(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>::AddFile(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* outToken{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics)->AddFile(*(void**)(&file), &outToken));
        return hstring{ outToken, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>::RedeemTokenForFileAsync(param::hstring const& token) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics)->RedeemTokenForFileAsync(*(void**)(&token), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_DataTransfer_ISharedStorageAccessManagerStatics<D>::RemoveFile(param::hstring const& token) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics)->RemoveFile(*(void**)(&token)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Uri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Html() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Html(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Rtf() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Rtf(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::Bitmap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_Bitmap(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics<D>::StorageItems() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics)->get_StorageItems(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics2<D>::WebLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2)->get_WebLink(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics2<D>::ApplicationLink() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2)->get_ApplicationLink(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_IStandardDataFormatsStatics3<D>::UserActivityJsonArray() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3)->get_UserActivityJsonArray(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_DataTransfer_ITargetApplicationChosenEventArgs<D>::ApplicationName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs)->get_ApplicationName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::ApplicationModel::DataTransfer::DataProviderHandler, H> final : implements_delegate<winrt::Windows::ApplicationModel::DataTransfer::DataProviderHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::ApplicationModel::DataTransfer::DataProviderHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* request) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataProviderRequest const*>(&request));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler, H> final : implements_delegate<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* operation) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderOperation const*>(&operation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions>
    {
        int32_t __stdcall get_IsRoamable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRoamable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsRoamable(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRoamable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAllowedInHistory(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAllowedInHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAllowedInHistory(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAllowedInHistory(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoamingFormats(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().RoamingFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HistoryFormats(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().HistoryFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Items(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics>
    {
        int32_t __stdcall GetContent(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().GetContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContent(void* content) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetContent(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackage const*>(&content));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Flush() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Flush();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clear() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ContentChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ContentChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContentChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>
    {
        int32_t __stdcall GetHistoryItemsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>>(this->shim().GetHistoryItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearHistory(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ClearHistory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteItemFromHistory(void* item, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().DeleteItemFromHistory(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHistoryItemAsContent(void* item, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::DataTransfer::SetHistoryItemAsContentStatus>(this->shim().SetHistoryItemAsContent(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsHistoryEnabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsHistoryEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsRoamingEnabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsRoamingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetContentWithOptions(void* content, void* options, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().SetContentWithOptions(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackage const*>(&content), *reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_HistoryChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HistoryChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HistoryChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HistoryChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RoamingEnabledChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RoamingEnabledChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RoamingEnabledChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoamingEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_HistoryEnabledChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HistoryEnabledChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HistoryEnabledChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HistoryEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage>
    {
        int32_t __stdcall GetView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().GetView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedOperation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().RequestedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RequestedOperation(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestedOperation(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_OperationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OperationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OperationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OperationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Destroyed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Destroyed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Destroyed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Destroyed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall SetData(void* formatId, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetData(*reinterpret_cast<hstring const*>(&formatId), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDataProvider(void* formatId, void* delayRenderer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDataProvider(*reinterpret_cast<hstring const*>(&formatId), *reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataProviderHandler const*>(&delayRenderer));
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
        int32_t __stdcall SetUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetHtmlFormat(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetHtmlFormat(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResourceMap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().ResourceMap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetRtf(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRtf(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBitmap(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBitmap(*reinterpret_cast<winrt::Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStorageItemsReadOnly(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStorageItems(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::IStorageItem> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStorageItems(void* value, bool readOnly) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStorageItems(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::IStorageItem> const*>(&value), readOnly);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2>
    {
        int32_t __stdcall SetApplicationLink(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetApplicationLink(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetWebLink(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetWebLink(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3>
    {
        int32_t __stdcall add_ShareCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShareCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShareCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShareCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage4> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackage4>
    {
        int32_t __stdcall add_ShareCanceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShareCanceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataPackage, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShareCanceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShareCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet>
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
        int32_t __stdcall get_FileTypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().FileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ApplicationName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ApplicationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ApplicationName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplicationName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ApplicationListingUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ApplicationListingUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ApplicationListingUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplicationListingUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2>
    {
        int32_t __stdcall get_ContentSourceWebLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ContentSourceWebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentSourceWebLink(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentSourceWebLink(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentSourceApplicationLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ContentSourceApplicationLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentSourceApplicationLink(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentSourceApplicationLink(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PackageFamilyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Square30x30Logo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Square30x30Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Square30x30Logo(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Square30x30Logo(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogoBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().LogoBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LogoBackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogoBackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3>
    {
        int32_t __stdcall get_EnterpriseId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnterpriseId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnterpriseId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4>
    {
        int32_t __stdcall get_ContentSourceUserActivityJson(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentSourceUserActivityJson());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ContentSourceUserActivityJson(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContentSourceUserActivityJson(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
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
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileTypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ApplicationName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ApplicationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ApplicationListingUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ApplicationListingUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2>
    {
        int32_t __stdcall get_PackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentSourceWebLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ContentSourceWebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentSourceApplicationLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ContentSourceApplicationLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Square30x30Logo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Square30x30Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogoBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().LogoBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3>
    {
        int32_t __stdcall get_EnterpriseId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4>
    {
        int32_t __stdcall get_ContentSourceUserActivityJson(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentSourceUserActivityJson());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5>
    {
        int32_t __stdcall get_IsFromRoamingClipboard(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFromRoamingClipboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView>
    {
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestedOperation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().RequestedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportOperationCompleted(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportOperationCompleted(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AvailableFormats(void** formatIds) noexcept final try
        {
            clear_abi(formatIds);
            typename D::abi_guard guard(this->shim());
            *formatIds = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AvailableFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Contains(void* formatId, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Contains(*reinterpret_cast<hstring const*>(&formatId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDataAsync(void* formatId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::IInspectable>>(this->shim().GetDataAsync(*reinterpret_cast<hstring const*>(&formatId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTextAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetTextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCustomTextAsync(void* formatId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetTextAsync(*reinterpret_cast<hstring const*>(&formatId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUriAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>>(this->shim().GetUriAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHtmlFormatAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetHtmlFormatAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetResourceMapAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::Streams::RandomAccessStreamReference>>>(this->shim().GetResourceMapAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRtfAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetRtfAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBitmapAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::RandomAccessStreamReference>>(this->shim().GetBitmapAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStorageItemsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>>(this->shim().GetStorageItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2>
    {
        int32_t __stdcall GetApplicationLinkAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>>(this->shim().GetApplicationLinkAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetWebLinkAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Uri>>(this->shim().GetWebLinkAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3>
    {
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessWithEnterpriseIdAsync(void* enterpriseId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>>(this->shim().RequestAccessAsync(*reinterpret_cast<hstring const*>(&enterpriseId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnlockAndAssumeEnterpriseIdentity(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>(this->shim().UnlockAndAssumeEnterpriseIdentity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4>
    {
        int32_t __stdcall SetAcceptedFormatId(void* formatId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAcceptedFormatId(*reinterpret_cast<hstring const*>(&formatId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral>
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
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest>
    {
        int32_t __stdcall get_FormatId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FormatId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Deadline(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataProviderDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetData(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataRequest> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataRequest>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackage>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Deadline(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FailWithDisplayText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FailWithDisplayText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral>
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
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager>
    {
        int32_t __stdcall add_DataRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DataRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DataRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TargetApplicationChosen(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TargetApplicationChosen(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TargetApplicationChosen(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetApplicationChosen(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2>
    {
        int32_t __stdcall add_ShareProvidersRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShareProvidersRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager, winrt::Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShareProvidersRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShareProvidersRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics>
    {
        int32_t __stdcall ShowShareUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowShareUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2>
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3>
    {
        int32_t __stdcall ShowShareUIWithOptions(void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowShareUI(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics>
    {
        int32_t __stdcall GetStaticFragment(void* htmlFormat, void** htmlFragment) noexcept final try
        {
            clear_abi(htmlFragment);
            typename D::abi_guard guard(this->shim());
            *htmlFragment = detach_from<hstring>(this->shim().GetStaticFragment(*reinterpret_cast<hstring const*>(&htmlFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateHtmlFormat(void* htmlFragment, void** htmlFormat) noexcept final try
        {
            clear_abi(htmlFormat);
            typename D::abi_guard guard(this->shim());
            *htmlFormat = detach_from<hstring>(this->shim().CreateHtmlFormat(*reinterpret_cast<hstring const*>(&htmlFragment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs>
    {
        int32_t __stdcall get_Operation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().Operation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2>
    {
        int32_t __stdcall get_AcceptedFormatId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AcceptedFormatId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs>
    {
        int32_t __stdcall get_ShareTarget(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::ShareTargetInfo>(this->shim().ShareTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProvider> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProvider>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayIcon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().DisplayIcon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProviderFactory> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProviderFactory>
    {
        int32_t __stdcall Create(void* title, void* displayIcon, struct struct_Windows_UI_Color backgroundColor, void* handler, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider>(this->shim().Create(*reinterpret_cast<hstring const*>(&title), *reinterpret_cast<winrt::Windows::Storage::Streams::RandomAccessStreamReference const*>(&displayIcon), *reinterpret_cast<winrt::Windows::UI::Color const*>(&backgroundColor), *reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Provider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider>(this->shim().Provider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompleted() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs>
    {
        int32_t __stdcall get_Providers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider>>(this->shim().Providers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().Data());
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
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo>
    {
        int32_t __stdcall get_AppUserModelId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShareProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider>(this->shim().ShareProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions>
    {
        int32_t __stdcall get_Theme(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::DataTransfer::ShareUITheme>(this->shim().Theme());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Theme(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Theme(*reinterpret_cast<winrt::Windows::ApplicationModel::DataTransfer::ShareUITheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionRect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect>>(this->shim().SelectionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SelectionRect(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectionRect(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics>
    {
        int32_t __stdcall AddFile(void* file, void** outToken) noexcept final try
        {
            clear_abi(outToken);
            typename D::abi_guard guard(this->shim());
            *outToken = detach_from<hstring>(this->shim().AddFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RedeemTokenForFileAsync(void* token, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().RedeemTokenForFileAsync(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveFile(void* token) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveFile(*reinterpret_cast<hstring const*>(&token));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Html(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Html());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rtf(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Rtf());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bitmap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Bitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StorageItems(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StorageItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2>
    {
        int32_t __stdcall get_WebLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WebLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ApplicationLink(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ApplicationLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3>
    {
        int32_t __stdcall get_UserActivityJsonArray(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserActivityJsonArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs>
    {
        int32_t __stdcall get_ApplicationName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ApplicationName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer
{
    constexpr auto operator|(DataPackageOperation const left, DataPackageOperation const right) noexcept
    {
        return static_cast<DataPackageOperation>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DataPackageOperation& left, DataPackageOperation const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DataPackageOperation const left, DataPackageOperation const right) noexcept
    {
        return static_cast<DataPackageOperation>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DataPackageOperation& left, DataPackageOperation const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DataPackageOperation const value) noexcept
    {
        return static_cast<DataPackageOperation>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DataPackageOperation const left, DataPackageOperation const right) noexcept
    {
        return static_cast<DataPackageOperation>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DataPackageOperation& left, DataPackageOperation const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto Clipboard::GetContent()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView(*)(IClipboardStatics const&), Clipboard, IClipboardStatics>([](IClipboardStatics const& f) { return f.GetContent(); });
    }
    inline auto Clipboard::SetContent(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& content)
    {
        impl::call_factory<Clipboard, IClipboardStatics>([&](IClipboardStatics const& f) { return f.SetContent(content); });
    }
    inline auto Clipboard::Flush()
    {
        impl::call_factory_cast<void(*)(IClipboardStatics const&), Clipboard, IClipboardStatics>([](IClipboardStatics const& f) { return f.Flush(); });
    }
    inline auto Clipboard::Clear()
    {
        impl::call_factory_cast<void(*)(IClipboardStatics const&), Clipboard, IClipboardStatics>([](IClipboardStatics const& f) { return f.Clear(); });
    }
    inline auto Clipboard::ContentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<Clipboard, IClipboardStatics>([&](IClipboardStatics const& f) { return f.ContentChanged(handler); });
    }
    inline Clipboard::ContentChanged_revoker Clipboard::ContentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<Clipboard, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics>();
        return { f, f.ContentChanged(handler) };
    }
    inline auto Clipboard::ContentChanged(winrt::event_token const& token)
    {
        impl::call_factory<Clipboard, IClipboardStatics>([&](IClipboardStatics const& f) { return f.ContentChanged(token); });
    }
    inline auto Clipboard::GetHistoryItemsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult>(*)(IClipboardStatics2 const&), Clipboard, IClipboardStatics2>([](IClipboardStatics2 const& f) { return f.GetHistoryItemsAsync(); });
    }
    inline auto Clipboard::ClearHistory()
    {
        return impl::call_factory_cast<bool(*)(IClipboardStatics2 const&), Clipboard, IClipboardStatics2>([](IClipboardStatics2 const& f) { return f.ClearHistory(); });
    }
    inline auto Clipboard::DeleteItemFromHistory(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item)
    {
        return impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.DeleteItemFromHistory(item); });
    }
    inline auto Clipboard::SetHistoryItemAsContent(winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem const& item)
    {
        return impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.SetHistoryItemAsContent(item); });
    }
    inline auto Clipboard::IsHistoryEnabled()
    {
        return impl::call_factory_cast<bool(*)(IClipboardStatics2 const&), Clipboard, IClipboardStatics2>([](IClipboardStatics2 const& f) { return f.IsHistoryEnabled(); });
    }
    inline auto Clipboard::IsRoamingEnabled()
    {
        return impl::call_factory_cast<bool(*)(IClipboardStatics2 const&), Clipboard, IClipboardStatics2>([](IClipboardStatics2 const& f) { return f.IsRoamingEnabled(); });
    }
    inline auto Clipboard::SetContentWithOptions(winrt::Windows::ApplicationModel::DataTransfer::DataPackage const& content, winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions const& options)
    {
        return impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.SetContentWithOptions(content, options); });
    }
    inline auto Clipboard::HistoryChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler)
    {
        return impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.HistoryChanged(handler); });
    }
    inline Clipboard::HistoryChanged_revoker Clipboard::HistoryChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> const& handler)
    {
        auto f = get_activation_factory<Clipboard, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>();
        return { f, f.HistoryChanged(handler) };
    }
    inline auto Clipboard::HistoryChanged(winrt::event_token const& token)
    {
        impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.HistoryChanged(token); });
    }
    inline auto Clipboard::RoamingEnabledChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.RoamingEnabledChanged(handler); });
    }
    inline Clipboard::RoamingEnabledChanged_revoker Clipboard::RoamingEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<Clipboard, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>();
        return { f, f.RoamingEnabledChanged(handler) };
    }
    inline auto Clipboard::RoamingEnabledChanged(winrt::event_token const& token)
    {
        impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.RoamingEnabledChanged(token); });
    }
    inline auto Clipboard::HistoryEnabledChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.HistoryEnabledChanged(handler); });
    }
    inline Clipboard::HistoryEnabledChanged_revoker Clipboard::HistoryEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<Clipboard, winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2>();
        return { f, f.HistoryEnabledChanged(handler) };
    }
    inline auto Clipboard::HistoryEnabledChanged(winrt::event_token const& token)
    {
        impl::call_factory<Clipboard, IClipboardStatics2>([&](IClipboardStatics2 const& f) { return f.HistoryEnabledChanged(token); });
    }
    inline ClipboardContentOptions::ClipboardContentOptions() :
        ClipboardContentOptions(impl::call_factory_cast<ClipboardContentOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), ClipboardContentOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ClipboardContentOptions>(); }))
    {
    }
    inline DataPackage::DataPackage() :
        DataPackage(impl::call_factory_cast<DataPackage(*)(winrt::Windows::Foundation::IActivationFactory const&), DataPackage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DataPackage>(); }))
    {
    }
    inline auto DataTransferManager::ShowShareUI()
    {
        impl::call_factory_cast<void(*)(IDataTransferManagerStatics const&), DataTransferManager, IDataTransferManagerStatics>([](IDataTransferManagerStatics const& f) { return f.ShowShareUI(); });
    }
    inline auto DataTransferManager::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager(*)(IDataTransferManagerStatics const&), DataTransferManager, IDataTransferManagerStatics>([](IDataTransferManagerStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto DataTransferManager::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(IDataTransferManagerStatics2 const&), DataTransferManager, IDataTransferManagerStatics2>([](IDataTransferManagerStatics2 const& f) { return f.IsSupported(); });
    }
    inline auto DataTransferManager::ShowShareUI(winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions const& options)
    {
        impl::call_factory<DataTransferManager, IDataTransferManagerStatics3>([&](IDataTransferManagerStatics3 const& f) { return f.ShowShareUI(options); });
    }
    inline auto HtmlFormatHelper::GetStaticFragment(param::hstring const& htmlFormat)
    {
        return impl::call_factory<HtmlFormatHelper, IHtmlFormatHelperStatics>([&](IHtmlFormatHelperStatics const& f) { return f.GetStaticFragment(htmlFormat); });
    }
    inline auto HtmlFormatHelper::CreateHtmlFormat(param::hstring const& htmlFragment)
    {
        return impl::call_factory<HtmlFormatHelper, IHtmlFormatHelperStatics>([&](IHtmlFormatHelperStatics const& f) { return f.CreateHtmlFormat(htmlFragment); });
    }
    inline ShareProvider::ShareProvider(param::hstring const& title, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& displayIcon, winrt::Windows::UI::Color const& backgroundColor, winrt::Windows::ApplicationModel::DataTransfer::ShareProviderHandler const& handler) :
        ShareProvider(impl::call_factory<ShareProvider, IShareProviderFactory>([&](IShareProviderFactory const& f) { return f.Create(title, displayIcon, backgroundColor, handler); }))
    {
    }
    inline ShareUIOptions::ShareUIOptions() :
        ShareUIOptions(impl::call_factory_cast<ShareUIOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), ShareUIOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ShareUIOptions>(); }))
    {
    }
    inline auto SharedStorageAccessManager::AddFile(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<SharedStorageAccessManager, ISharedStorageAccessManagerStatics>([&](ISharedStorageAccessManagerStatics const& f) { return f.AddFile(file); });
    }
    inline auto SharedStorageAccessManager::RedeemTokenForFileAsync(param::hstring const& token)
    {
        return impl::call_factory<SharedStorageAccessManager, ISharedStorageAccessManagerStatics>([&](ISharedStorageAccessManagerStatics const& f) { return f.RedeemTokenForFileAsync(token); });
    }
    inline auto SharedStorageAccessManager::RemoveFile(param::hstring const& token)
    {
        impl::call_factory<SharedStorageAccessManager, ISharedStorageAccessManagerStatics>([&](ISharedStorageAccessManagerStatics const& f) { return f.RemoveFile(token); });
    }
    inline auto StandardDataFormats::Text()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics const&), StandardDataFormats, IStandardDataFormatsStatics>([](IStandardDataFormatsStatics const& f) { return f.Text(); });
    }
    inline auto StandardDataFormats::Uri()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics const&), StandardDataFormats, IStandardDataFormatsStatics>([](IStandardDataFormatsStatics const& f) { return f.Uri(); });
    }
    inline auto StandardDataFormats::Html()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics const&), StandardDataFormats, IStandardDataFormatsStatics>([](IStandardDataFormatsStatics const& f) { return f.Html(); });
    }
    inline auto StandardDataFormats::Rtf()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics const&), StandardDataFormats, IStandardDataFormatsStatics>([](IStandardDataFormatsStatics const& f) { return f.Rtf(); });
    }
    inline auto StandardDataFormats::Bitmap()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics const&), StandardDataFormats, IStandardDataFormatsStatics>([](IStandardDataFormatsStatics const& f) { return f.Bitmap(); });
    }
    inline auto StandardDataFormats::StorageItems()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics const&), StandardDataFormats, IStandardDataFormatsStatics>([](IStandardDataFormatsStatics const& f) { return f.StorageItems(); });
    }
    inline auto StandardDataFormats::WebLink()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics2 const&), StandardDataFormats, IStandardDataFormatsStatics2>([](IStandardDataFormatsStatics2 const& f) { return f.WebLink(); });
    }
    inline auto StandardDataFormats::ApplicationLink()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics2 const&), StandardDataFormats, IStandardDataFormatsStatics2>([](IStandardDataFormatsStatics2 const& f) { return f.ApplicationLink(); });
    }
    inline auto StandardDataFormats::UserActivityJsonArray()
    {
        return impl::call_factory_cast<hstring(*)(IStandardDataFormatsStatics3 const&), StandardDataFormats, IStandardDataFormatsStatics3>([](IStandardDataFormatsStatics3 const& f) { return f.UserActivityJsonArray(); });
    }
    template <typename L> DataProviderHandler::DataProviderHandler(L handler) :
        DataProviderHandler(impl::make_delegate<DataProviderHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DataProviderHandler::DataProviderHandler(F* handler) :
        DataProviderHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DataProviderHandler::DataProviderHandler(O* object, M method) :
        DataProviderHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DataProviderHandler::DataProviderHandler(com_ptr<O>&& object, M method) :
        DataProviderHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DataProviderHandler::DataProviderHandler(weak_ref<O>&& object, M method) :
        DataProviderHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DataProviderHandler::operator()(winrt::Windows::ApplicationModel::DataTransfer::DataProviderRequest const& request) const
    {
        check_hresult((*(impl::abi_t<DataProviderHandler>**)this)->Invoke(*(void**)(&request)));
    }
    template <typename L> ShareProviderHandler::ShareProviderHandler(L handler) :
        ShareProviderHandler(impl::make_delegate<ShareProviderHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> ShareProviderHandler::ShareProviderHandler(F* handler) :
        ShareProviderHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> ShareProviderHandler::ShareProviderHandler(O* object, M method) :
        ShareProviderHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> ShareProviderHandler::ShareProviderHandler(com_ptr<O>&& object, M method) :
        ShareProviderHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> ShareProviderHandler::ShareProviderHandler(weak_ref<O>&& object, M method) :
        ShareProviderHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto ShareProviderHandler::operator()(winrt::Windows::ApplicationModel::DataTransfer::ShareProviderOperation const& operation) const
    {
        check_hresult((*(impl::abi_t<ShareProviderHandler>**)this)->Invoke(*(void**)(&operation)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardContentOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardHistoryItemsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IClipboardStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackage4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySet4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackagePropertySetView5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataPackageView4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataProviderDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataProviderRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IDataTransferManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IHtmlFormatHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IOperationCompletedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProviderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProviderOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareProvidersRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareTargetInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IShareUIOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ISharedStorageAccessManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::IStandardDataFormatsStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ITargetApplicationChosenEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::Clipboard> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardContentOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ClipboardHistoryItemsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackagePropertySetView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataPackageView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataProviderDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataProviderRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::DataTransferManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::HtmlFormatHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::OperationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareProviderOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareProvidersRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareTargetInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::ShareUIOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::SharedStorageAccessManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::StandardDataFormats> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::DataTransfer::TargetApplicationChosenEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
