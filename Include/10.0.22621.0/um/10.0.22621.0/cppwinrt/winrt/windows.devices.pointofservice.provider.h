// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_PointOfService_Provider_H
#define WINRT_Windows_Devices_PointOfService_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.PointOfService.h"
#include "winrt/impl/Windows.Devices.PointOfService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.PointOfService.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::StopAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->StopAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::TryAcquireLatestFrameAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->TryAcquireLatestFrameAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->get_Connection(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->add_FrameArrived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->remove_FrameArrived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReaderFrameArrivedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest<D>::Symbology() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest)->get_Symbology(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest<D>::ReportCompletedAsync(winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes const& attributes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest)->ReportCompletedAsync(*(void**)(&attributes), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::VideoDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_VideoDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<uint32_t>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SupportedSymbologies() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_SupportedSymbologies(&value));
        return winrt::Windows::Foundation::Collections::IVector<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::CompanyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_CompanyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::CompanyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->put_CompanyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Version() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_Version(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Version(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->put_Version(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportScannedDataAsync(winrt::Windows::Devices::PointOfService::BarcodeScannerReport const& report) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportScannedDataAsync(*(void**)(&report), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportTriggerStateAsync(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerTriggerState const& state) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportTriggerStateAsync(static_cast<int32_t>(state), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportErrorAsync(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData const& errorData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportErrorAsync(*(void**)(&errorData), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportErrorAsync(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData const& errorData, bool isRetriable, winrt::Windows::Devices::PointOfService::BarcodeScannerReport const& scanReport) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportErrorAsyncWithScanReport(*(void**)(&errorData), isRetriable, *(void**)(&scanReport), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_EnableScannerRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, EnableScannerRequested_revoker>(this, EnableScannerRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_EnableScannerRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_DisableScannerRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DisableScannerRequested_revoker>(this, DisableScannerRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_DisableScannerRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_SetActiveSymbologiesRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SetActiveSymbologiesRequested_revoker>(this, SetActiveSymbologiesRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_SetActiveSymbologiesRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_StartSoftwareTriggerRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StartSoftwareTriggerRequested_revoker>(this, StartSoftwareTriggerRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_StartSoftwareTriggerRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_StopSoftwareTriggerRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StopSoftwareTriggerRequested_revoker>(this, StopSoftwareTriggerRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_StopSoftwareTriggerRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_GetBarcodeSymbologyAttributesRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GetBarcodeSymbologyAttributesRequested_revoker>(this, GetBarcodeSymbologyAttributesRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_GetBarcodeSymbologyAttributesRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_SetBarcodeSymbologyAttributesRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SetBarcodeSymbologyAttributesRequested_revoker>(this, SetBarcodeSymbologyAttributesRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_SetBarcodeSymbologyAttributesRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_HideVideoPreviewRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, HideVideoPreviewRequested_revoker>(this, HideVideoPreviewRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_HideVideoPreviewRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection2<D>::CreateFrameReaderAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2)->CreateFrameReaderAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection2<D>::CreateFrameReaderAsync(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& preferredFormat) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2)->CreateFrameReaderWithFormatAsync(static_cast<int32_t>(preferredFormat), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection2<D>::CreateFrameReaderAsync(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& preferredFormat, winrt::Windows::Graphics::Imaging::BitmapSize const& preferredSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2)->CreateFrameReaderWithFormatAndSizeAsync(static_cast<int32_t>(preferredFormat), impl::bind_in(preferredSize), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderTriggerDetails<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails)->get_Connection(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest<D>::Symbologies() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest)->get_Symbologies(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::Symbology() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->get_Symbology(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::Attributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->get_Attributes(&value));
        return winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest<D>::ReportCompletedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest)->ReportCompletedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest<D>::ReportFailedAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest)->ReportFailedAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAsync(reason, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, *(void**)(&failedReasonDescription), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequestEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs)->get_Request(&value));
        return winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequestEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapPixelFormat) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::Format() const
    {
        winrt::Windows::Graphics::Imaging::BitmapPixelFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_Format(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::PixelData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_PixelData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitValidationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->get_IsCheckDigitValidationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitValidationSupported(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->put_IsCheckDigitValidationSupported(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitTransmissionSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->get_IsCheckDigitTransmissionSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitTransmissionSupported(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->put_IsCheckDigitTransmissionSupported(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsDecodeLengthSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->get_IsDecodeLengthSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsDecodeLengthSupported(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->put_IsDecodeLengthSupported(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes) consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::CreateAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->CreateAttributes(&value));
        return winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest>
    {
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest>
    {
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader>
    {
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryAcquireLatestFrameAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame>>(this->shim().TryAcquireLatestFrameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FrameArrived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameArrived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs>
    {
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest>
    {
        int32_t __stdcall get_Symbology(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Symbology());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompletedAsync(void* attributes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest>
    {
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedSymbologies(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<uint32_t>>(this->shim().SupportedSymbologies());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportScannedDataAsync(void* report, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportScannedDataAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::BarcodeScannerReport const*>(&report)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportTriggerStateAsync(int32_t state, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportTriggerStateAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerTriggerState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportErrorAsync(void* errorData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportErrorAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData const*>(&errorData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportErrorAsyncWithScanReport(void* errorData, bool isRetriable, void* scanReport, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportErrorAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData const*>(&errorData), isRetriable, *reinterpret_cast<winrt::Windows::Devices::PointOfService::BarcodeScannerReport const*>(&scanReport)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_EnableScannerRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnableScannerRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnableScannerRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableScannerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DisableScannerRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DisableScannerRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DisableScannerRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisableScannerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SetActiveSymbologiesRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SetActiveSymbologiesRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SetActiveSymbologiesRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetActiveSymbologiesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_StartSoftwareTriggerRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StartSoftwareTriggerRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StartSoftwareTriggerRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartSoftwareTriggerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_StopSoftwareTriggerRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StopSoftwareTriggerRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StopSoftwareTriggerRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopSoftwareTriggerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GetBarcodeSymbologyAttributesRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GetBarcodeSymbologyAttributesRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GetBarcodeSymbologyAttributesRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GetBarcodeSymbologyAttributesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SetBarcodeSymbologyAttributesRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SetBarcodeSymbologyAttributesRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SetBarcodeSymbologyAttributesRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBarcodeSymbologyAttributesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_HideVideoPreviewRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().HideVideoPreviewRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HideVideoPreviewRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HideVideoPreviewRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2>
    {
        int32_t __stdcall CreateFrameReaderAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>>(this->shim().CreateFrameReaderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameReaderWithFormatAsync(int32_t preferredFormat, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapPixelFormat const*>(&preferredFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameReaderWithFormatAndSizeAsync(int32_t preferredFormat, struct struct_Windows_Graphics_Imaging_BitmapSize preferredSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapPixelFormat const*>(&preferredFormat), *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapSize const*>(&preferredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails>
    {
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest>
    {
        int32_t __stdcall get_Symbologies(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Symbologies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest>
    {
        int32_t __stdcall get_Symbology(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Symbology());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Attributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest>
    {
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest>
    {
        int32_t __stdcall ReportCompletedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2>
    {
        int32_t __stdcall ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest>(this->shim().Request());
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
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame>
    {
        int32_t __stdcall get_Format(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PixelData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().PixelData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder> : produce_base<D, winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder>
    {
        int32_t __stdcall get_IsCheckDigitValidationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCheckDigitValidationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCheckDigitValidationSupported(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCheckDigitValidationSupported(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCheckDigitTransmissionSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCheckDigitTransmissionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCheckDigitTransmissionSupported(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCheckDigitTransmissionSupported(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDecodeLengthSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDecodeLengthSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDecodeLengthSupported(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDecodeLengthSupported(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>(this->shim().CreateAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService::Provider
{
    inline BarcodeSymbologyAttributesBuilder::BarcodeSymbologyAttributesBuilder() :
        BarcodeSymbologyAttributesBuilder(impl::call_factory_cast<BarcodeSymbologyAttributesBuilder(*)(winrt::Windows::Foundation::IActivationFactory const&), BarcodeSymbologyAttributesBuilder>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BarcodeSymbologyAttributesBuilder>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeSymbologyAttributesBuilder> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
