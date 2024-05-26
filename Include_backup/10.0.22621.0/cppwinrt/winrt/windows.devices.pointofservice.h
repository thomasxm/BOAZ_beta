// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_PointOfService_H
#define WINRT_Windows_Devices_PointOfService_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.PointOfService.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->get_Capabilities(&value));
        return winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner>) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::ClaimScannerAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->ClaimScannerAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->CheckHealthAsync(static_cast<int32_t>(level), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::GetSupportedSymbologiesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->GetSupportedSymbologiesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::IsSymbologySupportedAsync(uint32_t barcodeSymbology) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->IsSymbologySupportedAsync(barcodeSymbology, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->RetrieveStatisticsAsync(*(void**)(&statisticsCategories), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::GetSupportedProfiles() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->GetSupportedProfiles(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::IsProfileSupported(param::hstring const& profile) const
    {
        bool isSupported{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->IsProfileSupported(*(void**)(&profile), &isSupported));
        return isSupported;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::BarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->add_StatusUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::BarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IBarcodeScanner<D>::StatusUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner)->remove_StatusUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IBarcodeScanner2<D>::VideoDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScanner2)->get_VideoDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::PowerReportingType() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_PowerReportingType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::IsStatisticsReportingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_IsStatisticsReportingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::IsStatisticsUpdatingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_IsStatisticsUpdatingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>::IsImagePreviewSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities)->get_IsImagePreviewSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities1<D>::IsSoftwareTriggerSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1)->get_IsSoftwareTriggerSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities2<D>::IsVideoPreviewSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2)->get_IsVideoPreviewSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerReport) consume_Windows_Devices_PointOfService_IBarcodeScannerDataReceivedEventArgs<D>::Report() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs)->get_Report(&value));
        return winrt::Windows::Devices::PointOfService::BarcodeScannerReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerReport) consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>::PartialInputData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs)->get_PartialInputData(&value));
        return winrt::Windows::Devices::PointOfService::BarcodeScannerReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>::IsRetriable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs)->get_IsRetriable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData) consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>::ErrorData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs)->get_ErrorData(&value));
        return winrt::Windows::Devices::PointOfService::UnifiedPosErrorData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType) consume_Windows_Devices_PointOfService_IBarcodeScannerImagePreviewReceivedEventArgs<D>::Preview() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs)->get_Preview(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>::ScanDataType() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerReport)->get_ScanDataType(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>::ScanData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerReport)->get_ScanData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>::ScanDataLabel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerReport)->get_ScanDataLabel(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerReport) consume_Windows_Devices_PointOfService_IBarcodeScannerReportFactory<D>::CreateInstance(uint32_t scanDataType, winrt::Windows::Storage::Streams::IBuffer const& scanData, winrt::Windows::Storage::Streams::IBuffer const& scanDataLabel) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory)->CreateInstance(scanDataType, *(void**)(&scanData), *(void**)(&scanDataLabel), &result));
        return winrt::Windows::Devices::PointOfService::BarcodeScannerReport{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>) consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>) consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IBarcodeScannerStatics2<D>::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2)->GetDeviceSelectorWithConnectionTypes(static_cast<uint32_t>(connectionTypes), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerStatus) consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::PointOfService::BarcodeScannerStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs<D>::ExtendedStatus() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs)->get_ExtendedStatus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Unknown() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Unknown(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean8() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean8Add2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean8Add2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean8Add5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean8Add5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Eanv() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Eanv(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::EanvAdd2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_EanvAdd2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::EanvAdd5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_EanvAdd5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean13() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean13(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean13Add2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean13Add2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean13Add5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean13Add5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Isbn() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Isbn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IsbnAdd5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IsbnAdd5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ismn() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ismn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IsmnAdd2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IsmnAdd2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IsmnAdd5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IsmnAdd5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Issn() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Issn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IssnAdd2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IssnAdd2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::IssnAdd5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_IssnAdd5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean99() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean99(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean99Add2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean99Add2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ean99Add5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ean99Add5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Upca() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Upca(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpcaAdd2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpcaAdd2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpcaAdd5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpcaAdd5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Upce() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Upce(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpceAdd2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpceAdd2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpceAdd5() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpceAdd5(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UpcCoupon() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UpcCoupon(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfStd() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfStd(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfDis() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfDis(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfInt() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfInt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfInd() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfInd(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfMat() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfMat(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::TfIata() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_TfIata(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1DatabarType1() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1DatabarType1(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1DatabarType2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1DatabarType2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1DatabarType3() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1DatabarType3(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code39() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code39(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code39Ex() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code39Ex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Trioptic39() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Trioptic39(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code32() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code32(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Pzn() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Pzn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code93() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code93(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code93Ex() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code93Ex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code128() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code128(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1128() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1128(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Gs1128Coupon() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Gs1128Coupon(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UccEan128() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UccEan128(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Sisac() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Sisac(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Isbt() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Isbt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Codabar() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Codabar(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code11() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code11(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Msi() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Msi(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Plessey() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Plessey(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Telepen() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Telepen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code16k() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code16k(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::CodablockA() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_CodablockA(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::CodablockF() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_CodablockF(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Codablock128() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Codablock128(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Code49() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Code49(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Aztec() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Aztec(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::DataCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_DataCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::DataMatrix() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_DataMatrix(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::HanXin() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_HanXin(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Maxicode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Maxicode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::MicroPdf417() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_MicroPdf417(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::MicroQr() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_MicroQr(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Pdf417() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Pdf417(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Qr() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Qr(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::MsTag() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_MsTag(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ccab() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ccab(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Ccc() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Ccc(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Tlc39() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Tlc39(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::AusPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_AusPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::CanPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_CanPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ChinaPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ChinaPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::DutchKix() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_DutchKix(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::InfoMail() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_InfoMail(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ItalianPost25() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ItalianPost25(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ItalianPost39() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ItalianPost39(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::JapanPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_JapanPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::KoreanPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_KoreanPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::SwedenPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_SwedenPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UkPost() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UkPost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsIntelligent() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsIntelligent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsIntelligentPkg() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsIntelligentPkg(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsPlanet() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsPlanet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::UsPostNet() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_UsPostNet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Us4StateFics() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Us4StateFics(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::OcrA() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_OcrA(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::OcrB() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_OcrB(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::Micr() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_Micr(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::ExtendedBase() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->get_ExtendedBase(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>::GetName(uint32_t scanDataType) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics)->GetName(scanDataType, &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics2<D>::Gs1DWCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2)->get_Gs1DWCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitValidationEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitValidationEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitValidationEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_IsCheckDigitValidationEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitValidationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitValidationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitTransmissionEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitTransmissionEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitTransmissionEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_IsCheckDigitTransmissionEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsCheckDigitTransmissionSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsCheckDigitTransmissionSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength1() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_DecodeLength1(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength1(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_DecodeLength1(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength2() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_DecodeLength2(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLength2(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_DecodeLength2(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLengthKind() const
    {
        winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_DecodeLengthKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::DecodeLengthKind(winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->put_DecodeLengthKind(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>::IsDecodeLengthSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes)->get_IsDecodeLengthSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ICashDrawer<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerCapabilities) consume_Windows_Devices_PointOfService_ICashDrawer<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->get_Capabilities(&value));
        return winrt::Windows::Devices::PointOfService::CashDrawerCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerStatus) consume_Windows_Devices_PointOfService_ICashDrawer<D>::Status() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->get_Status(&value));
        return winrt::Windows::Devices::PointOfService::CashDrawerStatus{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICashDrawer<D>::IsDrawerOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->get_IsDrawerOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerEventSource) consume_Windows_Devices_PointOfService_ICashDrawer<D>::DrawerEventSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->get_DrawerEventSource(&value));
        return winrt::Windows::Devices::PointOfService::CashDrawerEventSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer>) consume_Windows_Devices_PointOfService_ICashDrawer<D>::ClaimDrawerAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->ClaimDrawerAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_ICashDrawer<D>::CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->CheckHealthAsync(static_cast<int32_t>(level), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_ICashDrawer<D>::GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->GetStatisticsAsync(*(void**)(&statisticsCategories), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawer, winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->add_StatusUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawer, winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawer<D>::StatusUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawer)->remove_StatusUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::PowerReportingType() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_PowerReportingType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatisticsReportingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatisticsReportingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatisticsUpdatingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatisticsUpdatingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatusReportingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatusReportingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsStatusMultiDrawerDetectSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsStatusMultiDrawerDetectSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>::IsDrawerOpenSensorAvailable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities)->get_IsDrawerOpenSensorAvailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_AlarmTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_AlarmTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepFrequency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_BeepFrequency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepFrequency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_BeepFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDuration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_BeepDuration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_BeepDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDelay(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->put_BeepDelay(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::BeepDelay() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->get_BeepDelay(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->add_AlarmTimeoutExpired(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired_revoker consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AlarmTimeoutExpired_revoker>(this, AlarmTimeoutExpired(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::AlarmTimeoutExpired(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->remove_AlarmTimeoutExpired(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>::StartAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm)->StartAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerEventSource)->add_DrawerClosed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed_revoker consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DrawerClosed_revoker>(this, DrawerClosed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerClosed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerEventSource)->remove_DrawerClosed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerEventSource)->add_DrawerOpened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened_revoker consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DrawerOpened_revoker>(this, DrawerOpened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>::DrawerOpened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerEventSource)->remove_DrawerOpened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawer) consume_Windows_Devices_PointOfService_ICashDrawerEventSourceEventArgs<D>::CashDrawer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs)->get_CashDrawer(&value));
        return winrt::Windows::Devices::PointOfService::CashDrawer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>) consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>) consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ICashDrawerStatics2<D>::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatics2)->GetDeviceSelectorWithConnectionTypes(static_cast<uint32_t>(connectionTypes), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerStatusKind) consume_Windows_Devices_PointOfService_ICashDrawerStatus<D>::StatusKind() const
    {
        winrt::Windows::Devices::PointOfService::CashDrawerStatusKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatus)->get_StatusKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ICashDrawerStatus<D>::ExtendedStatus() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatus)->get_ExtendedStatus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerStatus) consume_Windows_Devices_PointOfService_ICashDrawerStatusUpdatedEventArgs<D>::Status() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs)->get_Status(&value));
        return winrt::Windows::Devices::PointOfService::CashDrawerStatus{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDisabledOnDataReceived(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->put_IsDisabledOnDataReceived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDisabledOnDataReceived() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_IsDisabledOnDataReceived(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDecodeDataEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->put_IsDecodeDataEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::IsDecodeDataEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->get_IsDecodeDataEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::EnableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->EnableAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DisableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->DisableAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::RetainDevice() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->RetainDevice());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::SetActiveSymbologiesAsync(param::async_iterable<uint32_t> const& symbologies) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->SetActiveSymbologiesAsync(*(void**)(&symbologies), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->ResetStatisticsAsync(*(void**)(&statisticsCategories), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->UpdateStatisticsAsync(*(void**)(&statistics), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::SetActiveProfileAsync(param::hstring const& profile) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->SetActiveProfileAsync(*(void**)(&profile), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_DataReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DataReceived_revoker>(this, DataReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::DataReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_DataReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_TriggerPressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
    {
        return impl::make_event_revoker<D, TriggerPressed_revoker>(this, TriggerPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerPressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_TriggerPressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_TriggerReleased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
    {
        return impl::make_event_revoker<D, TriggerReleased_revoker>(this, TriggerReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::TriggerReleased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_TriggerReleased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_ReleaseDeviceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const
    {
        return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_ReleaseDeviceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_ImagePreviewReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ImagePreviewReceived_revoker>(this, ImagePreviewReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ImagePreviewReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_ImagePreviewReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->add_ErrorOccurred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner)->remove_ErrorOccurred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1<D>::StartSoftwareTriggerAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1)->StartSoftwareTriggerAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1<D>::StopSoftwareTriggerAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1)->StopSoftwareTriggerAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2<D>::GetSymbologyAttributesAsync(uint32_t barcodeSymbology) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2)->GetSymbologyAttributesAsync(barcodeSymbology, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2<D>::SetSymbologyAttributesAsync(uint32_t barcodeSymbology, winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes const& attributes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2)->SetSymbologyAttributesAsync(barcodeSymbology, *(void**)(&attributes), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::ShowVideoPreviewAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->ShowVideoPreviewAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::HideVideoPreview() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->HideVideoPreview());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::IsVideoPreviewShownOnEnable(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->put_IsVideoPreviewShownOnEnable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>::IsVideoPreviewShownOnEnable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3)->get_IsVideoPreviewShownOnEnable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::IsDrawerOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->get_IsDrawerOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::CloseAlarm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->get_CloseAlarm(&value));
        return winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::OpenDrawerAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->OpenDrawerAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::EnableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->EnableAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::DisableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->DisableAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::RetainDeviceAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->RetainDeviceAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->ResetStatisticsAsync(*(void**)(&statisticsCategories), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->UpdateStatisticsAsync(*(void**)(&statistics), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->add_ReleaseDeviceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer)->remove_ReleaseDeviceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::JournalPrintJob) consume_Windows_Devices_PointOfService_IClaimedJournalPrinter<D>::CreateJob() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter)->CreateJob(&value));
        return winrt::Windows::Devices::PointOfService::JournalPrintJob{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCapabilities) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_Capabilities(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::PhysicalDeviceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_PhysicalDeviceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::PhysicalDeviceDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_PhysicalDeviceDescription(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceControlDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceControlDescription(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceControlVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceControlVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DeviceServiceVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DeviceServiceVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayWindow) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::DefaultWindow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->get_DefaultWindow(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayWindow{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::RetainDevice() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->RetainDevice());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->add_ReleaseDeviceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay)->remove_ReleaseDeviceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->GetStatisticsAsync(*(void**)(&statisticsCategories), &result));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->CheckHealthAsync(static_cast<int32_t>(level), &result));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::CheckPowerStatusAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->CheckPowerStatusAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->add_StatusUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::StatusUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->remove_StatusUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Size>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::SupportedScreenSizesInCharacters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_SupportedScreenSizesInCharacters(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Size>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::MaxBitmapSizeInPixels() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_MaxBitmapSizeInPixels(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<int32_t>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::SupportedCharacterSets() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_SupportedCharacterSets(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::CustomGlyphs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->get_CustomGlyphs(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayAttributes) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::GetAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->GetAttributes(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayAttributes{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryUpdateAttributesAsync(winrt::Windows::Devices::PointOfService::LineDisplayAttributes const& attributes) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryUpdateAttributesAsync(*(void**)(&attributes), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TrySetDescriptorAsync(uint32_t descriptor, winrt::Windows::Devices::PointOfService::LineDisplayDescriptorState const& descriptorState) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TrySetDescriptorAsync(descriptor, static_cast<int32_t>(descriptorState), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryClearDescriptorsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryClearDescriptorsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayWindow>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryCreateWindowAsync(winrt::Windows::Foundation::Rect const& viewport, winrt::Windows::Foundation::Size const& windowSize) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryCreateWindowAsync(impl::bind_in(viewport), impl::bind_in(windowSize), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayWindow>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryStoreStorageFileBitmapAsync(winrt::Windows::Storage::StorageFile const& bitmap) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryStoreStorageFileBitmapAsync(*(void**)(&bitmap), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryStoreStorageFileBitmapAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryStoreStorageFileBitmapWithAlignmentAsync(*(void**)(&bitmap), static_cast<int32_t>(horizontalAlignment), static_cast<int32_t>(verticalAlignment), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>) consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>::TryStoreStorageFileBitmapAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2)->TryStoreStorageFileBitmapWithAlignmentAndWidthAsync(*(void**)(&bitmap), static_cast<int32_t>(horizontalAlignment), static_cast<int32_t>(verticalAlignment), widthInPixels, &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>) consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics)->GetDeviceSelectorWithConnectionTypes(static_cast<uint32_t>(connectionTypes), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDisabledOnDataReceived(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_IsDisabledOnDataReceived(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDisabledOnDataReceived() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsDisabledOnDataReceived(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDecodeDataEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_IsDecodeDataEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDecodeDataEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsDecodeDataEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsDeviceAuthenticated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsDeviceAuthenticated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DataEncryptionAlgorithm(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_DataEncryptionAlgorithm(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DataEncryptionAlgorithm() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_DataEncryptionAlgorithm(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::TracksToRead(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_TracksToRead(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::TracksToRead() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_TracksToRead(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsTransmitSentinelsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->put_IsTransmitSentinelsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::IsTransmitSentinelsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->get_IsTransmitSentinelsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::EnableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->EnableAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DisableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->DisableAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::RetainDevice() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->RetainDevice());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::SetErrorReportingType(winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->SetErrorReportingType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::RetrieveDeviceAuthenticationDataAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->RetrieveDeviceAuthenticationDataAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->AuthenticateDeviceAsync(responseToken.size(), get_abi(responseToken), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::DeAuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->DeAuthenticateDeviceAsync(responseToken.size(), get_abi(responseToken), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::UpdateKeyAsync(param::hstring const& key, param::hstring const& keyName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->UpdateKeyAsync(*(void**)(&key), *(void**)(&keyName), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->ResetStatisticsAsync(*(void**)(&statisticsCategories), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->UpdateStatisticsAsync(*(void**)(&statistics), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_BankCardDataReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BankCardDataReceived_revoker>(this, BankCardDataReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::BankCardDataReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_BankCardDataReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_AamvaCardDataReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AamvaCardDataReceived_revoker>(this, AamvaCardDataReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::AamvaCardDataReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_AamvaCardDataReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_VendorSpecificDataReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, VendorSpecificDataReceived_revoker>(this, VendorSpecificDataReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::VendorSpecificDataReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_VendorSpecificDataReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_ReleaseDeviceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const
    {
        return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_ReleaseDeviceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->add_ErrorOccurred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader)->remove_ErrorOccurred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::CharacterSet(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->put_CharacterSet(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::CharacterSet() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_CharacterSet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsCoverOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_IsCoverOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsCharacterSetMappingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->put_IsCharacterSetMappingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::IsCharacterSetMappingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_IsCharacterSetMappingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::MapMode(winrt::Windows::Devices::PointOfService::PosPrinterMapMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->put_MapMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterMapMode) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::MapMode() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterMapMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_MapMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::Receipt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_Receipt(&value));
        return winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::Slip() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_Slip(&value));
        return winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::Journal() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->get_Journal(&value));
        return winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::EnableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->EnableAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::DisableAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->DisableAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::RetainDeviceAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->RetainDeviceAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->ResetStatisticsAsync(*(void**)(&statisticsCategories), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->UpdateStatisticsAsync(*(void**)(&statistics), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->add_ReleaseDeviceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested_revoker consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReleaseDeviceRequested_revoker>(this, ReleaseDeviceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>::ReleaseDeviceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter)->remove_ReleaseDeviceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed_revoker consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::SidewaysMaxLines() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_SidewaysMaxLines(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::SidewaysMaxChars() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_SidewaysMaxChars(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::LinesToPaperCut() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_LinesToPaperCut(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::PageSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_PageSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::PrintArea() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter)->get_PrintArea(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ReceiptPrintJob) consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>::CreateJob() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter)->CreateJob(&value));
        return winrt::Windows::Devices::PointOfService::ReceiptPrintJob{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::SidewaysMaxLines() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_SidewaysMaxLines(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::SidewaysMaxChars() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_SidewaysMaxChars(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::MaxLines() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_MaxLines(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::LinesNearEndToEnd() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_LinesNearEndToEnd(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterPrintSide) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::PrintSide() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterPrintSide value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_PrintSide(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::PageSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_PageSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::PrintArea() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->get_PrintArea(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::OpenJaws() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->OpenJaws());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::CloseJaws() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->CloseJaws());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::InsertSlipAsync(winrt::Windows::Foundation::TimeSpan const& timeout) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->InsertSlipAsync(impl::bind_in(timeout), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::RemoveSlipAsync(winrt::Windows::Foundation::TimeSpan const& timeout) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->RemoveSlipAsync(impl::bind_in(timeout), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::ChangePrintSide(winrt::Windows::Devices::PointOfService::PosPrinterPrintSide const& printSide) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->ChangePrintSide(static_cast<int32_t>(printSide)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::SlipPrintJob) consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>::CreateJob() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter)->CreateJob(&value));
        return winrt::Windows::Devices::PointOfService::SlipPrintJob{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::CharactersPerLine(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_CharactersPerLine(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::CharactersPerLine() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_CharactersPerLine(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineHeight(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_LineHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_LineHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineSpacing(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_LineSpacing(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineSpacing() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_LineSpacing(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::LineWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_LineWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsLetterQuality(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_IsLetterQuality(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsLetterQuality() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsLetterQuality(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsPaperNearEnd() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsPaperNearEnd(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::ColorCartridge(winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->put_ColorCartridge(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::ColorCartridge() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_ColorCartridge(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsCoverOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsCoverOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsCartridgeRemoved() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsCartridgeRemoved(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsCartridgeEmpty() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsCartridgeEmpty(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsHeadCleaning() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsHeadCleaning(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsPaperEmpty() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsPaperEmpty(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::IsReadyToPrint() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->get_IsReadyToPrint(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>::ValidateData(param::hstring const& data) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation)->ValidateData(*(void**)(&data), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsPrinterPresent() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsPrinterPresent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDualColorSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDualColorSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterColorCapabilities) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::ColorCartridgeCapabilities() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterColorCapabilities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_ColorCartridgeCapabilities(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterCartridgeSensors) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::CartridgeSensors() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterCartridgeSensors value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_CartridgeSensors(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsBoldSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsBoldSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsItalicSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsItalicSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsUnderlineSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsUnderlineSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDoubleHighPrintSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDoubleHighPrintSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDoubleWidePrintSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDoubleWidePrintSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsDoubleHighDoubleWidePrintSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsDoubleHighDoubleWidePrintSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsPaperEmptySensorSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsPaperEmptySensorSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::IsPaperNearEndSensorSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_IsPaperNearEndSensorSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>::SupportedCharactersPerLine() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities)->get_SupportedCharactersPerLine(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsBarcodeSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsBarcodeSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsBitmapSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsBitmapSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsLeft90RotationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsLeft90RotationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsRight90RotationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsRight90RotationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::Is180RotationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_Is180RotationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::IsPrintAreaSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_IsPrintAreaSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::RuledLineCapabilities() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_RuledLineCapabilities(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::SupportedBarcodeRotations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_SupportedBarcodeRotations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>) consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>::SupportedBitmapRotations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities)->get_SupportedBitmapRotations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IJournalPrintJob<D>::Print(param::hstring const& data, winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrintJob)->Print(*(void**)(&data), *(void**)(&printOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IJournalPrintJob<D>::FeedPaperByLine(int32_t lineCount) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrintJob)->FeedPaperByLine(lineCount));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IJournalPrintJob<D>::FeedPaperByMapModeUnit(int32_t distance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrintJob)->FeedPaperByMapModeUnit(distance));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsReverseVideoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsReverseVideoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsStrikethroughSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsStrikethroughSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsSuperscriptSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsSuperscriptSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsSubscriptSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsSubscriptSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsReversePaperFeedByLineSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsReversePaperFeedByLineSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>::IsReversePaperFeedByMapModeUnitSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2)->get_IsReversePaperFeedByMapModeUnitSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCapabilities) consume_Windows_Devices_PointOfService_ILineDisplay<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_Capabilities(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplay<D>::PhysicalDeviceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_PhysicalDeviceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplay<D>::PhysicalDeviceDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_PhysicalDeviceDescription(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceControlDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_DeviceControlDescription(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceControlVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_DeviceControlVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplay<D>::DeviceServiceVersion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->get_DeviceServiceVersion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>) consume_Windows_Devices_PointOfService_ILineDisplay<D>::ClaimAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay)->ClaimAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>) consume_Windows_Devices_PointOfService_ILineDisplay2<D>::CheckPowerStatusAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplay2)->CheckPowerStatusAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsPowerNotifyEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_IsPowerNotifyEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsPowerNotifyEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_IsPowerNotifyEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::Brightness() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_Brightness(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::Brightness(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_Brightness(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::BlinkRate() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_BlinkRate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::BlinkRate(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_BlinkRate(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::ScreenSizeInCharacters() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_ScreenSizeInCharacters(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::ScreenSizeInCharacters(winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_ScreenSizeInCharacters(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CharacterSet() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_CharacterSet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CharacterSet(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_CharacterSet(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsCharacterSetMappingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_IsCharacterSetMappingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::IsCharacterSetMappingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_IsCharacterSetMappingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayWindow) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CurrentWindow() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->get_CurrentWindow(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayWindow{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>::CurrentWindow(winrt::Windows::Devices::PointOfService::LineDisplayWindow const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayAttributes)->put_CurrentWindow(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsStatisticsReportingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsStatisticsReportingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsStatisticsUpdatingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsStatisticsUpdatingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::PowerReportingType() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_PowerReportingType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanChangeScreenSize() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanChangeScreenSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanDisplayBitmaps() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanDisplayBitmaps(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanReadCharacterAtCursor() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanReadCharacterAtCursor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanMapCharacterSets() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanMapCharacterSets(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanDisplayCustomGlyphs() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanDisplayCustomGlyphs(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanReverse() const
    {
        winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanReverse(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanBlink() const
    {
        winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanBlink(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::CanChangeBlinkRate() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_CanChangeBlinkRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsBrightnessSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsBrightnessSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsCursorSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsCursorSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsHorizontalMarqueeSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsHorizontalMarqueeSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsVerticalMarqueeSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsVerticalMarqueeSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::IsInterCharacterWaitSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_IsInterCharacterWaitSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::SupportedDescriptors() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_SupportedDescriptors(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>::SupportedWindows() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities)->get_SupportedWindows(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::CanCustomize() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_CanCustomize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsBlinkSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsBlinkSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsBlockSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsBlockSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsHalfBlockSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsHalfBlockSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsUnderlineSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsUnderlineSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsReverseSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsReverseSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::IsOtherSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->get_IsOtherSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::GetAttributes() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->GetAttributes(&result));
        return winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>::TryUpdateAttributesAsync(winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes const& attributes) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursor)->TryUpdateAttributesAsync(*(void**)(&attributes), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsBlinkEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_IsBlinkEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsBlinkEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_IsBlinkEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCursorType) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::CursorType() const
    {
        winrt::Windows::Devices::PointOfService::LineDisplayCursorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_CursorType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::CursorType(winrt::Windows::Devices::PointOfService::LineDisplayCursorType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_CursorType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsAutoAdvanceEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_IsAutoAdvanceEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::IsAutoAdvanceEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_IsAutoAdvanceEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>::Position(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>::SizeInPixels() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs)->get_SizeInPixels(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>::SupportedGlyphCodes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs)->get_SupportedGlyphCodes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>::TryRedefineAsync(uint32_t glyphCode, winrt::Windows::Storage::Streams::IBuffer const& glyphData) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs)->TryRedefineAsync(glyphCode, *(void**)(&glyphData), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::Format() const
    {
        winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->get_Format(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::Format(winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->put_Format(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::RepeatWaitInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->get_RepeatWaitInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::RepeatWaitInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->put_RepeatWaitInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::ScrollWaitInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->get_ScrollWaitInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::ScrollWaitInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->put_ScrollWaitInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::TryStartScrollingAsync(winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->TryStartScrollingAsync(static_cast<int32_t>(direction), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>::TryStopScrollingAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayMarquee)->TryStopScrollingAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>) consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>) consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatics)->GetDeviceSelectorWithConnectionTypes(static_cast<uint32_t>(connectionTypes), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector) consume_Windows_Devices_PointOfService_ILineDisplayStatics2<D>::StatisticsCategorySelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatics2)->get_StatisticsCategorySelector(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>::AllStatistics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector)->get_AllStatistics(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>::UnifiedPosStatistics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector)->get_UnifiedPosStatistics(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>::ManufacturerStatistics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector)->get_ManufacturerStatistics(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus) consume_Windows_Devices_PointOfService_ILineDisplayStatusUpdatedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap<D>::EscapeSequence() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap)->get_EscapeSequence(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap<D>::TryDeleteAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap)->TryDeleteAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::SizeInCharacters() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->get_SizeInCharacters(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::InterCharacterWaitInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->get_InterCharacterWaitInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::InterCharacterWaitInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->put_InterCharacterWaitInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryRefreshAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->TryRefreshAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryDisplayTextAsync(param::hstring const& text, winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->TryDisplayTextAsync(*(void**)(&text), static_cast<int32_t>(displayAttribute), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryDisplayTextAsync(param::hstring const& text, winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute, winrt::Windows::Foundation::Point const& startPosition) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->TryDisplayTextAtPositionAsync(*(void**)(&text), static_cast<int32_t>(displayAttribute), impl::bind_in(startPosition), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryDisplayTextAsync(param::hstring const& text) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->TryDisplayTextNormalAsync(*(void**)(&text), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryScrollTextAsync(winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction, uint32_t numberOfColumnsOrRows) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->TryScrollTextAsync(static_cast<int32_t>(direction), numberOfColumnsOrRows, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>::TryClearTextAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow)->TryClearTextAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCursor) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::Cursor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->get_Cursor(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayCursor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayMarquee) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::Marquee() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->get_Marquee(&value));
        return winrt::Windows::Devices::PointOfService::LineDisplayMarquee{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<uint32_t>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::ReadCharacterAtCursorAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->ReadCharacterAtCursorAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<uint32_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStoredBitmapAtCursorAsync(winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap const& bitmap) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStoredBitmapAtCursorAsync(*(void**)(&bitmap), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtCursorAsync(winrt::Windows::Storage::StorageFile const& bitmap) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtCursorAsync(*(void**)(&bitmap), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtCursorAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtCursorWithAlignmentAsync(*(void**)(&bitmap), static_cast<int32_t>(horizontalAlignment), static_cast<int32_t>(verticalAlignment), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtCursorAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtCursorWithAlignmentAndWidthAsync(*(void**)(&bitmap), static_cast<int32_t>(horizontalAlignment), static_cast<int32_t>(verticalAlignment), widthInPixels, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtPointAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Foundation::Point const& offsetInPixels) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtPointAsync(*(void**)(&bitmap), impl::bind_in(offsetInPixels), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>::TryDisplayStorageFileBitmapAtPointAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Foundation::Point const& offsetInPixels, int32_t widthInPixels) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ILineDisplayWindow2)->TryDisplayStorageFileBitmapAtPointWithWidthAsync(*(void**)(&bitmap), impl::bind_in(offsetInPixels), widthInPixels, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->get_Capabilities(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint32_t>) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::SupportedCardTypes() const
    {
        uint32_t value_impl_size{};
        uint32_t* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->get_SupportedCardTypes(&value_impl_size, &value));
        return com_array<uint32_t>{ value, value_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::DeviceAuthenticationProtocol() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->get_DeviceAuthenticationProtocol(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->CheckHealthAsync(static_cast<int32_t>(level), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader>) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::ClaimReaderAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->ClaimReaderAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->RetrieveStatisticsAsync(*(void**)(&statisticsCategories), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::GetErrorReportingType() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->GetErrorReportingType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::MagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->add_StatusUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::MagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>::StatusUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReader)->remove_StatusUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Report() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Report(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::LicenseNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_LicenseNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::ExpirationDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_ExpirationDate(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Restrictions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Restrictions(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Class() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Class(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Endorsements() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Endorsements(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::BirthDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_BirthDate(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::FirstName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_FirstName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Surname() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Surname(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Suffix() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Suffix(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Gender() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Gender(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::HairColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_HairColor(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::EyeColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_EyeColor(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Height() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Height(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Weight() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Weight(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::Address() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_Address(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::City() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_City(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::State() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_State(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>::PostalCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs)->get_PostalCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Report() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Report(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::AccountNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_AccountNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::ExpirationDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_ExpirationDate(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::ServiceCode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_ServiceCode(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::FirstName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_FirstName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::MiddleInitial() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_MiddleInitial(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Surname() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Surname(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>::Suffix() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs)->get_Suffix(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::CardAuthentication() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_CardAuthentication(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::SupportedEncryptionAlgorithms() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_SupportedEncryptionAlgorithms(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::AuthenticationLevel() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_AuthenticationLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsIsoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsIsoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsJisOneSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsJisOneSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsJisTwoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsJisTwoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::PowerReportingType() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_PowerReportingType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsStatisticsReportingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsStatisticsReportingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsStatisticsUpdatingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsStatisticsUpdatingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsTrackDataMaskingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsTrackDataMaskingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>::IsTransmitSentinelsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities)->get_IsTransmitSentinelsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::Unknown() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_Unknown(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::Bank() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_Bank(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::Aamva() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_Aamva(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>::ExtendedBase() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics)->get_ExtendedBase(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>::None() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics)->get_None(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>::TripleDesDukpt() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics)->get_TripleDesDukpt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>::ExtendedBase() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics)->get_ExtendedBase(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track1Status() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track1Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track2Status() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track2Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track3Status() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track3Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::Track4Status() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_Track4Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData) consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::ErrorData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_ErrorData(&value));
        return winrt::Windows::Devices::PointOfService::UnifiedPosErrorData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>::PartialInputData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs)->get_PartialInputData(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::CardType() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_CardType(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track1(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track2(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track3(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Track4() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Track4(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::CardAuthenticationData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_CardAuthenticationData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::CardAuthenticationDataLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_CardAuthenticationDataLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>::AdditionalSecurityInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport)->get_AdditionalSecurityInformation(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>) consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>) consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics2<D>::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2)->GetDeviceSelectorWithConnectionTypes(static_cast<uint32_t>(connectionTypes), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatus) consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs<D>::ExtendedStatus() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs)->get_ExtendedStatus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>::DiscretionaryData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData)->get_DiscretionaryData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>::EncryptedData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData)->get_EncryptedData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) consume_Windows_Devices_PointOfService_IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs<D>::Report() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs)->get_Report(&value));
        return winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IPosPrinter<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterCapabilities) consume_Windows_Devices_PointOfService_IPosPrinter<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->get_Capabilities(&value));
        return winrt::Windows::Devices::PointOfService::PosPrinterCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_Devices_PointOfService_IPosPrinter<D>::SupportedCharacterSets() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->get_SupportedCharacterSets(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Devices_PointOfService_IPosPrinter<D>::SupportedTypeFaces() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->get_SupportedTypeFaces(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterStatus) consume_Windows_Devices_PointOfService_IPosPrinter<D>::Status() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->get_Status(&value));
        return winrt::Windows::Devices::PointOfService::PosPrinterStatus{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter>) consume_Windows_Devices_PointOfService_IPosPrinter<D>::ClaimPrinterAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->ClaimPrinterAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_IPosPrinter<D>::CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->CheckHealthAsync(static_cast<int32_t>(level), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) consume_Windows_Devices_PointOfService_IPosPrinter<D>::GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->GetStatisticsAsync(*(void**)(&statisticsCategories), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<hstring>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::PosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->add_StatusUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated_revoker consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::PosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusUpdated_revoker>(this, StatusUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinter<D>::StatusUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter)->remove_StatusUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_Devices_PointOfService_IPosPrinter2<D>::SupportedBarcodeSymbologies() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter2)->get_SupportedBarcodeSymbologies(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterFontProperty) consume_Windows_Devices_PointOfService_IPosPrinter2<D>::GetFontProperty(param::hstring const& typeface) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinter2)->GetFontProperty(*(void**)(&typeface), &result));
        return winrt::Windows::Devices::PointOfService::PosPrinterFontProperty{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::PowerReportingType() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_PowerReportingType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::IsStatisticsReportingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_IsStatisticsReportingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::IsStatisticsUpdatingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_IsStatisticsUpdatingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::DefaultCharacterSet() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_DefaultCharacterSet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::HasCoverSensor() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_HasCoverSensor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::CanMapCharacterSet() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_CanMapCharacterSet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::IsTransactionSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_IsTransactionSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::Receipt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_Receipt(&value));
        return winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::Slip() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_Slip(&value));
        return winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities) consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>::Journal() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities)->get_Journal(&value));
        return winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>::Utf16LE() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics)->get_Utf16LE(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>::Ascii() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics)->get_Ascii(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>::Ansi() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics)->get_Ansi(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>::TypeFace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty)->get_TypeFace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>::IsScalableToAnySize() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty)->get_IsScalableToAnySize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::SizeUInt32>) consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>::CharacterSizes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty)->get_CharacterSizes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::SizeUInt32>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::Print(param::hstring const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterJob)->Print(*(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::PrintLine(param::hstring const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterJob)->PrintLine(*(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::PrintLine() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterJob)->PrintNewline());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Devices_PointOfService_IPosPrinterJob<D>::ExecuteAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterJob)->ExecuteAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::TypeFace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_TypeFace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::TypeFace(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_TypeFace(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_CharacterHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterHeight(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_CharacterHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Bold() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Bold(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Bold(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Bold(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Italic() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Italic(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Italic(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Italic(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Underline() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Underline(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Underline(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Underline(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::ReverseVideo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_ReverseVideo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::ReverseVideo(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_ReverseVideo(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Strikethrough() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Strikethrough(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Strikethrough(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Strikethrough(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Superscript() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Superscript(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Superscript(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Superscript(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Subscript() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Subscript(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Subscript(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Subscript(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleWide() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_DoubleWide(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleWide(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_DoubleWide(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleHigh() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_DoubleHigh(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::DoubleHigh(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_DoubleHigh(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterAlignment) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Alignment() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_Alignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::Alignment(winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_Alignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterSet() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->get_CharacterSet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>::CharacterSet(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions)->put_CharacterSet(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>) consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>) consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IPosPrinterStatics2<D>::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatics2)->GetDeviceSelectorWithConnectionTypes(static_cast<uint32_t>(connectionTypes), &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterStatusKind) consume_Windows_Devices_PointOfService_IPosPrinterStatus<D>::StatusKind() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterStatusKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatus)->get_StatusKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IPosPrinterStatus<D>::ExtendedStatus() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatus)->get_ExtendedStatus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterStatus) consume_Windows_Devices_PointOfService_IPosPrinterStatusUpdatedEventArgs<D>::Status() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs)->get_Status(&value));
        return winrt::Windows::Devices::PointOfService::PosPrinterStatus{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetBarcodeRotation(winrt::Windows::Devices::PointOfService::PosPrinterRotation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBarcodeRotation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetPrintRotation(winrt::Windows::Devices::PointOfService::PosPrinterRotation const& value, bool includeBitmaps) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetPrintRotation(static_cast<int32_t>(value), includeBitmaps));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetPrintArea(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetPrintArea(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBitmap(bitmapNumber, *(void**)(&bitmap), static_cast<int32_t>(alignment)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBitmapCustomWidthStandardAlign(bitmapNumber, *(void**)(&bitmap), static_cast<int32_t>(alignment), width));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetCustomAlignedBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetCustomAlignedBitmap(bitmapNumber, *(void**)(&bitmap), alignmentDistance));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::SetCustomAlignedBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->SetBitmapCustomWidthCustomAlign(bitmapNumber, *(void**)(&bitmap), alignmentDistance, width));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintSavedBitmap(uint32_t bitmapNumber) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintSavedBitmap(bitmapNumber));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::DrawRuledLine(param::hstring const& positionList, winrt::Windows::Devices::PointOfService::PosPrinterLineDirection const& lineDirection, uint32_t lineWidth, winrt::Windows::Devices::PointOfService::PosPrinterLineStyle const& lineStyle, uint32_t lineColor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->DrawRuledLine(*(void**)(&positionList), static_cast<int32_t>(lineDirection), lineWidth, static_cast<int32_t>(lineStyle), lineColor));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBarcode(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBarcode(*(void**)(&data), symbology, height, width, static_cast<int32_t>(textPosition), static_cast<int32_t>(alignment)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBarcodeCustomAlign(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, uint32_t alignmentDistance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBarcodeCustomAlign(*(void**)(&data), symbology, height, width, static_cast<int32_t>(textPosition), alignmentDistance));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBitmap(*(void**)(&bitmap), static_cast<int32_t>(alignment)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBitmapCustomWidthStandardAlign(*(void**)(&bitmap), static_cast<int32_t>(alignment), width));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintCustomAlignedBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintCustomAlignedBitmap(*(void**)(&bitmap), alignmentDistance));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>::PrintCustomAlignedBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob)->PrintBitmapCustomWidthCustomAlign(*(void**)(&bitmap), alignmentDistance, width));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>::MarkFeed(winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedKind const& kind) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob)->MarkFeed(static_cast<int32_t>(kind)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>::CutPaper(double percentage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob)->CutPaper(percentage));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>::CutPaper() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob)->CutPaperDefault());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::StampPaper() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob2)->StampPaper());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::Print(param::hstring const& data, winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob2)->Print(*(void**)(&data), *(void**)(&printOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::FeedPaperByLine(int32_t lineCount) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob2)->FeedPaperByLine(lineCount));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>::FeedPaperByMapModeUnit(int32_t distance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrintJob2)->FeedPaperByMapModeUnit(distance));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>::CanCutPaper() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities)->get_CanCutPaper(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>::IsStampSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities)->get_IsStampSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>::MarkFeedCapabilities() const
    {
        winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities)->get_MarkFeedCapabilities(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsReverseVideoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsReverseVideoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsStrikethroughSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsStrikethroughSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsSuperscriptSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsSuperscriptSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsSubscriptSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsSubscriptSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsReversePaperFeedByLineSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsReversePaperFeedByLineSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>::IsReversePaperFeedByMapModeUnitSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2)->get_IsReversePaperFeedByMapModeUnitSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ISlipPrintJob<D>::Print(param::hstring const& data, winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrintJob)->Print(*(void**)(&data), *(void**)(&printOptions)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ISlipPrintJob<D>::FeedPaperByLine(int32_t lineCount) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrintJob)->FeedPaperByLine(lineCount));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_PointOfService_ISlipPrintJob<D>::FeedPaperByMapModeUnit(int32_t distance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrintJob)->FeedPaperByMapModeUnit(distance));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities<D>::IsFullLengthSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities)->get_IsFullLengthSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities<D>::IsBothSidesPrintingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities)->get_IsBothSidesPrintingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsReverseVideoSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsReverseVideoSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsStrikethroughSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsStrikethroughSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsSuperscriptSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsSuperscriptSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsSubscriptSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsSubscriptSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsReversePaperFeedByLineSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsReversePaperFeedByLineSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>::IsReversePaperFeedByMapModeUnitSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2)->get_IsReversePaperFeedByMapModeUnitSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity) consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::Severity() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_Severity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason) consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::Reason() const
    {
        winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>::ExtendedReason() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData)->get_ExtendedReason(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData) consume_Windows_Devices_PointOfService_IUnifiedPosErrorDataFactory<D>::CreateInstance(param::hstring const& message, winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity const& severity, winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason const& reason, uint32_t extendedReason) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory)->CreateInstance(*(void**)(&message), static_cast<int32_t>(severity), static_cast<int32_t>(reason), extendedReason, &result));
        return winrt::Windows::Devices::PointOfService::UnifiedPosErrorData{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScanner> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScanner>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClaimScannerAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner>>(this->shim().ClaimScannerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckHealthAsync(int32_t level, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedSymbologiesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>>(this->shim().GetSupportedSymbologiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSymbologySupportedAsync(uint32_t barcodeSymbology, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSymbologySupportedAsync(barcodeSymbology));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrieveStatisticsAsync(void* statisticsCategories, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().RetrieveStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedProfiles(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetSupportedProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsProfileSupported(void* profile, bool* isSupported) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isSupported = detach_from<bool>(this->shim().IsProfileSupported(*reinterpret_cast<hstring const*>(&profile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::BarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScanner2> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScanner2>
    {
        int32_t __stdcall get_VideoDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities>
    {
        int32_t __stdcall get_PowerReportingType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsReportingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsUpdatingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsImagePreviewSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsImagePreviewSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>
    {
        int32_t __stdcall get_IsSoftwareTriggerSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSoftwareTriggerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>
    {
        int32_t __stdcall get_IsVideoPreviewSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVideoPreviewSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>
    {
        int32_t __stdcall get_Report(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeScannerReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>
    {
        int32_t __stdcall get_PartialInputData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeScannerReport>(this->shim().PartialInputData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRetriable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRetriable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData>(this->shim().ErrorData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>
    {
        int32_t __stdcall get_Preview(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Preview());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerReport> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerReport>
    {
        int32_t __stdcall get_ScanDataType(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ScanDataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScanData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ScanData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScanDataLabel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ScanDataLabel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory>
    {
        int32_t __stdcall CreateInstance(uint32_t scanDataType, void* scanData, void* scanDataLabel, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::PointOfService::BarcodeScannerReport>(this->shim().CreateInstance(scanDataType, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&scanData), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&scanDataLabel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2>
    {
        int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t connectionTypes, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeScannerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedStatus(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>
    {
        int32_t __stdcall get_Unknown(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Unknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean8(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean8Add2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean8Add2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean8Add5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean8Add5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Eanv(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Eanv());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EanvAdd2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().EanvAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EanvAdd5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().EanvAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean13(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean13());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean13Add2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean13Add2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean13Add5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean13Add5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Isbn(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Isbn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsbnAdd5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().IsbnAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ismn(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ismn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsmnAdd2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().IsmnAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsmnAdd5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().IsmnAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Issn(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Issn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IssnAdd2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().IssnAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IssnAdd5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().IssnAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean99(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean99());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean99Add2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean99Add2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ean99Add5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ean99Add5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Upca(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Upca());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpcaAdd2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UpcaAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpcaAdd5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UpcaAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Upce(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Upce());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpceAdd2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UpceAdd2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpceAdd5(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UpceAdd5());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpcCoupon(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UpcCoupon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TfStd(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TfStd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TfDis(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TfDis());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TfInt(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TfInt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TfInd(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TfInd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TfMat(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TfMat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TfIata(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TfIata());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gs1DatabarType1(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Gs1DatabarType1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gs1DatabarType2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Gs1DatabarType2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gs1DatabarType3(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Gs1DatabarType3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code39(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code39());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code39Ex(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code39Ex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Trioptic39(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Trioptic39());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code32(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code32());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pzn(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Pzn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code93(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code93());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code93Ex(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code93Ex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code128(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code128());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gs1128(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Gs1128());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gs1128Coupon(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Gs1128Coupon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UccEan128(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UccEan128());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Sisac(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Sisac());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Isbt(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Isbt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Codabar(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Codabar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code11(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code11());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Msi(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Msi());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Plessey(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Plessey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Telepen(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Telepen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code16k(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code16k());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CodablockA(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CodablockA());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CodablockF(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CodablockF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Codablock128(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Codablock128());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Code49(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Code49());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Aztec(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Aztec());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DataCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataMatrix(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DataMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HanXin(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().HanXin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Maxicode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Maxicode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicroPdf417(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MicroPdf417());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MicroQr(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MicroQr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pdf417(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Pdf417());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Qr(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Qr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MsTag(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MsTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ccab(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ccab());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ccc(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ccc());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tlc39(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Tlc39());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AusPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AusPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CanPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChinaPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ChinaPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DutchKix(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DutchKix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InfoMail(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().InfoMail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItalianPost25(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ItalianPost25());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItalianPost39(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ItalianPost39());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JapanPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().JapanPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KoreanPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().KoreanPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SwedenPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SwedenPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UkPost(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UkPost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsIntelligent(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UsIntelligent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsIntelligentPkg(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UsIntelligentPkg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsPlanet(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UsPlanet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsPostNet(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UsPostNet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Us4StateFics(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Us4StateFics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OcrA(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().OcrA());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OcrB(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().OcrB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Micr(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Micr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedBase(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedBase());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetName(uint32_t scanDataType, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetName(scanDataType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>
    {
        int32_t __stdcall get_Gs1DWCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Gs1DWCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> : produce_base<D, winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>
    {
        int32_t __stdcall get_IsCheckDigitValidationEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCheckDigitValidationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCheckDigitValidationEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCheckDigitValidationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCheckDigitValidationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCheckDigitValidationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCheckDigitTransmissionEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCheckDigitTransmissionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCheckDigitTransmissionEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCheckDigitTransmissionEnabled(value);
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
        int32_t __stdcall get_DecodeLength1(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DecodeLength1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodeLength1(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodeLength1(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodeLength2(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DecodeLength2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodeLength2(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodeLength2(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodeLengthKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind>(this->shim().DecodeLengthKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodeLengthKind(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodeLengthKind(*reinterpret_cast<winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const*>(&value));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawer> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawer>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDrawerOpen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDrawerOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DrawerEventSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawerEventSource>(this->shim().DrawerEventSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClaimDrawerAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer>>(this->shim().ClaimDrawerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckHealthAsync(int32_t level, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStatisticsAsync(void* statisticsCategories, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawer, winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities>
    {
        int32_t __stdcall get_PowerReportingType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsReportingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsUpdatingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatusReportingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatusReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatusMultiDrawerDetectSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatusMultiDrawerDetectSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDrawerOpenSensorAvailable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDrawerOpenSensorAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm>
    {
        int32_t __stdcall put_AlarmTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlarmTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlarmTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().AlarmTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BeepFrequency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeepFrequency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BeepFrequency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().BeepFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BeepDuration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeepDuration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BeepDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().BeepDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BeepDelay(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeepDelay(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BeepDelay(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().BeepDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AlarmTimeoutExpired(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AlarmTimeoutExpired(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AlarmTimeoutExpired(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlarmTimeoutExpired(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall StartAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerEventSource> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>
    {
        int32_t __stdcall add_DrawerClosed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DrawerClosed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DrawerClosed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DrawerClosed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DrawerOpened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DrawerOpened(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DrawerOpened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DrawerOpened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>
    {
        int32_t __stdcall get_CashDrawer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawer>(this->shim().CashDrawer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatics2> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatics2>
    {
        int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t connectionTypes, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatus> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatus>
    {
        int32_t __stdcall get_StatusKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawerStatusKind>(this->shim().StatusKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedStatus(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>
    {
        int32_t __stdcall get_Status(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
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
        int32_t __stdcall put_IsDisabledOnDataReceived(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDisabledOnDataReceived(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabledOnDataReceived(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledOnDataReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDecodeDataEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDecodeDataEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDecodeDataEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDecodeDataEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetainDevice() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RetainDevice();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetActiveSymbologiesAsync(void* symbologies, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetActiveSymbologiesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<uint32_t> const*>(&symbologies)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ResetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateStatisticsAsync(void* statistics, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetActiveProfileAsync(void* profile, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetActiveProfileAsync(*reinterpret_cast<hstring const*>(&profile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DataReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DataReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DataReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TriggerPressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TriggerPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TriggerPressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TriggerPressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TriggerReleased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TriggerReleased(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TriggerReleased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TriggerReleased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ImagePreviewReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ImagePreviewReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ImagePreviewReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImagePreviewReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ErrorOccurred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1>
    {
        int32_t __stdcall StartSoftwareTriggerAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartSoftwareTriggerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopSoftwareTriggerAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopSoftwareTriggerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2>
    {
        int32_t __stdcall GetSymbologyAttributesAsync(uint32_t barcodeSymbology, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>>(this->shim().GetSymbologyAttributesAsync(barcodeSymbology));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSymbologyAttributesAsync(uint32_t barcodeSymbology, void* attributes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SetSymbologyAttributesAsync(barcodeSymbology, *reinterpret_cast<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3>
    {
        int32_t __stdcall ShowVideoPreviewAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().ShowVideoPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HideVideoPreview() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HideVideoPreview();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsVideoPreviewShownOnEnable(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsVideoPreviewShownOnEnable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVideoPreviewShownOnEnable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVideoPreviewShownOnEnable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedCashDrawer> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedCashDrawer>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
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
        int32_t __stdcall get_IsDrawerOpen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDrawerOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CloseAlarm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm>(this->shim().CloseAlarm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenDrawerAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().OpenDrawerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetainDeviceAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RetainDeviceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().ResetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateStatisticsAsync(void* statistics, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter>
    {
        int32_t __stdcall CreateJob(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::JournalPrintJob>(this->shim().CreateJob());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplay> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplay>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhysicalDeviceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PhysicalDeviceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhysicalDeviceDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PhysicalDeviceDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceControlDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceControlDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceControlVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceControlVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceServiceVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceServiceVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultWindow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayWindow>(this->shim().DefaultWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetainDevice() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RetainDevice();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2>
    {
        int32_t __stdcall GetStatisticsAsync(void* statisticsCategories, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckHealthAsync(int32_t level, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckPowerStatusAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>>(this->shim().CheckPowerStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_SupportedScreenSizesInCharacters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Size>>(this->shim().SupportedScreenSizesInCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBitmapSizeInPixels(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().MaxBitmapSizeInPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCharacterSets(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<int32_t>>(this->shim().SupportedCharacterSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomGlyphs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs>(this->shim().CustomGlyphs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayAttributes>(this->shim().GetAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdateAttributesAsync(void* attributes, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUpdateAttributesAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetDescriptorAsync(uint32_t descriptor, int32_t descriptorState, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetDescriptorAsync(descriptor, *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayDescriptorState const*>(&descriptorState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryClearDescriptorsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryClearDescriptorsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateWindowAsync(winrt::Windows::Foundation::Rect viewport, winrt::Windows::Foundation::Size windowSize, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayWindow>>(this->shim().TryCreateWindowAsync(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&viewport), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&windowSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStoreStorageFileBitmapAsync(void* bitmap, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>>(this->shim().TryStoreStorageFileBitmapAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStoreStorageFileBitmapWithAlignmentAsync(void* bitmap, int32_t horizontalAlignment, int32_t verticalAlignment, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>>(this->shim().TryStoreStorageFileBitmapAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStoreStorageFileBitmapWithAlignmentAndWidthAsync(void* bitmap, int32_t horizontalAlignment, int32_t verticalAlignment, int32_t widthInPixels, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>>(this->shim().TryStoreStorageFileBitmapAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment), widthInPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t connectionTypes, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
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
        int32_t __stdcall put_IsDisabledOnDataReceived(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDisabledOnDataReceived(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDisabledOnDataReceived(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledOnDataReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDecodeDataEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDecodeDataEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDecodeDataEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDecodeDataEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDeviceAuthenticated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDeviceAuthenticated());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataEncryptionAlgorithm(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataEncryptionAlgorithm(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataEncryptionAlgorithm(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DataEncryptionAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TracksToRead(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TracksToRead(*reinterpret_cast<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TracksToRead(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds>(this->shim().TracksToRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTransmitSentinelsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTransmitSentinelsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTransmitSentinelsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTransmitSentinelsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetainDevice() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RetainDevice();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetErrorReportingType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetErrorReportingType(*reinterpret_cast<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrieveDeviceAuthenticationDataAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().RetrieveDeviceAuthenticationDataAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AuthenticateDeviceAsync(uint32_t __responseTokenSize, uint8_t* responseToken, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AuthenticateDeviceAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseToken), reinterpret_cast<uint8_t const *>(responseToken) + __responseTokenSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeAuthenticateDeviceAsync(uint32_t __responseTokenSize, uint8_t* responseToken, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeAuthenticateDeviceAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(responseToken), reinterpret_cast<uint8_t const *>(responseToken) + __responseTokenSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateKeyAsync(void* key, void* keyName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpdateKeyAsync(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<hstring const*>(&keyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ResetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateStatisticsAsync(void* statistics, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_BankCardDataReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BankCardDataReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BankCardDataReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BankCardDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AamvaCardDataReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AamvaCardDataReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AamvaCardDataReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AamvaCardDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VendorSpecificDataReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VendorSpecificDataReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VendorSpecificDataReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VendorSpecificDataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ErrorOccurred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedPosPrinter> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedPosPrinter>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
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
        int32_t __stdcall put_CharacterSet(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterSet(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterSet(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCoverOpen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCoverOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCharacterSetMappingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCharacterSetMappingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCharacterSetMappingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCharacterSetMappingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MapMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MapMode(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterMapMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MapMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterMapMode>(this->shim().MapMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Receipt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter>(this->shim().Receipt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Slip(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter>(this->shim().Slip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Journal(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter>(this->shim().Journal());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetainDeviceAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RetainDeviceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetStatisticsAsync(void* statisticsCategories, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().ResetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateStatisticsAsync(void* statistics, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&statistics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReleaseDeviceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleaseDeviceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter>
    {
        int32_t __stdcall get_SidewaysMaxLines(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SidewaysMaxChars(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxChars());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LinesToPaperCut(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LinesToPaperCut());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().PageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrintArea(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().PrintArea());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateJob(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::ReceiptPrintJob>(this->shim().CreateJob());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter> : produce_base<D, winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter>
    {
        int32_t __stdcall get_SidewaysMaxLines(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SidewaysMaxChars(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SidewaysMaxChars());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxLines(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxLines());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LinesNearEndToEnd(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LinesNearEndToEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrintSide(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterPrintSide>(this->shim().PrintSide());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().PageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrintArea(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().PrintArea());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenJaws() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenJaws();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CloseJaws() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CloseJaws();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InsertSlipAsync(int64_t timeout, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().InsertSlipAsync(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveSlipAsync(int64_t timeout, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RemoveSlipAsync(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangePrintSide(int32_t printSide) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangePrintSide(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterPrintSide const*>(&printSide));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateJob(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::SlipPrintJob>(this->shim().CreateJob());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> : produce_base<D, winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>
    {
        int32_t __stdcall put_CharactersPerLine(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharactersPerLine(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharactersPerLine(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CharactersPerLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LineHeight(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LineSpacing(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineSpacing(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineSpacing(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LineSpacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LineWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsLetterQuality(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLetterQuality(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLetterQuality(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLetterQuality());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPaperNearEnd(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPaperNearEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ColorCartridge(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorCartridge(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColorCartridge(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge>(this->shim().ColorCartridge());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCoverOpen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCoverOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCartridgeRemoved(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCartridgeRemoved());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCartridgeEmpty(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCartridgeEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHeadCleaning(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHeadCleaning());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPaperEmpty(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPaperEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReadyToPrint(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadyToPrint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ValidateData(void* data, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ValidateData(*reinterpret_cast<hstring const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>
    {
        int32_t __stdcall get_IsPrinterPresent(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrinterPresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDualColorSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDualColorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColorCartridgeCapabilities(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterColorCapabilities>(this->shim().ColorCartridgeCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CartridgeSensors(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterCartridgeSensors>(this->shim().CartridgeSensors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBoldSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBoldSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsItalicSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsItalicSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsUnderlineSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUnderlineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDoubleHighPrintSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDoubleHighPrintSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDoubleWidePrintSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDoubleWidePrintSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDoubleHighDoubleWidePrintSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDoubleHighDoubleWidePrintSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPaperEmptySensorSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPaperEmptySensorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPaperNearEndSensorSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPaperNearEndSensorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCharactersPerLine(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedCharactersPerLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>
    {
        int32_t __stdcall get_IsBarcodeSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBarcodeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBitmapSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBitmapSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLeft90RotationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLeft90RotationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsRight90RotationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsRight90RotationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Is180RotationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Is180RotationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPrintAreaSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrintAreaSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RuledLineCapabilities(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities>(this->shim().RuledLineCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedBarcodeRotations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>>(this->shim().SupportedBarcodeRotations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedBitmapRotations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>>(this->shim().SupportedBitmapRotations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IJournalPrintJob> : produce_base<D, winrt::Windows::Devices::PointOfService::IJournalPrintJob>
    {
        int32_t __stdcall Print(void* data, void* printOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Print(*reinterpret_cast<hstring const*>(&data), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const*>(&printOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FeedPaperByLine(int32_t lineCount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FeedPaperByLine(lineCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FeedPaperByMapModeUnit(int32_t distance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FeedPaperByMapModeUnit(distance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2> : produce_base<D, winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2>
    {
        int32_t __stdcall get_IsReverseVideoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReverseVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStrikethroughSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStrikethroughSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSuperscriptSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSuperscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSubscriptSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSubscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReversePaperFeedByLineSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByLineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByMapModeUnitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplay> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplay>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhysicalDeviceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PhysicalDeviceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhysicalDeviceDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PhysicalDeviceDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceControlDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceControlDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceControlVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceControlVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceServiceVersion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceServiceVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClaimAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>>(this->shim().ClaimAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplay2> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplay2>
    {
        int32_t __stdcall CheckPowerStatusAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>>(this->shim().CheckPowerStatusAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayAttributes> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayAttributes>
    {
        int32_t __stdcall get_IsPowerNotifyEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPowerNotifyEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPowerNotifyEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPowerNotifyEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Brightness(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Brightness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Brightness(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Brightness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BlinkRate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().BlinkRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BlinkRate(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BlinkRate(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScreenSizeInCharacters(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().ScreenSizeInCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScreenSizeInCharacters(winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScreenSizeInCharacters(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterSet(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CharacterSet(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterSet(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCharacterSetMappingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCharacterSetMappingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCharacterSetMappingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCharacterSetMappingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentWindow(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayWindow>(this->shim().CurrentWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CurrentWindow(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentWindow(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayWindow const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities>
    {
        int32_t __stdcall get_IsStatisticsReportingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsUpdatingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PowerReportingType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanChangeScreenSize(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanChangeScreenSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanDisplayBitmaps(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanDisplayBitmaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanReadCharacterAtCursor(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanReadCharacterAtCursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanMapCharacterSets(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanMapCharacterSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanDisplayCustomGlyphs(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanDisplayCustomGlyphs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanReverse(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>(this->shim().CanReverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanBlink(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>(this->shim().CanBlink());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanChangeBlinkRate(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanChangeBlinkRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBrightnessSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBrightnessSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCursorSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCursorSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHorizontalMarqueeSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHorizontalMarqueeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVerticalMarqueeSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVerticalMarqueeSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInterCharacterWaitSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInterCharacterWaitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedDescriptors(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SupportedDescriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedWindows(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SupportedWindows());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayCursor> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayCursor>
    {
        int32_t __stdcall get_CanCustomize(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanCustomize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBlinkSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBlinkSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBlockSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBlockSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsHalfBlockSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHalfBlockSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsUnderlineSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUnderlineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReverseSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReverseSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOtherSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOtherSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAttributes(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes>(this->shim().GetAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdateAttributesAsync(void* attributes, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUpdateAttributesAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes>
    {
        int32_t __stdcall get_IsBlinkEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBlinkEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsBlinkEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsBlinkEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CursorType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayCursorType>(this->shim().CursorType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CursorType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CursorType(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayCursorType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAutoAdvanceEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAutoAdvanceEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAutoAdvanceEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAutoAdvanceEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>
    {
        int32_t __stdcall get_SizeInPixels(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().SizeInPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedGlyphCodes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedGlyphCodes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRedefineAsync(uint32_t glyphCode, void* glyphData, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRedefineAsync(glyphCode, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&glyphData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayMarquee> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayMarquee>
    {
        int32_t __stdcall get_Format(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Format(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Format(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RepeatWaitInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RepeatWaitInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RepeatWaitInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RepeatWaitInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScrollWaitInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().ScrollWaitInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScrollWaitInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScrollWaitInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStartScrollingAsync(int32_t direction, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryStartScrollingAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryStopScrollingAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryStopScrollingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t connectionTypes, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatics2> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatics2>
    {
        int32_t __stdcall get_StatisticsCategorySelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>(this->shim().StatisticsCategorySelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>
    {
        int32_t __stdcall get_AllStatistics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AllStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnifiedPosStatistics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnifiedPosStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManufacturerStatistics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ManufacturerStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap>
    {
        int32_t __stdcall get_EscapeSequence(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EscapeSequence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDeleteAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayWindow> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayWindow>
    {
        int32_t __stdcall get_SizeInCharacters(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().SizeInCharacters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InterCharacterWaitInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().InterCharacterWaitInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InterCharacterWaitInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InterCharacterWaitInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRefreshAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRefreshAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayTextAsync(void* text, int32_t displayAttribute, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayTextAsync(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute const*>(&displayAttribute)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayTextAtPositionAsync(void* text, int32_t displayAttribute, winrt::Windows::Foundation::Point startPosition, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayTextAsync(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute const*>(&displayAttribute), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&startPosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayTextNormalAsync(void* text, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayTextAsync(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryScrollTextAsync(int32_t direction, uint32_t numberOfColumnsOrRows, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryScrollTextAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection const*>(&direction), numberOfColumnsOrRows));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryClearTextAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryClearTextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ILineDisplayWindow2> : produce_base<D, winrt::Windows::Devices::PointOfService::ILineDisplayWindow2>
    {
        int32_t __stdcall get_Cursor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayCursor>(this->shim().Cursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Marquee(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::LineDisplayMarquee>(this->shim().Marquee());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadCharacterAtCursorAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().ReadCharacterAtCursorAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayStoredBitmapAtCursorAsync(void* bitmap, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStoredBitmapAtCursorAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayStorageFileBitmapAtCursorAsync(void* bitmap, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtCursorAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayStorageFileBitmapAtCursorWithAlignmentAsync(void* bitmap, int32_t horizontalAlignment, int32_t verticalAlignment, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtCursorAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayStorageFileBitmapAtCursorWithAlignmentAndWidthAsync(void* bitmap, int32_t horizontalAlignment, int32_t verticalAlignment, int32_t widthInPixels, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtCursorAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const*>(&horizontalAlignment), *reinterpret_cast<winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const*>(&verticalAlignment), widthInPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayStorageFileBitmapAtPointAsync(void* bitmap, winrt::Windows::Foundation::Point offsetInPixels, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtPointAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&offsetInPixels)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryDisplayStorageFileBitmapAtPointWithWidthAsync(void* bitmap, winrt::Windows::Foundation::Point offsetInPixels, int32_t widthInPixels, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDisplayStorageFileBitmapAtPointAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&bitmap), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&offsetInPixels), widthInPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReader> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReader>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCardTypes(uint32_t* __valueSize, uint32_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            std::tie(*__valueSize, *value) = detach_abi(this->shim().SupportedCardTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceAuthenticationProtocol(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol>(this->shim().DeviceAuthenticationProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckHealthAsync(int32_t level, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClaimReaderAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader>>(this->shim().ClaimReaderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrieveStatisticsAsync(void* statisticsCategories, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().RetrieveStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetErrorReportingType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType>(this->shim().GetErrorReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::MagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>
    {
        int32_t __stdcall get_Report(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LicenseNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LicenseNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Restrictions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Restrictions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Class(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Class());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Endorsements(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Endorsements());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BirthDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BirthDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Surname(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Surname());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Suffix(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Suffix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gender(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Gender());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HairColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HairColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EyeColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EyeColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Weight(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Address(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Address());
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
        int32_t __stdcall get_State(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().State());
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>
    {
        int32_t __stdcall get_Report(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccountNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AccountNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExpirationDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceCode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ServiceCode());
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
        int32_t __stdcall get_FirstName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MiddleInitial(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MiddleInitial());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Surname(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Surname());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Suffix(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Suffix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>
    {
        int32_t __stdcall get_CardAuthentication(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CardAuthentication());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedEncryptionAlgorithms(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SupportedEncryptionAlgorithms());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel>(this->shim().AuthenticationLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIsoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIsoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsJisOneSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsJisOneSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsJisTwoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsJisTwoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PowerReportingType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsReportingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsUpdatingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTrackDataMaskingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTrackDataMaskingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTransmitSentinelsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTransmitSentinelsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>
    {
        int32_t __stdcall get_Unknown(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Unknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bank(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Bank());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Aamva(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Aamva());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedBase(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedBase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>
    {
        int32_t __stdcall get_None(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().None());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TripleDesDukpt(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TripleDesDukpt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedBase(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedBase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>
    {
        int32_t __stdcall get_Track1Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track1Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track2Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track2Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track3Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track3Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track4Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>(this->shim().Track4Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData>(this->shim().ErrorData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PartialInputData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().PartialInputData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport>
    {
        int32_t __stdcall get_CardType(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CardType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Track4(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData>(this->shim().Track4());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CardAuthenticationData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().CardAuthenticationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CardAuthenticationDataLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CardAuthenticationDataLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AdditionalSecurityInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().AdditionalSecurityInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>
    {
        int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t connectionTypes, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedStatus(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DiscretionaryData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DiscretionaryData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EncryptedData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().EncryptedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>
    {
        int32_t __stdcall get_Report(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinter> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinter>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedCharacterSets(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedCharacterSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedTypeFaces(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedTypeFaces());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClaimPrinterAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter>>(this->shim().ClaimPrinterAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckHealthAsync(int32_t level, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CheckHealthAsync(*reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const*>(&level)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStatisticsAsync(void* statisticsCategories, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetStatisticsAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&statisticsCategories)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::PosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinter2> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinter2>
    {
        int32_t __stdcall get_SupportedBarcodeSymbologies(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedBarcodeSymbologies());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFontProperty(void* typeface, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty>(this->shim().GetFontProperty(*reinterpret_cast<hstring const*>(&typeface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities>
    {
        int32_t __stdcall get_PowerReportingType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType>(this->shim().PowerReportingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsReportingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsReportingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStatisticsUpdatingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStatisticsUpdatingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultCharacterSet(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DefaultCharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasCoverSensor(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasCoverSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanMapCharacterSet(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanMapCharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTransactionSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTransactionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Receipt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities>(this->shim().Receipt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Slip(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities>(this->shim().Slip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Journal(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities>(this->shim().Journal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>
    {
        int32_t __stdcall get_Utf16LE(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Utf16LE());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ascii(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ascii());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ansi(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Ansi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty>
    {
        int32_t __stdcall get_TypeFace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TypeFace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsScalableToAnySize(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScalableToAnySize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterSizes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::SizeUInt32>>(this->shim().CharacterSizes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterJob> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterJob>
    {
        int32_t __stdcall Print(void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Print(*reinterpret_cast<hstring const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintLine(void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintLine(*reinterpret_cast<hstring const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintNewline() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintLine();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ExecuteAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().ExecuteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions>
    {
        int32_t __stdcall get_TypeFace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TypeFace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TypeFace(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TypeFace(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CharacterHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CharacterHeight(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bold(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Bold());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Bold(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bold(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Italic(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Italic());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Italic(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Italic(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Underline(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Underline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Underline(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Underline(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReverseVideo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ReverseVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReverseVideo(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReverseVideo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Strikethrough(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Strikethrough());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Strikethrough(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Strikethrough(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Superscript(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Superscript());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Superscript(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Superscript(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subscript(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Subscript());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Subscript(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Subscript(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DoubleWide(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DoubleWide());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DoubleWide(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DoubleWide(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DoubleHigh(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DoubleHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DoubleHigh(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DoubleHigh(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Alignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterAlignment>(this->shim().Alignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Alignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Alignment(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CharacterSet(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CharacterSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CharacterSet(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterSet(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatics> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatics2> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatics2>
    {
        int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t connectionTypes, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosConnectionTypes const*>(&connectionTypes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatus> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatus>
    {
        int32_t __stdcall get_StatusKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterStatusKind>(this->shim().StatusKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedStatus(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> : produce_base<D, winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>
    {
        int32_t __stdcall get_Status(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob> : produce_base<D, winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob>
    {
        int32_t __stdcall SetBarcodeRotation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBarcodeRotation(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrintRotation(int32_t value, bool includeBitmaps) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPrintRotation(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterRotation const*>(&value), includeBitmaps);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrintArea(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPrintArea(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBitmap(uint32_t bitmapNumber, void* bitmap, int32_t alignment) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBitmap(bitmapNumber, *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBitmapCustomWidthStandardAlign(uint32_t bitmapNumber, void* bitmap, int32_t alignment, uint32_t width) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBitmap(bitmapNumber, *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment), width);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetCustomAlignedBitmap(uint32_t bitmapNumber, void* bitmap, uint32_t alignmentDistance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCustomAlignedBitmap(bitmapNumber, *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBitmapCustomWidthCustomAlign(uint32_t bitmapNumber, void* bitmap, uint32_t alignmentDistance, uint32_t width) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCustomAlignedBitmap(bitmapNumber, *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance, width);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintSavedBitmap(uint32_t bitmapNumber) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintSavedBitmap(bitmapNumber);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DrawRuledLine(void* positionList, int32_t lineDirection, uint32_t lineWidth, int32_t lineStyle, uint32_t lineColor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DrawRuledLine(*reinterpret_cast<hstring const*>(&positionList), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterLineDirection const*>(&lineDirection), lineWidth, *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterLineStyle const*>(&lineStyle), lineColor);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintBarcode(void* data, uint32_t symbology, uint32_t height, uint32_t width, int32_t textPosition, int32_t alignment) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintBarcode(*reinterpret_cast<hstring const*>(&data), symbology, height, width, *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const*>(&textPosition), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintBarcodeCustomAlign(void* data, uint32_t symbology, uint32_t height, uint32_t width, int32_t textPosition, uint32_t alignmentDistance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintBarcodeCustomAlign(*reinterpret_cast<hstring const*>(&data), symbology, height, width, *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const*>(&textPosition), alignmentDistance);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintBitmap(void* bitmap, int32_t alignment) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintBitmapCustomWidthStandardAlign(void* bitmap, int32_t alignment, uint32_t width) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterAlignment const*>(&alignment), width);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintCustomAlignedBitmap(void* bitmap, uint32_t alignmentDistance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintCustomAlignedBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PrintBitmapCustomWidthCustomAlign(void* bitmap, uint32_t alignmentDistance, uint32_t width) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintCustomAlignedBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapFrame const*>(&bitmap), alignmentDistance, width);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IReceiptPrintJob> : produce_base<D, winrt::Windows::Devices::PointOfService::IReceiptPrintJob>
    {
        int32_t __stdcall MarkFeed(int32_t kind) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MarkFeed(*reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedKind const*>(&kind));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CutPaper(double percentage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CutPaper(percentage);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CutPaperDefault() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CutPaper();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IReceiptPrintJob2> : produce_base<D, winrt::Windows::Devices::PointOfService::IReceiptPrintJob2>
    {
        int32_t __stdcall StampPaper() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StampPaper();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Print(void* data, void* printOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Print(*reinterpret_cast<hstring const*>(&data), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const*>(&printOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FeedPaperByLine(int32_t lineCount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FeedPaperByLine(lineCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FeedPaperByMapModeUnit(int32_t distance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FeedPaperByMapModeUnit(distance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities>
    {
        int32_t __stdcall get_CanCutPaper(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanCutPaper());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStampSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStampSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MarkFeedCapabilities(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities>(this->shim().MarkFeedCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> : produce_base<D, winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>
    {
        int32_t __stdcall get_IsReverseVideoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReverseVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStrikethroughSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStrikethroughSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSuperscriptSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSuperscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSubscriptSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSubscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReversePaperFeedByLineSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByLineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByMapModeUnitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ISlipPrintJob> : produce_base<D, winrt::Windows::Devices::PointOfService::ISlipPrintJob>
    {
        int32_t __stdcall Print(void* data, void* printOptions) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Print(*reinterpret_cast<hstring const*>(&data), *reinterpret_cast<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const*>(&printOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FeedPaperByLine(int32_t lineCount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FeedPaperByLine(lineCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FeedPaperByMapModeUnit(int32_t distance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FeedPaperByMapModeUnit(distance);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities> : produce_base<D, winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities>
    {
        int32_t __stdcall get_IsFullLengthSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFullLengthSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBothSidesPrintingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBothSidesPrintingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2> : produce_base<D, winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2>
    {
        int32_t __stdcall get_IsReverseVideoSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReverseVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStrikethroughSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStrikethroughSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSuperscriptSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSuperscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSubscriptSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSubscriptSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReversePaperFeedByLineSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByLineSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReversePaperFeedByMapModeUnitSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReversePaperFeedByMapModeUnitSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData> : produce_base<D, winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Severity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity>(this->shim().Severity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedReason(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExtendedReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> : produce_base<D, winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>
    {
        int32_t __stdcall CreateInstance(void* message, int32_t severity, int32_t reason, uint32_t extendedReason, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&message), *reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity const*>(&severity), *reinterpret_cast<winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason const*>(&reason), extendedReason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService
{
    constexpr auto operator|(PosConnectionTypes const left, PosConnectionTypes const right) noexcept
    {
        return static_cast<PosConnectionTypes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PosConnectionTypes& left, PosConnectionTypes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PosConnectionTypes const left, PosConnectionTypes const right) noexcept
    {
        return static_cast<PosConnectionTypes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PosConnectionTypes& left, PosConnectionTypes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PosConnectionTypes const value) noexcept
    {
        return static_cast<PosConnectionTypes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PosConnectionTypes const left, PosConnectionTypes const right) noexcept
    {
        return static_cast<PosConnectionTypes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PosConnectionTypes& left, PosConnectionTypes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(PosPrinterCartridgeSensors const left, PosPrinterCartridgeSensors const right) noexcept
    {
        return static_cast<PosPrinterCartridgeSensors>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PosPrinterCartridgeSensors& left, PosPrinterCartridgeSensors const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PosPrinterCartridgeSensors const left, PosPrinterCartridgeSensors const right) noexcept
    {
        return static_cast<PosPrinterCartridgeSensors>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PosPrinterCartridgeSensors& left, PosPrinterCartridgeSensors const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PosPrinterCartridgeSensors const value) noexcept
    {
        return static_cast<PosPrinterCartridgeSensors>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PosPrinterCartridgeSensors const left, PosPrinterCartridgeSensors const right) noexcept
    {
        return static_cast<PosPrinterCartridgeSensors>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PosPrinterCartridgeSensors& left, PosPrinterCartridgeSensors const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(PosPrinterColorCapabilities const left, PosPrinterColorCapabilities const right) noexcept
    {
        return static_cast<PosPrinterColorCapabilities>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PosPrinterColorCapabilities& left, PosPrinterColorCapabilities const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PosPrinterColorCapabilities const left, PosPrinterColorCapabilities const right) noexcept
    {
        return static_cast<PosPrinterColorCapabilities>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PosPrinterColorCapabilities& left, PosPrinterColorCapabilities const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PosPrinterColorCapabilities const value) noexcept
    {
        return static_cast<PosPrinterColorCapabilities>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PosPrinterColorCapabilities const left, PosPrinterColorCapabilities const right) noexcept
    {
        return static_cast<PosPrinterColorCapabilities>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PosPrinterColorCapabilities& left, PosPrinterColorCapabilities const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(PosPrinterMarkFeedCapabilities const left, PosPrinterMarkFeedCapabilities const right) noexcept
    {
        return static_cast<PosPrinterMarkFeedCapabilities>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PosPrinterMarkFeedCapabilities& left, PosPrinterMarkFeedCapabilities const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PosPrinterMarkFeedCapabilities const left, PosPrinterMarkFeedCapabilities const right) noexcept
    {
        return static_cast<PosPrinterMarkFeedCapabilities>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PosPrinterMarkFeedCapabilities& left, PosPrinterMarkFeedCapabilities const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PosPrinterMarkFeedCapabilities const value) noexcept
    {
        return static_cast<PosPrinterMarkFeedCapabilities>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PosPrinterMarkFeedCapabilities const left, PosPrinterMarkFeedCapabilities const right) noexcept
    {
        return static_cast<PosPrinterMarkFeedCapabilities>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PosPrinterMarkFeedCapabilities& left, PosPrinterMarkFeedCapabilities const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(PosPrinterRuledLineCapabilities const left, PosPrinterRuledLineCapabilities const right) noexcept
    {
        return static_cast<PosPrinterRuledLineCapabilities>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(PosPrinterRuledLineCapabilities& left, PosPrinterRuledLineCapabilities const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(PosPrinterRuledLineCapabilities const left, PosPrinterRuledLineCapabilities const right) noexcept
    {
        return static_cast<PosPrinterRuledLineCapabilities>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(PosPrinterRuledLineCapabilities& left, PosPrinterRuledLineCapabilities const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(PosPrinterRuledLineCapabilities const value) noexcept
    {
        return static_cast<PosPrinterRuledLineCapabilities>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(PosPrinterRuledLineCapabilities const left, PosPrinterRuledLineCapabilities const right) noexcept
    {
        return static_cast<PosPrinterRuledLineCapabilities>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(PosPrinterRuledLineCapabilities& left, PosPrinterRuledLineCapabilities const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto BarcodeScanner::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>(*)(IBarcodeScannerStatics const&), BarcodeScanner, IBarcodeScannerStatics>([](IBarcodeScannerStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto BarcodeScanner::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<BarcodeScanner, IBarcodeScannerStatics>([&](IBarcodeScannerStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto BarcodeScanner::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IBarcodeScannerStatics const&), BarcodeScanner, IBarcodeScannerStatics>([](IBarcodeScannerStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto BarcodeScanner::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
    {
        return impl::call_factory<BarcodeScanner, IBarcodeScannerStatics2>([&](IBarcodeScannerStatics2 const& f) { return f.GetDeviceSelector(connectionTypes); });
    }
    inline BarcodeScannerReport::BarcodeScannerReport(uint32_t scanDataType, winrt::Windows::Storage::Streams::IBuffer const& scanData, winrt::Windows::Storage::Streams::IBuffer const& scanDataLabel) :
        BarcodeScannerReport(impl::call_factory<BarcodeScannerReport, IBarcodeScannerReportFactory>([&](IBarcodeScannerReportFactory const& f) { return f.CreateInstance(scanDataType, scanData, scanDataLabel); }))
    {
    }
    inline auto BarcodeSymbologies::Unknown()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Unknown(); });
    }
    inline auto BarcodeSymbologies::Ean8()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean8(); });
    }
    inline auto BarcodeSymbologies::Ean8Add2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean8Add2(); });
    }
    inline auto BarcodeSymbologies::Ean8Add5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean8Add5(); });
    }
    inline auto BarcodeSymbologies::Eanv()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Eanv(); });
    }
    inline auto BarcodeSymbologies::EanvAdd2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.EanvAdd2(); });
    }
    inline auto BarcodeSymbologies::EanvAdd5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.EanvAdd5(); });
    }
    inline auto BarcodeSymbologies::Ean13()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean13(); });
    }
    inline auto BarcodeSymbologies::Ean13Add2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean13Add2(); });
    }
    inline auto BarcodeSymbologies::Ean13Add5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean13Add5(); });
    }
    inline auto BarcodeSymbologies::Isbn()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Isbn(); });
    }
    inline auto BarcodeSymbologies::IsbnAdd5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.IsbnAdd5(); });
    }
    inline auto BarcodeSymbologies::Ismn()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ismn(); });
    }
    inline auto BarcodeSymbologies::IsmnAdd2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.IsmnAdd2(); });
    }
    inline auto BarcodeSymbologies::IsmnAdd5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.IsmnAdd5(); });
    }
    inline auto BarcodeSymbologies::Issn()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Issn(); });
    }
    inline auto BarcodeSymbologies::IssnAdd2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.IssnAdd2(); });
    }
    inline auto BarcodeSymbologies::IssnAdd5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.IssnAdd5(); });
    }
    inline auto BarcodeSymbologies::Ean99()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean99(); });
    }
    inline auto BarcodeSymbologies::Ean99Add2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean99Add2(); });
    }
    inline auto BarcodeSymbologies::Ean99Add5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ean99Add5(); });
    }
    inline auto BarcodeSymbologies::Upca()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Upca(); });
    }
    inline auto BarcodeSymbologies::UpcaAdd2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UpcaAdd2(); });
    }
    inline auto BarcodeSymbologies::UpcaAdd5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UpcaAdd5(); });
    }
    inline auto BarcodeSymbologies::Upce()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Upce(); });
    }
    inline auto BarcodeSymbologies::UpceAdd2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UpceAdd2(); });
    }
    inline auto BarcodeSymbologies::UpceAdd5()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UpceAdd5(); });
    }
    inline auto BarcodeSymbologies::UpcCoupon()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UpcCoupon(); });
    }
    inline auto BarcodeSymbologies::TfStd()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.TfStd(); });
    }
    inline auto BarcodeSymbologies::TfDis()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.TfDis(); });
    }
    inline auto BarcodeSymbologies::TfInt()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.TfInt(); });
    }
    inline auto BarcodeSymbologies::TfInd()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.TfInd(); });
    }
    inline auto BarcodeSymbologies::TfMat()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.TfMat(); });
    }
    inline auto BarcodeSymbologies::TfIata()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.TfIata(); });
    }
    inline auto BarcodeSymbologies::Gs1DatabarType1()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Gs1DatabarType1(); });
    }
    inline auto BarcodeSymbologies::Gs1DatabarType2()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Gs1DatabarType2(); });
    }
    inline auto BarcodeSymbologies::Gs1DatabarType3()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Gs1DatabarType3(); });
    }
    inline auto BarcodeSymbologies::Code39()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code39(); });
    }
    inline auto BarcodeSymbologies::Code39Ex()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code39Ex(); });
    }
    inline auto BarcodeSymbologies::Trioptic39()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Trioptic39(); });
    }
    inline auto BarcodeSymbologies::Code32()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code32(); });
    }
    inline auto BarcodeSymbologies::Pzn()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Pzn(); });
    }
    inline auto BarcodeSymbologies::Code93()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code93(); });
    }
    inline auto BarcodeSymbologies::Code93Ex()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code93Ex(); });
    }
    inline auto BarcodeSymbologies::Code128()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code128(); });
    }
    inline auto BarcodeSymbologies::Gs1128()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Gs1128(); });
    }
    inline auto BarcodeSymbologies::Gs1128Coupon()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Gs1128Coupon(); });
    }
    inline auto BarcodeSymbologies::UccEan128()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UccEan128(); });
    }
    inline auto BarcodeSymbologies::Sisac()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Sisac(); });
    }
    inline auto BarcodeSymbologies::Isbt()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Isbt(); });
    }
    inline auto BarcodeSymbologies::Codabar()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Codabar(); });
    }
    inline auto BarcodeSymbologies::Code11()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code11(); });
    }
    inline auto BarcodeSymbologies::Msi()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Msi(); });
    }
    inline auto BarcodeSymbologies::Plessey()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Plessey(); });
    }
    inline auto BarcodeSymbologies::Telepen()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Telepen(); });
    }
    inline auto BarcodeSymbologies::Code16k()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code16k(); });
    }
    inline auto BarcodeSymbologies::CodablockA()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.CodablockA(); });
    }
    inline auto BarcodeSymbologies::CodablockF()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.CodablockF(); });
    }
    inline auto BarcodeSymbologies::Codablock128()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Codablock128(); });
    }
    inline auto BarcodeSymbologies::Code49()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Code49(); });
    }
    inline auto BarcodeSymbologies::Aztec()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Aztec(); });
    }
    inline auto BarcodeSymbologies::DataCode()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.DataCode(); });
    }
    inline auto BarcodeSymbologies::DataMatrix()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.DataMatrix(); });
    }
    inline auto BarcodeSymbologies::HanXin()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.HanXin(); });
    }
    inline auto BarcodeSymbologies::Maxicode()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Maxicode(); });
    }
    inline auto BarcodeSymbologies::MicroPdf417()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.MicroPdf417(); });
    }
    inline auto BarcodeSymbologies::MicroQr()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.MicroQr(); });
    }
    inline auto BarcodeSymbologies::Pdf417()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Pdf417(); });
    }
    inline auto BarcodeSymbologies::Qr()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Qr(); });
    }
    inline auto BarcodeSymbologies::MsTag()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.MsTag(); });
    }
    inline auto BarcodeSymbologies::Ccab()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ccab(); });
    }
    inline auto BarcodeSymbologies::Ccc()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Ccc(); });
    }
    inline auto BarcodeSymbologies::Tlc39()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Tlc39(); });
    }
    inline auto BarcodeSymbologies::AusPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.AusPost(); });
    }
    inline auto BarcodeSymbologies::CanPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.CanPost(); });
    }
    inline auto BarcodeSymbologies::ChinaPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.ChinaPost(); });
    }
    inline auto BarcodeSymbologies::DutchKix()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.DutchKix(); });
    }
    inline auto BarcodeSymbologies::InfoMail()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.InfoMail(); });
    }
    inline auto BarcodeSymbologies::ItalianPost25()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.ItalianPost25(); });
    }
    inline auto BarcodeSymbologies::ItalianPost39()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.ItalianPost39(); });
    }
    inline auto BarcodeSymbologies::JapanPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.JapanPost(); });
    }
    inline auto BarcodeSymbologies::KoreanPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.KoreanPost(); });
    }
    inline auto BarcodeSymbologies::SwedenPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.SwedenPost(); });
    }
    inline auto BarcodeSymbologies::UkPost()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UkPost(); });
    }
    inline auto BarcodeSymbologies::UsIntelligent()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UsIntelligent(); });
    }
    inline auto BarcodeSymbologies::UsIntelligentPkg()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UsIntelligentPkg(); });
    }
    inline auto BarcodeSymbologies::UsPlanet()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UsPlanet(); });
    }
    inline auto BarcodeSymbologies::UsPostNet()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.UsPostNet(); });
    }
    inline auto BarcodeSymbologies::Us4StateFics()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Us4StateFics(); });
    }
    inline auto BarcodeSymbologies::OcrA()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.OcrA(); });
    }
    inline auto BarcodeSymbologies::OcrB()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.OcrB(); });
    }
    inline auto BarcodeSymbologies::Micr()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.Micr(); });
    }
    inline auto BarcodeSymbologies::ExtendedBase()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics const&), BarcodeSymbologies, IBarcodeSymbologiesStatics>([](IBarcodeSymbologiesStatics const& f) { return f.ExtendedBase(); });
    }
    inline auto BarcodeSymbologies::GetName(uint32_t scanDataType)
    {
        return impl::call_factory<BarcodeSymbologies, IBarcodeSymbologiesStatics>([&](IBarcodeSymbologiesStatics const& f) { return f.GetName(scanDataType); });
    }
    inline auto BarcodeSymbologies::Gs1DWCode()
    {
        return impl::call_factory_cast<uint32_t(*)(IBarcodeSymbologiesStatics2 const&), BarcodeSymbologies, IBarcodeSymbologiesStatics2>([](IBarcodeSymbologiesStatics2 const& f) { return f.Gs1DWCode(); });
    }
    inline auto CashDrawer::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>(*)(ICashDrawerStatics const&), CashDrawer, ICashDrawerStatics>([](ICashDrawerStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto CashDrawer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<CashDrawer, ICashDrawerStatics>([&](ICashDrawerStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto CashDrawer::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ICashDrawerStatics const&), CashDrawer, ICashDrawerStatics>([](ICashDrawerStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto CashDrawer::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
    {
        return impl::call_factory<CashDrawer, ICashDrawerStatics2>([&](ICashDrawerStatics2 const& f) { return f.GetDeviceSelector(connectionTypes); });
    }
    inline auto ClaimedLineDisplay::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<ClaimedLineDisplay, IClaimedLineDisplayStatics>([&](IClaimedLineDisplayStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto ClaimedLineDisplay::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IClaimedLineDisplayStatics const&), ClaimedLineDisplay, IClaimedLineDisplayStatics>([](IClaimedLineDisplayStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto ClaimedLineDisplay::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
    {
        return impl::call_factory<ClaimedLineDisplay, IClaimedLineDisplayStatics>([&](IClaimedLineDisplayStatics const& f) { return f.GetDeviceSelector(connectionTypes); });
    }
    inline auto LineDisplay::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<LineDisplay, ILineDisplayStatics>([&](ILineDisplayStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto LineDisplay::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>(*)(ILineDisplayStatics const&), LineDisplay, ILineDisplayStatics>([](ILineDisplayStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto LineDisplay::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ILineDisplayStatics const&), LineDisplay, ILineDisplayStatics>([](ILineDisplayStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto LineDisplay::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
    {
        return impl::call_factory<LineDisplay, ILineDisplayStatics>([&](ILineDisplayStatics const& f) { return f.GetDeviceSelector(connectionTypes); });
    }
    inline auto LineDisplay::StatisticsCategorySelector()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector(*)(ILineDisplayStatics2 const&), LineDisplay, ILineDisplayStatics2>([](ILineDisplayStatics2 const& f) { return f.StatisticsCategorySelector(); });
    }
    inline auto MagneticStripeReader::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>(*)(IMagneticStripeReaderStatics const&), MagneticStripeReader, IMagneticStripeReaderStatics>([](IMagneticStripeReaderStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto MagneticStripeReader::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<MagneticStripeReader, IMagneticStripeReaderStatics>([&](IMagneticStripeReaderStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto MagneticStripeReader::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IMagneticStripeReaderStatics const&), MagneticStripeReader, IMagneticStripeReaderStatics>([](IMagneticStripeReaderStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto MagneticStripeReader::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
    {
        return impl::call_factory<MagneticStripeReader, IMagneticStripeReaderStatics2>([&](IMagneticStripeReaderStatics2 const& f) { return f.GetDeviceSelector(connectionTypes); });
    }
    inline auto MagneticStripeReaderCardTypes::Unknown()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderCardTypesStatics const&), MagneticStripeReaderCardTypes, IMagneticStripeReaderCardTypesStatics>([](IMagneticStripeReaderCardTypesStatics const& f) { return f.Unknown(); });
    }
    inline auto MagneticStripeReaderCardTypes::Bank()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderCardTypesStatics const&), MagneticStripeReaderCardTypes, IMagneticStripeReaderCardTypesStatics>([](IMagneticStripeReaderCardTypesStatics const& f) { return f.Bank(); });
    }
    inline auto MagneticStripeReaderCardTypes::Aamva()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderCardTypesStatics const&), MagneticStripeReaderCardTypes, IMagneticStripeReaderCardTypesStatics>([](IMagneticStripeReaderCardTypesStatics const& f) { return f.Aamva(); });
    }
    inline auto MagneticStripeReaderCardTypes::ExtendedBase()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderCardTypesStatics const&), MagneticStripeReaderCardTypes, IMagneticStripeReaderCardTypesStatics>([](IMagneticStripeReaderCardTypesStatics const& f) { return f.ExtendedBase(); });
    }
    inline auto MagneticStripeReaderEncryptionAlgorithms::None()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderEncryptionAlgorithmsStatics const&), MagneticStripeReaderEncryptionAlgorithms, IMagneticStripeReaderEncryptionAlgorithmsStatics>([](IMagneticStripeReaderEncryptionAlgorithmsStatics const& f) { return f.None(); });
    }
    inline auto MagneticStripeReaderEncryptionAlgorithms::TripleDesDukpt()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderEncryptionAlgorithmsStatics const&), MagneticStripeReaderEncryptionAlgorithms, IMagneticStripeReaderEncryptionAlgorithmsStatics>([](IMagneticStripeReaderEncryptionAlgorithmsStatics const& f) { return f.TripleDesDukpt(); });
    }
    inline auto MagneticStripeReaderEncryptionAlgorithms::ExtendedBase()
    {
        return impl::call_factory_cast<uint32_t(*)(IMagneticStripeReaderEncryptionAlgorithmsStatics const&), MagneticStripeReaderEncryptionAlgorithms, IMagneticStripeReaderEncryptionAlgorithmsStatics>([](IMagneticStripeReaderEncryptionAlgorithmsStatics const& f) { return f.ExtendedBase(); });
    }
    inline auto PosPrinter::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>(*)(IPosPrinterStatics const&), PosPrinter, IPosPrinterStatics>([](IPosPrinterStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto PosPrinter::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<PosPrinter, IPosPrinterStatics>([&](IPosPrinterStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto PosPrinter::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IPosPrinterStatics const&), PosPrinter, IPosPrinterStatics>([](IPosPrinterStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto PosPrinter::GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes)
    {
        return impl::call_factory<PosPrinter, IPosPrinterStatics2>([&](IPosPrinterStatics2 const& f) { return f.GetDeviceSelector(connectionTypes); });
    }
    inline auto PosPrinterCharacterSetIds::Utf16LE()
    {
        return impl::call_factory_cast<uint32_t(*)(IPosPrinterCharacterSetIdsStatics const&), PosPrinterCharacterSetIds, IPosPrinterCharacterSetIdsStatics>([](IPosPrinterCharacterSetIdsStatics const& f) { return f.Utf16LE(); });
    }
    inline auto PosPrinterCharacterSetIds::Ascii()
    {
        return impl::call_factory_cast<uint32_t(*)(IPosPrinterCharacterSetIdsStatics const&), PosPrinterCharacterSetIds, IPosPrinterCharacterSetIdsStatics>([](IPosPrinterCharacterSetIdsStatics const& f) { return f.Ascii(); });
    }
    inline auto PosPrinterCharacterSetIds::Ansi()
    {
        return impl::call_factory_cast<uint32_t(*)(IPosPrinterCharacterSetIdsStatics const&), PosPrinterCharacterSetIds, IPosPrinterCharacterSetIdsStatics>([](IPosPrinterCharacterSetIdsStatics const& f) { return f.Ansi(); });
    }
    inline PosPrinterPrintOptions::PosPrinterPrintOptions() :
        PosPrinterPrintOptions(impl::call_factory_cast<PosPrinterPrintOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), PosPrinterPrintOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PosPrinterPrintOptions>(); }))
    {
    }
    inline UnifiedPosErrorData::UnifiedPosErrorData(param::hstring const& message, winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity const& severity, winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason const& reason, uint32_t extendedReason) :
        UnifiedPosErrorData(impl::call_factory<UnifiedPosErrorData, IUnifiedPosErrorDataFactory>([&](IUnifiedPosErrorDataFactory const& f) { return f.CreateInstance(message, severity, reason, extendedReason); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScanner> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScanner2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IJournalPrintJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplay> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplay2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCursor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrintJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ISlipPrintJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScanner> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeSymbologies> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerEventSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::JournalPrintJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplay> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCursor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayMarquee> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::LineDisplayWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCardTypes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterCharacterSetIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterStatus> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ReceiptPrintJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::SlipPrintJob> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
