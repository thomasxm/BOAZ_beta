// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Sensors_H
#define WINRT_Windows_Devices_Sensors_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Display.2.h"
#include "winrt/impl/Windows.Devices.Sensors.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerReading) consume_Windows_Devices_Sensors_IAccelerometer<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::AccelerometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAccelerometer<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometer<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAccelerometer<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->add_Shaken(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken_revoker consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Shaken_revoker>(this, Shaken(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer)->remove_Shaken(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometer2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_IAccelerometer2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometer3<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer3)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAccelerometer3<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer3)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAccelerometer3<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer3)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerReadingType) consume_Windows_Devices_Sensors_IAccelerometer4<D>::ReadingType() const
    {
        winrt::Windows::Devices::Sensors::AccelerometerReadingType type{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer4)->get_ReadingType(reinterpret_cast<int32_t*>(&type)));
        return type;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerDataThreshold) consume_Windows_Devices_Sensors_IAccelerometer5<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometer5)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::AccelerometerDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>::XAxisInGForce() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold)->get_XAxisInGForce(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>::XAxisInGForce(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold)->put_XAxisInGForce(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>::YAxisInGForce() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold)->get_YAxisInGForce(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>::YAxisInGForce(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold)->put_YAxisInGForce(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>::ZAxisInGForce() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold)->get_ZAxisInGForce(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAccelerometerDataThreshold<D>::ZAxisInGForce(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold)->put_ZAxisInGForce(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IAccelerometerDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IAccelerometerReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAccelerometerReading<D>::AccelerationX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReading)->get_AccelerationX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAccelerometerReading<D>::AccelerationY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReading)->get_AccelerationY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAccelerometerReading<D>::AccelerationZ() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReading)->get_AccelerationZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IAccelerometerReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IAccelerometerReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AccelerometerReading) consume_Windows_Devices_Sensors_IAccelerometerReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::AccelerometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IAccelerometerShakenEventArgs<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Accelerometer) consume_Windows_Devices_Sensors_IAccelerometerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Accelerometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Accelerometer) consume_Windows_Devices_Sensors_IAccelerometerStatics2<D>::GetDefault(winrt::Windows::Devices::Sensors::AccelerometerReadingType const& readingType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerStatics2)->GetDefaultWithAccelerometerReadingType(static_cast<int32_t>(readingType), &result));
        return winrt::Windows::Devices::Sensors::Accelerometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Accelerometer>) consume_Windows_Devices_Sensors_IAccelerometerStatics3<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerStatics3)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Accelerometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IAccelerometerStatics3<D>::GetDeviceSelector(winrt::Windows::Devices::Sensors::AccelerometerReadingType const& readingType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAccelerometerStatics3)->GetDeviceSelector(static_cast<int32_t>(readingType), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensorReading>) consume_Windows_Devices_Sensors_IActivitySensor<D>::GetCurrentReadingAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->GetCurrentReadingAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensorReading>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Sensors::ActivityType>) consume_Windows_Devices_Sensors_IActivitySensor<D>::SubscribedActivities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->get_SubscribedActivities(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Sensors::ActivityType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IActivitySensor<D>::PowerInMilliwatts() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->get_PowerInMilliwatts(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IActivitySensor<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivityType>) consume_Windows_Devices_Sensors_IActivitySensor<D>::SupportedActivities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->get_SupportedActivities(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivityType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IActivitySensor<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ActivitySensor, winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ActivitySensor, winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IActivitySensorReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivityType) consume_Windows_Devices_Sensors_IActivitySensorReading<D>::Activity() const
    {
        winrt::Windows::Devices::Sensors::ActivityType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorReading)->get_Activity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivitySensorReadingConfidence) consume_Windows_Devices_Sensors_IActivitySensorReading<D>::Confidence() const
    {
        winrt::Windows::Devices::Sensors::ActivitySensorReadingConfidence value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorReading)->get_Confidence(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivitySensorReading) consume_Windows_Devices_Sensors_IActivitySensorReadingChangeReport<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::ActivitySensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ActivitySensorReading) consume_Windows_Devices_Sensors_IActivitySensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::ActivitySensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>) consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>) consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>) consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorStatics)->GetSystemHistoryAsync(impl::bind_in(fromTime), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>) consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime, winrt::Windows::Foundation::TimeSpan const& duration) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorStatics)->GetSystemHistoryWithDurationAsync(impl::bind_in(fromTime), impl::bind_in(duration), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport>) consume_Windows_Devices_Sensors_IActivitySensorTriggerDetails<D>::ReadReports() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails)->ReadReports(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IAdaptiveDimmingOptions<D>::AllowWhenExternalDisplayConnected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions)->get_AllowWhenExternalDisplayConnected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAdaptiveDimmingOptions<D>::AllowWhenExternalDisplayConnected(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions)->put_AllowWhenExternalDisplayConnected(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AltimeterReading) consume_Windows_Devices_Sensors_IAltimeter<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::AltimeterReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IAltimeter<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAltimeter<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAltimeter<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAltimeter<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Altimeter, winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Altimeter, winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IAltimeter2<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter2)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAltimeter2<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter2)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IAltimeter2<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeter2)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IAltimeterReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeterReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IAltimeterReading<D>::AltitudeChangeInMeters() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeterReading)->get_AltitudeChangeInMeters(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IAltimeterReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeterReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IAltimeterReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeterReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AltimeterReading) consume_Windows_Devices_Sensors_IAltimeterReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::AltimeterReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Altimeter) consume_Windows_Devices_Sensors_IAltimeterStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IAltimeterStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Altimeter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::BarometerReading) consume_Windows_Devices_Sensors_IBarometer<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::BarometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IBarometer<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IBarometer<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IBarometer<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IBarometer<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Barometer, winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Barometer, winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IBarometer2<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer2)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IBarometer2<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer2)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IBarometer2<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer2)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::BarometerDataThreshold) consume_Windows_Devices_Sensors_IBarometer3<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometer3)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::BarometerDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IBarometerDataThreshold<D>::Hectopascals() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerDataThreshold)->get_Hectopascals(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IBarometerDataThreshold<D>::Hectopascals(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerDataThreshold)->put_Hectopascals(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IBarometerReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IBarometerReading<D>::StationPressureInHectopascals() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerReading)->get_StationPressureInHectopascals(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IBarometerReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IBarometerReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::BarometerReading) consume_Windows_Devices_Sensors_IBarometerReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::BarometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Barometer) consume_Windows_Devices_Sensors_IBarometerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Barometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Barometer>) consume_Windows_Devices_Sensors_IBarometerStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerStatics2)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Barometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IBarometerStatics2<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IBarometerStatics2)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::CompassReading) consume_Windows_Devices_Sensors_ICompass<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::CompassReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ICompass<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ICompass<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ICompass<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Compass, winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Compass, winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ICompass2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_ICompass2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ICompass3<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass3)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ICompass3<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass3)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ICompass3<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass3)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::CompassDataThreshold) consume_Windows_Devices_Sensors_ICompass4<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompass4)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::CompassDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_ICompassDataThreshold<D>::Degrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassDataThreshold)->get_Degrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ICompassDataThreshold<D>::Degrees(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassDataThreshold)->put_Degrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ICompassDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_ICompassReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_ICompassReading<D>::HeadingMagneticNorth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReading)->get_HeadingMagneticNorth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Devices_Sensors_ICompassReading<D>::HeadingTrueNorth() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReading)->get_HeadingTrueNorth(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_ICompassReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_ICompassReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::CompassReading) consume_Windows_Devices_Sensors_ICompassReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::CompassReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) consume_Windows_Devices_Sensors_ICompassReadingHeadingAccuracy<D>::HeadingAccuracy() const
    {
        winrt::Windows::Devices::Sensors::MagnetometerAccuracy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy)->get_HeadingAccuracy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Compass) consume_Windows_Devices_Sensors_ICompassStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Compass{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ICompassStatics2<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassStatics2)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Compass>) consume_Windows_Devices_Sensors_ICompassStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ICompassStatics2)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Compass>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::GyrometerReading) consume_Windows_Devices_Sensors_IGyrometer<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::GyrometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IGyrometer<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometer<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IGyrometer<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Gyrometer, winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Gyrometer, winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometer2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_IGyrometer2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometer3<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer3)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IGyrometer3<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer3)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IGyrometer3<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer3)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::GyrometerDataThreshold) consume_Windows_Devices_Sensors_IGyrometer4<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometer4)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::GyrometerDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>::XAxisInDegreesPerSecond() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDataThreshold)->get_XAxisInDegreesPerSecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>::XAxisInDegreesPerSecond(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDataThreshold)->put_XAxisInDegreesPerSecond(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>::YAxisInDegreesPerSecond() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDataThreshold)->get_YAxisInDegreesPerSecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>::YAxisInDegreesPerSecond(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDataThreshold)->put_YAxisInDegreesPerSecond(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>::ZAxisInDegreesPerSecond() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDataThreshold)->get_ZAxisInDegreesPerSecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IGyrometerDataThreshold<D>::ZAxisInDegreesPerSecond(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDataThreshold)->put_ZAxisInDegreesPerSecond(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IGyrometerDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IGyrometerReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IGyrometerReading<D>::AngularVelocityX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReading)->get_AngularVelocityX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IGyrometerReading<D>::AngularVelocityY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReading)->get_AngularVelocityY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IGyrometerReading<D>::AngularVelocityZ() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReading)->get_AngularVelocityZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IGyrometerReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IGyrometerReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::GyrometerReading) consume_Windows_Devices_Sensors_IGyrometerReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::GyrometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Gyrometer) consume_Windows_Devices_Sensors_IGyrometerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Gyrometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IGyrometerStatics2<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerStatics2)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Gyrometer>) consume_Windows_Devices_Sensors_IGyrometerStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IGyrometerStatics2)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Gyrometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IHingeAngleReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IHingeAngleReading<D>::AngleInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleReading)->get_AngleInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IHingeAngleReading<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleReading)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleReading>) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::GetCurrentReadingAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->GetCurrentReadingAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleReading>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::MinReportThresholdInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->get_MinReportThresholdInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReportThresholdInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->get_ReportThresholdInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReportThresholdInDegrees(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->put_ReportThresholdInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HingeAngleSensor, winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HingeAngleSensor, winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HingeAngleReading) consume_Windows_Devices_Sensors_IHingeAngleSensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::HingeAngleReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>) consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::GetDefaultAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics)->GetDefaultAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>) consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::GetRelatedToAdjacentPanelsAsync(param::hstring const& firstPanelId, param::hstring const& secondPanelId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics)->GetRelatedToAdjacentPanelsAsync(*(void**)(&firstPanelId), *(void**)(&secondPanelId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>) consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IHumanPresenceFeatures<D>::SensorId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceFeatures)->get_SensorId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceFeatures<D>::SupportedWakeOrLockDistancesInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceFeatures)->get_SupportedWakeOrLockDistancesInMillimeters(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceFeatures<D>::IsWakeOnApproachSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceFeatures)->get_IsWakeOnApproachSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceFeatures<D>::IsLockOnLeaveSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceFeatures)->get_IsLockOnLeaveSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceFeatures<D>::IsAttentionAwareDimmingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceFeatures)->get_IsAttentionAwareDimmingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceFeatures2<D>::IsAdaptiveDimmingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2)->get_IsAdaptiveDimmingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::MaxDetectableDistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor)->get_MaxDetectableDistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::MinDetectableDistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor)->get_MinDetectableDistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading) consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::GetCurrentReading() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor)->GetCurrentReading(&result));
        return winrt::Windows::Devices::Sensors::HumanPresenceSensorReading{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HumanPresenceSensor, winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HumanPresenceSensor, winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceSensor2<D>::IsPresenceSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor2)->get_IsPresenceSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceSensor2<D>::IsEngagementSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensor2)->get_IsEngagementSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::Initialize(param::hstring const& deviceInterface) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->Initialize(*(void**)(&deviceInterface)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::ProcessReading(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading const& reading) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->ProcessReading(*(void**)(&reading), &result));
        return winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::ProcessReadingTimeoutExpired(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading const& reading) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->ProcessReadingTimeoutExpired(*(void**)(&reading)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::Uninitialize() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->Uninitialize());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorExtension<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IHumanPresenceSensorReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresence) consume_Windows_Devices_Sensors_IHumanPresenceSensorReading<D>::Presence() const
    {
        winrt::Windows::Devices::Sensors::HumanPresence value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading)->get_Presence(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanEngagement) consume_Windows_Devices_Sensors_IHumanPresenceSensorReading<D>::Engagement() const
    {
        winrt::Windows::Devices::Sensors::HumanEngagement value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading)->get_Engagement(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceSensorReading<D>::DistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading)->get_DistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IHumanPresenceSensorReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensorReading) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::HumanPresenceSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::Timestamp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->get_Timestamp(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::Timestamp(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->put_Timestamp(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence>) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::Presence() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->get_Presence(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::Presence(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->put_Presence(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement>) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::Engagement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->get_Engagement(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::Engagement(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->put_Engagement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::DistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->get_DistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSensorReadingUpdate<D>::DistanceInMillimeters(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate)->put_DistanceInMillimeters(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>) consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics<D>::FromIdAsync(param::hstring const& sensorId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics)->FromIdAsync(*(void**)(&sensorId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>) consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensor) consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics2<D>::FromId(param::hstring const& sensorId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2)->FromId(*(void**)(&sensorId), &result));
        return winrt::Windows::Devices::Sensors::HumanPresenceSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSensor) consume_Windows_Devices_Sensors_IHumanPresenceSensorStatics2<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::HumanPresenceSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::SensorId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_SensorId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::SensorId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_SensorId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::IsWakeOnApproachEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_IsWakeOnApproachEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::IsWakeOnApproachEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_IsWakeOnApproachEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::WakeOnApproachDistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_WakeOnApproachDistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::WakeOnApproachDistanceInMillimeters(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_WakeOnApproachDistanceInMillimeters(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::IsLockOnLeaveEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_IsLockOnLeaveEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::IsLockOnLeaveEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_IsLockOnLeaveEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::LockOnLeaveDistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_LockOnLeaveDistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::LockOnLeaveDistanceInMillimeters(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_LockOnLeaveDistanceInMillimeters(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::LockOnLeaveTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_LockOnLeaveTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::LockOnLeaveTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_LockOnLeaveTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::IsAttentionAwareDimmingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->get_IsAttentionAwareDimmingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings<D>::IsAttentionAwareDimmingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings)->put_IsAttentionAwareDimmingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IHumanPresenceSettings2<D>::IsAdaptiveDimmingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings2)->get_IsAdaptiveDimmingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettings2<D>::IsAdaptiveDimmingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings2)->put_IsAdaptiveDimmingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::WakeOnApproachOptions) consume_Windows_Devices_Sensors_IHumanPresenceSettings2<D>::WakeOptions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings2)->get_WakeOptions(&value));
        return winrt::Windows::Devices::Sensors::WakeOnApproachOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions) consume_Windows_Devices_Sensors_IHumanPresenceSettings2<D>::DimmingOptions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings2)->get_DimmingOptions(&value));
        return winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LockOnLeaveOptions) consume_Windows_Devices_Sensors_IHumanPresenceSettings2<D>::LockOptions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettings2)->get_LockOptions(&value));
        return winrt::Windows::Devices::Sensors::LockOnLeaveOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSettings>) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::GetCurrentSettingsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->GetCurrentSettingsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSettings>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceSettings) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::GetCurrentSettings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->GetCurrentSettings(&result));
        return winrt::Windows::Devices::Sensors::HumanPresenceSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::UpdateSettingsAsync(winrt::Windows::Devices::Sensors::HumanPresenceSettings const& settings) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->UpdateSettingsAsync(*(void**)(&settings), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::UpdateSettings(winrt::Windows::Devices::Sensors::HumanPresenceSettings const& settings) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->UpdateSettings(*(void**)(&settings)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::GetSupportedFeaturesForSensorIdAsync(param::hstring const& sensorId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->GetSupportedFeaturesForSensorIdAsync(*(void**)(&sensorId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::HumanPresenceFeatures) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::GetSupportedFeaturesForSensorId(param::hstring const& sensorId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->GetSupportedFeaturesForSensorId(*(void**)(&sensorId), &result));
        return winrt::Windows::Devices::Sensors::HumanPresenceFeatures{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::GetSupportedLockOnLeaveTimeouts() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->GetSupportedLockOnLeaveTimeouts(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::TimeSpan>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::SettingsChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->add_SettingsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::SettingsChanged_revoker consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::SettingsChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SettingsChanged_revoker>(this, SettingsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IHumanPresenceSettingsStatics<D>::SettingsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics)->remove_SettingsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::InclinometerReading) consume_Windows_Devices_Sensors_IInclinometer<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::InclinometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IInclinometer<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometer<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IInclinometer<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Inclinometer, winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Inclinometer, winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometer2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_IInclinometer2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorReadingType) consume_Windows_Devices_Sensors_IInclinometer2<D>::ReadingType() const
    {
        winrt::Windows::Devices::Sensors::SensorReadingType type{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer2)->get_ReadingType(reinterpret_cast<int32_t*>(&type)));
        return type;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometer3<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer3)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IInclinometer3<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer3)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IInclinometer3<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer3)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::InclinometerDataThreshold) consume_Windows_Devices_Sensors_IInclinometer4<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometer4)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::InclinometerDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>::PitchInDegrees() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDataThreshold)->get_PitchInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>::PitchInDegrees(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDataThreshold)->put_PitchInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>::RollInDegrees() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDataThreshold)->get_RollInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>::RollInDegrees(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDataThreshold)->put_RollInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>::YawInDegrees() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDataThreshold)->get_YawInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IInclinometerDataThreshold<D>::YawInDegrees(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDataThreshold)->put_YawInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IInclinometerDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IInclinometerReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IInclinometerReading<D>::PitchDegrees() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReading)->get_PitchDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IInclinometerReading<D>::RollDegrees() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReading)->get_RollDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IInclinometerReading<D>::YawDegrees() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReading)->get_YawDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IInclinometerReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IInclinometerReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::InclinometerReading) consume_Windows_Devices_Sensors_IInclinometerReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::InclinometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) consume_Windows_Devices_Sensors_IInclinometerReadingYawAccuracy<D>::YawAccuracy() const
    {
        winrt::Windows::Devices::Sensors::MagnetometerAccuracy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy)->get_YawAccuracy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Inclinometer) consume_Windows_Devices_Sensors_IInclinometerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Inclinometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Inclinometer) consume_Windows_Devices_Sensors_IInclinometerStatics2<D>::GetDefaultForRelativeReadings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerStatics2)->GetDefaultForRelativeReadings(&result));
        return winrt::Windows::Devices::Sensors::Inclinometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Inclinometer) consume_Windows_Devices_Sensors_IInclinometerStatics3<D>::GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerStatics3)->GetDefaultWithSensorReadingType(static_cast<int32_t>(sensorReadingtype), &result));
        return winrt::Windows::Devices::Sensors::Inclinometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IInclinometerStatics4<D>::GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerStatics4)->GetDeviceSelector(static_cast<int32_t>(readingType), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Inclinometer>) consume_Windows_Devices_Sensors_IInclinometerStatics4<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IInclinometerStatics4)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Inclinometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensorReading) consume_Windows_Devices_Sensors_ILightSensor<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::LightSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ILightSensor<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ILightSensor<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ILightSensor<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::LightSensor, winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::LightSensor, winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ILightSensor2<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor2)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ILightSensor2<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor2)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_ILightSensor2<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor2)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensorDataThreshold) consume_Windows_Devices_Sensors_ILightSensor3<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensor3)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::LightSensorDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ILightSensorDataThreshold<D>::LuxPercentage() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorDataThreshold)->get_LuxPercentage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ILightSensorDataThreshold<D>::LuxPercentage(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorDataThreshold)->put_LuxPercentage(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ILightSensorDataThreshold<D>::AbsoluteLux() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorDataThreshold)->get_AbsoluteLux(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ILightSensorDataThreshold<D>::AbsoluteLux(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorDataThreshold)->put_AbsoluteLux(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ILightSensorDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_ILightSensorReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ILightSensorReading<D>::IlluminanceInLux() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorReading)->get_IlluminanceInLux(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_ILightSensorReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_ILightSensorReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensorReading) consume_Windows_Devices_Sensors_ILightSensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::LightSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::LightSensor) consume_Windows_Devices_Sensors_ILightSensorStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::LightSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ILightSensorStatics2<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorStatics2)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::LightSensor>) consume_Windows_Devices_Sensors_ILightSensorStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILightSensorStatics2)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::LightSensor>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_ILockOnLeaveOptions<D>::AllowWhenExternalDisplayConnected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILockOnLeaveOptions)->get_AllowWhenExternalDisplayConnected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ILockOnLeaveOptions<D>::AllowWhenExternalDisplayConnected(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ILockOnLeaveOptions)->put_AllowWhenExternalDisplayConnected(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerReading) consume_Windows_Devices_Sensors_IMagnetometer<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::MagnetometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IMagnetometer<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometer<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IMagnetometer<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Magnetometer, winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Magnetometer, winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometer2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_IMagnetometer2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometer3<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer3)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IMagnetometer3<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer3)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IMagnetometer3<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer3)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerDataThreshold) consume_Windows_Devices_Sensors_IMagnetometer4<D>::ReportThreshold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometer4)->get_ReportThreshold(&value));
        return winrt::Windows::Devices::Sensors::MagnetometerDataThreshold{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>::XAxisMicroteslas() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold)->get_XAxisMicroteslas(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>::XAxisMicroteslas(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold)->put_XAxisMicroteslas(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>::YAxisMicroteslas() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold)->get_YAxisMicroteslas(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>::YAxisMicroteslas(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold)->put_YAxisMicroteslas(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>::ZAxisMicroteslas() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold)->get_ZAxisMicroteslas(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IMagnetometerDataThreshold<D>::ZAxisMicroteslas(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold)->put_ZAxisMicroteslas(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IMagnetometerDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IMagnetometerReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IMagnetometerReading<D>::MagneticFieldX() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading)->get_MagneticFieldX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IMagnetometerReading<D>::MagneticFieldY() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading)->get_MagneticFieldY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_IMagnetometerReading<D>::MagneticFieldZ() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading)->get_MagneticFieldZ(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) consume_Windows_Devices_Sensors_IMagnetometerReading<D>::DirectionalAccuracy() const
    {
        winrt::Windows::Devices::Sensors::MagnetometerAccuracy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading)->get_DirectionalAccuracy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IMagnetometerReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IMagnetometerReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerReading) consume_Windows_Devices_Sensors_IMagnetometerReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::MagnetometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Magnetometer) consume_Windows_Devices_Sensors_IMagnetometerStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::Magnetometer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IMagnetometerStatics2<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerStatics2)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Magnetometer>) consume_Windows_Devices_Sensors_IMagnetometerStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IMagnetometerStatics2)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Magnetometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensorReading) consume_Windows_Devices_Sensors_IOrientationSensor<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::OrientationSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IOrientationSensor<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::OrientationSensor, winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::OrientationSensor, winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IOrientationSensor2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_IOrientationSensor2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorReadingType) consume_Windows_Devices_Sensors_IOrientationSensor2<D>::ReadingType() const
    {
        winrt::Windows::Devices::Sensors::SensorReadingType type{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor2)->get_ReadingType(reinterpret_cast<int32_t*>(&type)));
        return type;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IOrientationSensor3<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor3)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IOrientationSensor3<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor3)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IOrientationSensor3<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensor3)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IOrientationSensorDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IOrientationSensorReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorRotationMatrix) consume_Windows_Devices_Sensors_IOrientationSensorReading<D>::RotationMatrix() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReading)->get_RotationMatrix(&value));
        return winrt::Windows::Devices::Sensors::SensorRotationMatrix{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorQuaternion) consume_Windows_Devices_Sensors_IOrientationSensorReading<D>::Quaternion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReading)->get_Quaternion(&value));
        return winrt::Windows::Devices::Sensors::SensorQuaternion{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_IOrientationSensorReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_IOrientationSensorReading2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReading2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensorReading) consume_Windows_Devices_Sensors_IOrientationSensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::OrientationSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::MagnetometerAccuracy) consume_Windows_Devices_Sensors_IOrientationSensorReadingYawAccuracy<D>::YawAccuracy() const
    {
        winrt::Windows::Devices::Sensors::MagnetometerAccuracy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy)->get_YawAccuracy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) consume_Windows_Devices_Sensors_IOrientationSensorStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::OrientationSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) consume_Windows_Devices_Sensors_IOrientationSensorStatics2<D>::GetDefaultForRelativeReadings() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics2)->GetDefaultForRelativeReadings(&result));
        return winrt::Windows::Devices::Sensors::OrientationSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) consume_Windows_Devices_Sensors_IOrientationSensorStatics3<D>::GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics3)->GetDefaultWithSensorReadingType(static_cast<int32_t>(sensorReadingtype), &result));
        return winrt::Windows::Devices::Sensors::OrientationSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::OrientationSensor) consume_Windows_Devices_Sensors_IOrientationSensorStatics3<D>::GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingType, winrt::Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics3)->GetDefaultWithSensorReadingTypeAndSensorOptimizationGoal(static_cast<int32_t>(sensorReadingType), static_cast<int32_t>(optimizationGoal), &result));
        return winrt::Windows::Devices::Sensors::OrientationSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>::GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics4)->GetDeviceSelector(static_cast<int32_t>(readingType), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>::GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType, winrt::Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics4)->GetDeviceSelectorWithSensorReadingTypeAndSensorOptimizationGoal(static_cast<int32_t>(readingType), static_cast<int32_t>(optimizationGoal), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::OrientationSensor>) consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IOrientationSensorStatics4)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::OrientationSensor>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IPedometer<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Sensors_IPedometer<D>::PowerInMilliwatts() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->get_PowerInMilliwatts(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IPedometer<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IPedometer<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_IPedometer<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Pedometer, winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Pedometer, winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::Windows::Devices::Sensors::PedometerStepKind, winrt::Windows::Devices::Sensors::PedometerReading>) consume_Windows_Devices_Sensors_IPedometer2<D>::GetCurrentReadings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometer2)->GetCurrentReadings(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::Windows::Devices::Sensors::PedometerStepKind, winrt::Windows::Devices::Sensors::PedometerReading>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::PedometerDataThreshold) consume_Windows_Devices_Sensors_IPedometerDataThresholdFactory<D>::Create(winrt::Windows::Devices::Sensors::Pedometer const& sensor, int32_t stepGoal) const
    {
        void* threshold{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory)->Create(*(void**)(&sensor), stepGoal, &threshold));
        return winrt::Windows::Devices::Sensors::PedometerDataThreshold{ threshold, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::PedometerStepKind) consume_Windows_Devices_Sensors_IPedometerReading<D>::StepKind() const
    {
        winrt::Windows::Devices::Sensors::PedometerStepKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerReading)->get_StepKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Sensors_IPedometerReading<D>::CumulativeSteps() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerReading)->get_CumulativeSteps(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IPedometerReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Sensors_IPedometerReading<D>::CumulativeStepsDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerReading)->get_CumulativeStepsDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::PedometerReading) consume_Windows_Devices_Sensors_IPedometerReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::PedometerReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>) consume_Windows_Devices_Sensors_IPedometerStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>) consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerStatics)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>) consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerStatics)->GetSystemHistoryAsync(impl::bind_in(fromTime), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>) consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime, winrt::Windows::Foundation::TimeSpan const& duration) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerStatics)->GetSystemHistoryWithDurationAsync(impl::bind_in(fromTime), impl::bind_in(duration), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>) consume_Windows_Devices_Sensors_IPedometerStatics2<D>::GetReadingsFromTriggerDetails(winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IPedometerStatics2)->GetReadingsFromTriggerDetails(*(void**)(&triggerDetails), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IProximitySensor<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IProximitySensor<D>::MaxDistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->get_MaxDistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IProximitySensor<D>::MinDistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->get_MinDistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorReading) consume_Windows_Devices_Sensors_IProximitySensor<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::ProximitySensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ProximitySensor, winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ProximitySensor, winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController) consume_Windows_Devices_Sensors_IProximitySensor<D>::CreateDisplayOnOffController() const
    {
        void* controller{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensor)->CreateDisplayOnOffController(&controller));
        return winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController{ controller, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold) consume_Windows_Devices_Sensors_IProximitySensorDataThresholdFactory<D>::Create(winrt::Windows::Devices::Sensors::ProximitySensor const& sensor) const
    {
        void* threshold{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory)->Create(*(void**)(&sensor), &threshold));
        return winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold{ threshold, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_IProximitySensorReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IProximitySensorReading<D>::IsDetected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorReading)->get_IsDetected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Sensors_IProximitySensorReading<D>::DistanceInMillimeters() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorReading)->get_DistanceInMillimeters(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensorReading) consume_Windows_Devices_Sensors_IProximitySensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::ProximitySensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_IProximitySensorStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::ProximitySensor) consume_Windows_Devices_Sensors_IProximitySensorStatics<D>::FromId(param::hstring const& sensorId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorStatics)->FromId(*(void**)(&sensorId), &result));
        return winrt::Windows::Devices::Sensors::ProximitySensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ProximitySensorReading>) consume_Windows_Devices_Sensors_IProximitySensorStatics2<D>::GetReadingsFromTriggerDetails(winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IProximitySensorStatics2)->GetReadingsFromTriggerDetails(*(void**)(&triggerDetails), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ProximitySensorReading>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ISensorDataThresholdTriggerDetails<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SensorType) consume_Windows_Devices_Sensors_ISensorDataThresholdTriggerDetails<D>::SensorType() const
    {
        winrt::Windows::Devices::Sensors::SensorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails)->get_SensorType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorQuaternion<D>::W() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorQuaternion)->get_W(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorQuaternion<D>::X() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorQuaternion)->get_X(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorQuaternion<D>::Y() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorQuaternion)->get_Y(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorQuaternion<D>::Z() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorQuaternion)->get_Z(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M11() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M11(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M12() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M13() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M13(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M21() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M21(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M22() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M22(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M23() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M23(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M31() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M31(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M32() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M32(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M33() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISensorRotationMatrix)->get_M33(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientation) consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::GetCurrentOrientation() const
    {
        winrt::Windows::Devices::Sensors::SimpleOrientation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensor)->GetCurrentOrientation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::SimpleOrientationSensor, winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensor)->add_OrientationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged_revoker consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::SimpleOrientationSensor, winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OrientationChanged_revoker>(this, OrientationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensor)->remove_OrientationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_ISimpleOrientationSensor2<D>::ReadingTransform(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2)->put_ReadingTransform(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Devices_Sensors_ISimpleOrientationSensor2<D>::ReadingTransform() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2)->get_ReadingTransform(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ISimpleOrientationSensorDeviceId<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_ISimpleOrientationSensorOrientationChangedEventArgs<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientation) consume_Windows_Devices_Sensors_ISimpleOrientationSensorOrientationChangedEventArgs<D>::Orientation() const
    {
        winrt::Windows::Devices::Sensors::SimpleOrientation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs)->get_Orientation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::SimpleOrientationSensor) consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics)->GetDefault(&result));
        return winrt::Windows::Devices::Sensors::SimpleOrientationSensor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics2<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>) consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IWakeOnApproachOptions<D>::AllowWhenExternalDisplayConnected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IWakeOnApproachOptions)->get_AllowWhenExternalDisplayConnected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IWakeOnApproachOptions<D>::AllowWhenExternalDisplayConnected(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IWakeOnApproachOptions)->put_AllowWhenExternalDisplayConnected(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Sensors_IWakeOnApproachOptions<D>::DisableWhenBatterySaverOn() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IWakeOnApproachOptions)->get_DisableWhenBatterySaverOn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_IWakeOnApproachOptions<D>::DisableWhenBatterySaverOn(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::IWakeOnApproachOptions)->put_DisableWhenBatterySaverOn(value));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometer> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometer>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::AccelerometerReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Shaken(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Shaken(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Accelerometer, winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Shaken(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Shaken(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometer2> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometer2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometer3> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometer3>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometer4> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometer4>
    {
        int32_t __stdcall get_ReadingType(int32_t* type) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *type = detach_from<winrt::Windows::Devices::Sensors::AccelerometerReadingType>(this->shim().ReadingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometer5> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometer5>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::AccelerometerDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold>
    {
        int32_t __stdcall get_XAxisInGForce(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().XAxisInGForce());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XAxisInGForce(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XAxisInGForce(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YAxisInGForce(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().YAxisInGForce());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_YAxisInGForce(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().YAxisInGForce(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZAxisInGForce(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ZAxisInGForce());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ZAxisInGForce(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ZAxisInGForce(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerReading> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccelerationX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AccelerationX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccelerationY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AccelerationY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccelerationZ(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AccelerationZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::AccelerometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Accelerometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerStatics2>
    {
        int32_t __stdcall GetDefaultWithAccelerometerReadingType(int32_t readingType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Accelerometer>(this->shim().GetDefault(*reinterpret_cast<winrt::Windows::Devices::Sensors::AccelerometerReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAccelerometerStatics3> : produce_base<D, winrt::Windows::Devices::Sensors::IAccelerometerStatics3>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Accelerometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(int32_t readingType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::Sensors::AccelerometerReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IActivitySensor> : produce_base<D, winrt::Windows::Devices::Sensors::IActivitySensor>
    {
        int32_t __stdcall GetCurrentReadingAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensorReading>>(this->shim().GetCurrentReadingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubscribedActivities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Sensors::ActivityType>>(this->shim().SubscribedActivities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PowerInMilliwatts(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PowerInMilliwatts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedActivities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivityType>>(this->shim().SupportedActivities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ActivitySensor, winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IActivitySensorReading> : produce_base<D, winrt::Windows::Devices::Sensors::IActivitySensorReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Activity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::ActivityType>(this->shim().Activity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Confidence(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::ActivitySensorReadingConfidence>(this->shim().Confidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport> : produce_base<D, winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::ActivitySensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::ActivitySensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IActivitySensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IActivitySensorStatics>
    {
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>>(this->shim().GetDefaultAsync());
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
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSystemHistoryAsync(int64_t fromTime, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&fromTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSystemHistoryWithDurationAsync(int64_t fromTime, int64_t duration, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&fromTime), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails> : produce_base<D, winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails>
    {
        int32_t __stdcall ReadReports(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport>>(this->shim().ReadReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions> : produce_base<D, winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions>
    {
        int32_t __stdcall get_AllowWhenExternalDisplayConnected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWhenExternalDisplayConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWhenExternalDisplayConnected(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWhenExternalDisplayConnected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAltimeter> : produce_base<D, winrt::Windows::Devices::Sensors::IAltimeter>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::AltimeterReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Altimeter, winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAltimeter2> : produce_base<D, winrt::Windows::Devices::Sensors::IAltimeter2>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAltimeterReading> : produce_base<D, winrt::Windows::Devices::Sensors::IAltimeterReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AltitudeChangeInMeters(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AltitudeChangeInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAltimeterReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IAltimeterReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::AltimeterReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IAltimeterStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IAltimeterStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Altimeter>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometer> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometer>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::BarometerReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Barometer, winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometer2> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometer2>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometer3> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometer3>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::BarometerDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometerDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometerDataThreshold>
    {
        int32_t __stdcall get_Hectopascals(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Hectopascals());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Hectopascals(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hectopascals(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometerReading> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometerReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StationPressureInHectopascals(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().StationPressureInHectopascals());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometerReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometerReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::BarometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometerStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Barometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IBarometerStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IBarometerStatics2>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Barometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompass> : produce_base<D, winrt::Windows::Devices::Sensors::ICompass>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::CompassReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Compass, winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompass2> : produce_base<D, winrt::Windows::Devices::Sensors::ICompass2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompass3> : produce_base<D, winrt::Windows::Devices::Sensors::ICompass3>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompass4> : produce_base<D, winrt::Windows::Devices::Sensors::ICompass4>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::CompassDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassDataThreshold>
    {
        int32_t __stdcall get_Degrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Degrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Degrees(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Degrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassReading> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeadingMagneticNorth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HeadingMagneticNorth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeadingTrueNorth(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().HeadingTrueNorth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassReading2> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::CompassReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy>
    {
        int32_t __stdcall get_HeadingAccuracy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().HeadingAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassStatics> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Compass>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ICompassStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::ICompassStatics2>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Compass>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometer> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometer>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::GyrometerReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Gyrometer, winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometer2> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometer2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometer3> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometer3>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometer4> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometer4>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::GyrometerDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerDataThreshold>
    {
        int32_t __stdcall get_XAxisInDegreesPerSecond(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().XAxisInDegreesPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XAxisInDegreesPerSecond(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XAxisInDegreesPerSecond(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YAxisInDegreesPerSecond(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().YAxisInDegreesPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_YAxisInDegreesPerSecond(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().YAxisInDegreesPerSecond(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZAxisInDegreesPerSecond(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ZAxisInDegreesPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ZAxisInDegreesPerSecond(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ZAxisInDegreesPerSecond(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerReading> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AngularVelocityX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AngularVelocityX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AngularVelocityY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AngularVelocityY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AngularVelocityZ(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AngularVelocityZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::GyrometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Gyrometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IGyrometerStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IGyrometerStatics2>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Gyrometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHingeAngleReading> : produce_base<D, winrt::Windows::Devices::Sensors::IHingeAngleReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AngleInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AngleInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHingeAngleSensor> : produce_base<D, winrt::Windows::Devices::Sensors::IHingeAngleSensor>
    {
        int32_t __stdcall GetCurrentReadingAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleReading>>(this->shim().GetCurrentReadingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinReportThresholdInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinReportThresholdInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportThresholdInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ReportThresholdInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportThresholdInDegrees(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportThresholdInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HingeAngleSensor, winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::HingeAngleReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRelatedToAdjacentPanelsAsync(void* firstPanelId, void* secondPanelId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>>(this->shim().GetRelatedToAdjacentPanelsAsync(*reinterpret_cast<hstring const*>(&firstPanelId), *reinterpret_cast<hstring const*>(&secondPanelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceFeatures> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceFeatures>
    {
        int32_t __stdcall get_SensorId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SensorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedWakeOrLockDistancesInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedWakeOrLockDistancesInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsWakeOnApproachSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsWakeOnApproachSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLockOnLeaveSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLockOnLeaveSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAttentionAwareDimmingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAttentionAwareDimmingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2>
    {
        int32_t __stdcall get_IsAdaptiveDimmingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAdaptiveDimmingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensor> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensor>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxDetectableDistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().MaxDetectableDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinDetectableDistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().MinDetectableDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentReading(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::HumanPresenceSensor, winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensor2> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensor2>
    {
        int32_t __stdcall get_IsPresenceSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPresenceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEngagementSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEngagementSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension>
    {
        int32_t __stdcall Initialize(void* deviceInterface) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Initialize(*reinterpret_cast<hstring const*>(&deviceInterface));
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
        int32_t __stdcall ProcessReading(void* reading, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate>(this->shim().ProcessReading(*reinterpret_cast<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading const*>(&reading)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessReadingTimeoutExpired(void* reading) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessReadingTimeoutExpired(*reinterpret_cast<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading const*>(&reading));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Uninitialize() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uninitialize();
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Presence(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::HumanPresence>(this->shim().Presence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Engagement(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::HumanEngagement>(this->shim().Engagement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().DistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2>
    {
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate>
    {
        int32_t __stdcall get_Timestamp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Timestamp(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Timestamp(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Presence(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence>>(this->shim().Presence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Presence(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Presence(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanPresence> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Engagement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement>>(this->shim().Engagement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Engagement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Engagement(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Sensors::HumanEngagement> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().DistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DistanceInMillimeters(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DistanceInMillimeters(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* sensorId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2>
    {
        int32_t __stdcall FromId(void* sensorId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceSensor>(this->shim().FromId(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSettings> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSettings>
    {
        int32_t __stdcall get_SensorId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SensorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SensorId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SensorId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsWakeOnApproachEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsWakeOnApproachEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsWakeOnApproachEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsWakeOnApproachEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WakeOnApproachDistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().WakeOnApproachDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WakeOnApproachDistanceInMillimeters(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WakeOnApproachDistanceInMillimeters(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLockOnLeaveEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLockOnLeaveEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsLockOnLeaveEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLockOnLeaveEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LockOnLeaveDistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().LockOnLeaveDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LockOnLeaveDistanceInMillimeters(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LockOnLeaveDistanceInMillimeters(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LockOnLeaveTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().LockOnLeaveTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LockOnLeaveTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LockOnLeaveTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAttentionAwareDimmingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAttentionAwareDimmingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAttentionAwareDimmingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAttentionAwareDimmingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSettings2> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSettings2>
    {
        int32_t __stdcall get_IsAdaptiveDimmingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAdaptiveDimmingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAdaptiveDimmingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAdaptiveDimmingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WakeOptions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::WakeOnApproachOptions>(this->shim().WakeOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DimmingOptions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions>(this->shim().DimmingOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LockOptions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::LockOnLeaveOptions>(this->shim().LockOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>
    {
        int32_t __stdcall GetCurrentSettingsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSettings>>(this->shim().GetCurrentSettingsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentSettings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateSettingsAsync(void* settings, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UpdateSettingsAsync(*reinterpret_cast<winrt::Windows::Devices::Sensors::HumanPresenceSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateSettings(void* settings) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateSettings(*reinterpret_cast<winrt::Windows::Devices::Sensors::HumanPresenceSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedFeaturesForSensorIdAsync(void* sensorId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>>(this->shim().GetSupportedFeaturesForSensorIdAsync(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedFeaturesForSensorId(void* sensorId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::HumanPresenceFeatures>(this->shim().GetSupportedFeaturesForSensorId(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedLockOnLeaveTimeouts(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::TimeSpan>>(this->shim().GetSupportedLockOnLeaveTimeouts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SettingsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SettingsChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SettingsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SettingsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometer> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometer>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::InclinometerReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Inclinometer, winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometer2> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometer2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingType(int32_t* type) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *type = detach_from<winrt::Windows::Devices::Sensors::SensorReadingType>(this->shim().ReadingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometer3> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometer3>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometer4> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometer4>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::InclinometerDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerDataThreshold>
    {
        int32_t __stdcall get_PitchInDegrees(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().PitchInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PitchInDegrees(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PitchInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RollInDegrees(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().RollInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RollInDegrees(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RollInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YawInDegrees(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().YawInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_YawInDegrees(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().YawInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerReading> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PitchDegrees(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().PitchDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RollDegrees(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().RollDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YawDegrees(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().YawDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::InclinometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy>
    {
        int32_t __stdcall get_YawAccuracy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().YawAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Inclinometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerStatics2>
    {
        int32_t __stdcall GetDefaultForRelativeReadings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Inclinometer>(this->shim().GetDefaultForRelativeReadings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerStatics3> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerStatics3>
    {
        int32_t __stdcall GetDefaultWithSensorReadingType(int32_t sensorReadingtype, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Inclinometer>(this->shim().GetDefault(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorReadingType const*>(&sensorReadingtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IInclinometerStatics4> : produce_base<D, winrt::Windows::Devices::Sensors::IInclinometerStatics4>
    {
        int32_t __stdcall GetDeviceSelector(int32_t readingType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Inclinometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensor> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensor>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::LightSensorReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::LightSensor, winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensor2> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensor2>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensor3> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensor3>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::LightSensorDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorDataThreshold>
    {
        int32_t __stdcall get_LuxPercentage(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().LuxPercentage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LuxPercentage(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LuxPercentage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AbsoluteLux(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().AbsoluteLux());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AbsoluteLux(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AbsoluteLux(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorReading> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IlluminanceInLux(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().IlluminanceInLux());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorReading2> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::LightSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::LightSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILightSensorStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::ILightSensorStatics2>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::LightSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ILockOnLeaveOptions> : produce_base<D, winrt::Windows::Devices::Sensors::ILockOnLeaveOptions>
    {
        int32_t __stdcall get_AllowWhenExternalDisplayConnected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWhenExternalDisplayConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWhenExternalDisplayConnected(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWhenExternalDisplayConnected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometer> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometer>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Magnetometer, winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometer2> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometer2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometer3> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometer3>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometer4> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometer4>
    {
        int32_t __stdcall get_ReportThreshold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerDataThreshold>(this->shim().ReportThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold>
    {
        int32_t __stdcall get_XAxisMicroteslas(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().XAxisMicroteslas());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_XAxisMicroteslas(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().XAxisMicroteslas(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YAxisMicroteslas(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().YAxisMicroteslas());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_YAxisMicroteslas(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().YAxisMicroteslas(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZAxisMicroteslas(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().ZAxisMicroteslas());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ZAxisMicroteslas(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ZAxisMicroteslas(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerReading> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MagneticFieldX(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MagneticFieldX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MagneticFieldY(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MagneticFieldY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MagneticFieldZ(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MagneticFieldZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DirectionalAccuracy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().DirectionalAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::Magnetometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IMagnetometerStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IMagnetometerStatics2>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Magnetometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensor> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensor>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::OrientationSensorReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::OrientationSensor, winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensor2> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensor2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingType(int32_t* type) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *type = detach_from<winrt::Windows::Devices::Sensors::SensorReadingType>(this->shim().ReadingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensor3> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensor3>
    {
        int32_t __stdcall put_ReportLatency(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportLatency(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxBatchSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorReading> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RotationMatrix(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SensorRotationMatrix>(this->shim().RotationMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Quaternion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SensorQuaternion>(this->shim().Quaternion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorReading2> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::OrientationSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy>
    {
        int32_t __stdcall get_YawAccuracy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().YawAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics2>
    {
        int32_t __stdcall GetDefaultForRelativeReadings(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefaultForRelativeReadings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics3> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics3>
    {
        int32_t __stdcall GetDefaultWithSensorReadingType(int32_t sensorReadingtype, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefault(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorReadingType const*>(&sensorReadingtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultWithSensorReadingTypeAndSensorOptimizationGoal(int32_t sensorReadingType, int32_t optimizationGoal, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefault(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorReadingType const*>(&sensorReadingType), *reinterpret_cast<winrt::Windows::Devices::Sensors::SensorOptimizationGoal const*>(&optimizationGoal)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics4> : produce_base<D, winrt::Windows::Devices::Sensors::IOrientationSensorStatics4>
    {
        int32_t __stdcall GetDeviceSelector(int32_t readingType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorWithSensorReadingTypeAndSensorOptimizationGoal(int32_t readingType, int32_t optimizationGoal, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorReadingType const*>(&readingType), *reinterpret_cast<winrt::Windows::Devices::Sensors::SensorOptimizationGoal const*>(&optimizationGoal)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::OrientationSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometer> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometer>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PowerInMilliwatts(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PowerInMilliwatts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinimumReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReportInterval(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReportInterval(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Pedometer, winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometer2> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometer2>
    {
        int32_t __stdcall GetCurrentReadings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::Windows::Devices::Sensors::PedometerStepKind, winrt::Windows::Devices::Sensors::PedometerReading>>(this->shim().GetCurrentReadings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory>
    {
        int32_t __stdcall Create(void* sensor, int32_t stepGoal, void** threshold) noexcept final try
        {
            clear_abi(threshold);
            typename D::abi_guard guard(this->shim());
            *threshold = detach_from<winrt::Windows::Devices::Sensors::PedometerDataThreshold>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Sensors::Pedometer const*>(&sensor), stepGoal));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometerReading> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometerReading>
    {
        int32_t __stdcall get_StepKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::PedometerStepKind>(this->shim().StepKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CumulativeSteps(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CumulativeSteps());
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
        int32_t __stdcall get_CumulativeStepsDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().CumulativeStepsDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::PedometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometerStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometerStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>>(this->shim().GetDefaultAsync());
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
        int32_t __stdcall GetSystemHistoryAsync(int64_t fromTime, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&fromTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSystemHistoryWithDurationAsync(int64_t fromTime, int64_t duration, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&fromTime), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IPedometerStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IPedometerStatics2>
    {
        int32_t __stdcall GetReadingsFromTriggerDetails(void* triggerDetails, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::PedometerReading>>(this->shim().GetReadingsFromTriggerDetails(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const*>(&triggerDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IProximitySensor> : produce_base<D, winrt::Windows::Devices::Sensors::IProximitySensor>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxDistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().MaxDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinDistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().MinDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::ProximitySensorReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::ProximitySensor, winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReadingChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall CreateDisplayOnOffController(void** controller) noexcept final try
        {
            clear_abi(controller);
            typename D::abi_guard guard(this->shim());
            *controller = detach_from<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController>(this->shim().CreateDisplayOnOffController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory> : produce_base<D, winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>
    {
        int32_t __stdcall Create(void* sensor, void** threshold) noexcept final try
        {
            clear_abi(threshold);
            typename D::abi_guard guard(this->shim());
            *threshold = detach_from<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Sensors::ProximitySensor const*>(&sensor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IProximitySensorReading> : produce_base<D, winrt::Windows::Devices::Sensors::IProximitySensorReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDetected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDetected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceInMillimeters(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().DistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::ProximitySensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IProximitySensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::IProximitySensorStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromId(void* sensorId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::ProximitySensor>(this->shim().FromId(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IProximitySensorStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::IProximitySensorStatics2>
    {
        int32_t __stdcall GetReadingsFromTriggerDetails(void* triggerDetails, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Sensors::ProximitySensorReading>>(this->shim().GetReadingsFromTriggerDetails(*reinterpret_cast<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const*>(&triggerDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISensorDataThreshold> : produce_base<D, winrt::Windows::Devices::Sensors::ISensorDataThreshold>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails> : produce_base<D, winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SensorType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SensorType>(this->shim().SensorType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISensorQuaternion> : produce_base<D, winrt::Windows::Devices::Sensors::ISensorQuaternion>
    {
        int32_t __stdcall get_W(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().W());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_X(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().X());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Y(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Y());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Z(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Z());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISensorRotationMatrix> : produce_base<D, winrt::Windows::Devices::Sensors::ISensorRotationMatrix>
    {
        int32_t __stdcall get_M11(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M11());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M12(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M13(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M13());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M21(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M21());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M22(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M22());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M23(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M23());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M31(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M31());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M32(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M32());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_M33(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().M33());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensor> : produce_base<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensor>
    {
        int32_t __stdcall GetCurrentOrientation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SimpleOrientation>(this->shim().GetCurrentOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_OrientationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OrientationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::SimpleOrientationSensor, winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OrientationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OrientationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2> : produce_base<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2>
    {
        int32_t __stdcall put_ReadingTransform(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadingTransform(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadingTransform(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId> : produce_base<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::SimpleOrientation>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2> : produce_base<D, winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>
    {
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::SimpleOrientationSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::IWakeOnApproachOptions> : produce_base<D, winrt::Windows::Devices::Sensors::IWakeOnApproachOptions>
    {
        int32_t __stdcall get_AllowWhenExternalDisplayConnected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowWhenExternalDisplayConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowWhenExternalDisplayConnected(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowWhenExternalDisplayConnected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisableWhenBatterySaverOn(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DisableWhenBatterySaverOn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisableWhenBatterySaverOn(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisableWhenBatterySaverOn(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Sensors
{
    inline auto Accelerometer::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Accelerometer(*)(IAccelerometerStatics const&), Accelerometer, IAccelerometerStatics>([](IAccelerometerStatics const& f) { return f.GetDefault(); });
    }
    inline auto Accelerometer::GetDefault(winrt::Windows::Devices::Sensors::AccelerometerReadingType const& readingType)
    {
        return impl::call_factory<Accelerometer, IAccelerometerStatics2>([&](IAccelerometerStatics2 const& f) { return f.GetDefault(readingType); });
    }
    inline auto Accelerometer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Accelerometer, IAccelerometerStatics3>([&](IAccelerometerStatics3 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Accelerometer::GetDeviceSelector(winrt::Windows::Devices::Sensors::AccelerometerReadingType const& readingType)
    {
        return impl::call_factory<Accelerometer, IAccelerometerStatics3>([&](IAccelerometerStatics3 const& f) { return f.GetDeviceSelector(readingType); });
    }
    inline auto ActivitySensor::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::ActivitySensor>(*)(IActivitySensorStatics const&), ActivitySensor, IActivitySensorStatics>([](IActivitySensorStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto ActivitySensor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IActivitySensorStatics const&), ActivitySensor, IActivitySensorStatics>([](IActivitySensorStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto ActivitySensor::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<ActivitySensor, IActivitySensorStatics>([&](IActivitySensorStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto ActivitySensor::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime)
    {
        return impl::call_factory<ActivitySensor, IActivitySensorStatics>([&](IActivitySensorStatics const& f) { return f.GetSystemHistoryAsync(fromTime); });
    }
    inline auto ActivitySensor::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime, winrt::Windows::Foundation::TimeSpan const& duration)
    {
        return impl::call_factory<ActivitySensor, IActivitySensorStatics>([&](IActivitySensorStatics const& f) { return f.GetSystemHistoryAsync(fromTime, duration); });
    }
    inline auto Altimeter::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Altimeter(*)(IAltimeterStatics const&), Altimeter, IAltimeterStatics>([](IAltimeterStatics const& f) { return f.GetDefault(); });
    }
    inline auto Barometer::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Barometer(*)(IBarometerStatics const&), Barometer, IBarometerStatics>([](IBarometerStatics const& f) { return f.GetDefault(); });
    }
    inline auto Barometer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Barometer, IBarometerStatics2>([&](IBarometerStatics2 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Barometer::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IBarometerStatics2 const&), Barometer, IBarometerStatics2>([](IBarometerStatics2 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Compass::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Compass(*)(ICompassStatics const&), Compass, ICompassStatics>([](ICompassStatics const& f) { return f.GetDefault(); });
    }
    inline auto Compass::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ICompassStatics2 const&), Compass, ICompassStatics2>([](ICompassStatics2 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Compass::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Compass, ICompassStatics2>([&](ICompassStatics2 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Gyrometer::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Gyrometer(*)(IGyrometerStatics const&), Gyrometer, IGyrometerStatics>([](IGyrometerStatics const& f) { return f.GetDefault(); });
    }
    inline auto Gyrometer::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IGyrometerStatics2 const&), Gyrometer, IGyrometerStatics2>([](IGyrometerStatics2 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Gyrometer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Gyrometer, IGyrometerStatics2>([&](IGyrometerStatics2 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto HingeAngleSensor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IHingeAngleSensorStatics const&), HingeAngleSensor, IHingeAngleSensorStatics>([](IHingeAngleSensorStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto HingeAngleSensor::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HingeAngleSensor>(*)(IHingeAngleSensorStatics const&), HingeAngleSensor, IHingeAngleSensorStatics>([](IHingeAngleSensorStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto HingeAngleSensor::GetRelatedToAdjacentPanelsAsync(param::hstring const& firstPanelId, param::hstring const& secondPanelId)
    {
        return impl::call_factory<HingeAngleSensor, IHingeAngleSensorStatics>([&](IHingeAngleSensorStatics const& f) { return f.GetRelatedToAdjacentPanelsAsync(firstPanelId, secondPanelId); });
    }
    inline auto HingeAngleSensor::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<HingeAngleSensor, IHingeAngleSensorStatics>([&](IHingeAngleSensorStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto HumanPresenceSensor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IHumanPresenceSensorStatics const&), HumanPresenceSensor, IHumanPresenceSensorStatics>([](IHumanPresenceSensorStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto HumanPresenceSensor::FromIdAsync(param::hstring const& sensorId)
    {
        return impl::call_factory<HumanPresenceSensor, IHumanPresenceSensorStatics>([&](IHumanPresenceSensorStatics const& f) { return f.FromIdAsync(sensorId); });
    }
    inline auto HumanPresenceSensor::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSensor>(*)(IHumanPresenceSensorStatics const&), HumanPresenceSensor, IHumanPresenceSensorStatics>([](IHumanPresenceSensorStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto HumanPresenceSensor::FromId(param::hstring const& sensorId)
    {
        return impl::call_factory<HumanPresenceSensor, IHumanPresenceSensorStatics2>([&](IHumanPresenceSensorStatics2 const& f) { return f.FromId(sensorId); });
    }
    inline auto HumanPresenceSensor::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::HumanPresenceSensor(*)(IHumanPresenceSensorStatics2 const&), HumanPresenceSensor, IHumanPresenceSensorStatics2>([](IHumanPresenceSensorStatics2 const& f) { return f.GetDefault(); });
    }
    inline HumanPresenceSensorReadingUpdate::HumanPresenceSensorReadingUpdate() :
        HumanPresenceSensorReadingUpdate(impl::call_factory_cast<HumanPresenceSensorReadingUpdate(*)(winrt::Windows::Foundation::IActivationFactory const&), HumanPresenceSensorReadingUpdate>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<HumanPresenceSensorReadingUpdate>(); }))
    {
    }
    inline auto HumanPresenceSettings::GetCurrentSettingsAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::HumanPresenceSettings>(*)(IHumanPresenceSettingsStatics const&), HumanPresenceSettings, IHumanPresenceSettingsStatics>([](IHumanPresenceSettingsStatics const& f) { return f.GetCurrentSettingsAsync(); });
    }
    inline auto HumanPresenceSettings::GetCurrentSettings()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::HumanPresenceSettings(*)(IHumanPresenceSettingsStatics const&), HumanPresenceSettings, IHumanPresenceSettingsStatics>([](IHumanPresenceSettingsStatics const& f) { return f.GetCurrentSettings(); });
    }
    inline auto HumanPresenceSettings::UpdateSettingsAsync(winrt::Windows::Devices::Sensors::HumanPresenceSettings const& settings)
    {
        return impl::call_factory<HumanPresenceSettings, IHumanPresenceSettingsStatics>([&](IHumanPresenceSettingsStatics const& f) { return f.UpdateSettingsAsync(settings); });
    }
    inline auto HumanPresenceSettings::UpdateSettings(winrt::Windows::Devices::Sensors::HumanPresenceSettings const& settings)
    {
        impl::call_factory<HumanPresenceSettings, IHumanPresenceSettingsStatics>([&](IHumanPresenceSettingsStatics const& f) { return f.UpdateSettings(settings); });
    }
    inline auto HumanPresenceSettings::GetSupportedFeaturesForSensorIdAsync(param::hstring const& sensorId)
    {
        return impl::call_factory<HumanPresenceSettings, IHumanPresenceSettingsStatics>([&](IHumanPresenceSettingsStatics const& f) { return f.GetSupportedFeaturesForSensorIdAsync(sensorId); });
    }
    inline auto HumanPresenceSettings::GetSupportedFeaturesForSensorId(param::hstring const& sensorId)
    {
        return impl::call_factory<HumanPresenceSettings, IHumanPresenceSettingsStatics>([&](IHumanPresenceSettingsStatics const& f) { return f.GetSupportedFeaturesForSensorId(sensorId); });
    }
    inline auto HumanPresenceSettings::GetSupportedLockOnLeaveTimeouts()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::TimeSpan>(*)(IHumanPresenceSettingsStatics const&), HumanPresenceSettings, IHumanPresenceSettingsStatics>([](IHumanPresenceSettingsStatics const& f) { return f.GetSupportedLockOnLeaveTimeouts(); });
    }
    inline auto HumanPresenceSettings::SettingsChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<HumanPresenceSettings, IHumanPresenceSettingsStatics>([&](IHumanPresenceSettingsStatics const& f) { return f.SettingsChanged(handler); });
    }
    inline HumanPresenceSettings::SettingsChanged_revoker HumanPresenceSettings::SettingsChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<HumanPresenceSettings, winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics>();
        return { f, f.SettingsChanged(handler) };
    }
    inline auto HumanPresenceSettings::SettingsChanged(winrt::event_token const& token)
    {
        impl::call_factory<HumanPresenceSettings, IHumanPresenceSettingsStatics>([&](IHumanPresenceSettingsStatics const& f) { return f.SettingsChanged(token); });
    }
    inline auto Inclinometer::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Inclinometer(*)(IInclinometerStatics const&), Inclinometer, IInclinometerStatics>([](IInclinometerStatics const& f) { return f.GetDefault(); });
    }
    inline auto Inclinometer::GetDefaultForRelativeReadings()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Inclinometer(*)(IInclinometerStatics2 const&), Inclinometer, IInclinometerStatics2>([](IInclinometerStatics2 const& f) { return f.GetDefaultForRelativeReadings(); });
    }
    inline auto Inclinometer::GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype)
    {
        return impl::call_factory<Inclinometer, IInclinometerStatics3>([&](IInclinometerStatics3 const& f) { return f.GetDefault(sensorReadingtype); });
    }
    inline auto Inclinometer::GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType)
    {
        return impl::call_factory<Inclinometer, IInclinometerStatics4>([&](IInclinometerStatics4 const& f) { return f.GetDeviceSelector(readingType); });
    }
    inline auto Inclinometer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Inclinometer, IInclinometerStatics4>([&](IInclinometerStatics4 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto LightSensor::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::LightSensor(*)(ILightSensorStatics const&), LightSensor, ILightSensorStatics>([](ILightSensorStatics const& f) { return f.GetDefault(); });
    }
    inline auto LightSensor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ILightSensorStatics2 const&), LightSensor, ILightSensorStatics2>([](ILightSensorStatics2 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto LightSensor::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<LightSensor, ILightSensorStatics2>([&](ILightSensorStatics2 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Magnetometer::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::Magnetometer(*)(IMagnetometerStatics const&), Magnetometer, IMagnetometerStatics>([](IMagnetometerStatics const& f) { return f.GetDefault(); });
    }
    inline auto Magnetometer::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IMagnetometerStatics2 const&), Magnetometer, IMagnetometerStatics2>([](IMagnetometerStatics2 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Magnetometer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Magnetometer, IMagnetometerStatics2>([&](IMagnetometerStatics2 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto OrientationSensor::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::OrientationSensor(*)(IOrientationSensorStatics const&), OrientationSensor, IOrientationSensorStatics>([](IOrientationSensorStatics const& f) { return f.GetDefault(); });
    }
    inline auto OrientationSensor::GetDefaultForRelativeReadings()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::OrientationSensor(*)(IOrientationSensorStatics2 const&), OrientationSensor, IOrientationSensorStatics2>([](IOrientationSensorStatics2 const& f) { return f.GetDefaultForRelativeReadings(); });
    }
    inline auto OrientationSensor::GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype)
    {
        return impl::call_factory<OrientationSensor, IOrientationSensorStatics3>([&](IOrientationSensorStatics3 const& f) { return f.GetDefault(sensorReadingtype); });
    }
    inline auto OrientationSensor::GetDefault(winrt::Windows::Devices::Sensors::SensorReadingType const& sensorReadingType, winrt::Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal)
    {
        return impl::call_factory<OrientationSensor, IOrientationSensorStatics3>([&](IOrientationSensorStatics3 const& f) { return f.GetDefault(sensorReadingType, optimizationGoal); });
    }
    inline auto OrientationSensor::GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType)
    {
        return impl::call_factory<OrientationSensor, IOrientationSensorStatics4>([&](IOrientationSensorStatics4 const& f) { return f.GetDeviceSelector(readingType); });
    }
    inline auto OrientationSensor::GetDeviceSelector(winrt::Windows::Devices::Sensors::SensorReadingType const& readingType, winrt::Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal)
    {
        return impl::call_factory<OrientationSensor, IOrientationSensorStatics4>([&](IOrientationSensorStatics4 const& f) { return f.GetDeviceSelector(readingType, optimizationGoal); });
    }
    inline auto OrientationSensor::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<OrientationSensor, IOrientationSensorStatics4>([&](IOrientationSensorStatics4 const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Pedometer::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Pedometer, IPedometerStatics>([&](IPedometerStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Pedometer::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Pedometer>(*)(IPedometerStatics const&), Pedometer, IPedometerStatics>([](IPedometerStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto Pedometer::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IPedometerStatics const&), Pedometer, IPedometerStatics>([](IPedometerStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Pedometer::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime)
    {
        return impl::call_factory<Pedometer, IPedometerStatics>([&](IPedometerStatics const& f) { return f.GetSystemHistoryAsync(fromTime); });
    }
    inline auto Pedometer::GetSystemHistoryAsync(winrt::Windows::Foundation::DateTime const& fromTime, winrt::Windows::Foundation::TimeSpan const& duration)
    {
        return impl::call_factory<Pedometer, IPedometerStatics>([&](IPedometerStatics const& f) { return f.GetSystemHistoryAsync(fromTime, duration); });
    }
    inline auto Pedometer::GetReadingsFromTriggerDetails(winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails)
    {
        return impl::call_factory<Pedometer, IPedometerStatics2>([&](IPedometerStatics2 const& f) { return f.GetReadingsFromTriggerDetails(triggerDetails); });
    }
    inline PedometerDataThreshold::PedometerDataThreshold(winrt::Windows::Devices::Sensors::Pedometer const& sensor, int32_t stepGoal) :
        PedometerDataThreshold(impl::call_factory<PedometerDataThreshold, IPedometerDataThresholdFactory>([&](IPedometerDataThresholdFactory const& f) { return f.Create(sensor, stepGoal); }))
    {
    }
    inline auto ProximitySensor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IProximitySensorStatics const&), ProximitySensor, IProximitySensorStatics>([](IProximitySensorStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto ProximitySensor::FromId(param::hstring const& sensorId)
    {
        return impl::call_factory<ProximitySensor, IProximitySensorStatics>([&](IProximitySensorStatics const& f) { return f.FromId(sensorId); });
    }
    inline auto ProximitySensor::GetReadingsFromTriggerDetails(winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails)
    {
        return impl::call_factory<ProximitySensor, IProximitySensorStatics2>([&](IProximitySensorStatics2 const& f) { return f.GetReadingsFromTriggerDetails(triggerDetails); });
    }
    inline ProximitySensorDataThreshold::ProximitySensorDataThreshold(winrt::Windows::Devices::Sensors::ProximitySensor const& sensor) :
        ProximitySensorDataThreshold(impl::call_factory<ProximitySensorDataThreshold, IProximitySensorDataThresholdFactory>([&](IProximitySensorDataThresholdFactory const& f) { return f.Create(sensor); }))
    {
    }
    inline auto SimpleOrientationSensor::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Sensors::SimpleOrientationSensor(*)(ISimpleOrientationSensorStatics const&), SimpleOrientationSensor, ISimpleOrientationSensorStatics>([](ISimpleOrientationSensorStatics const& f) { return f.GetDefault(); });
    }
    inline auto SimpleOrientationSensor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ISimpleOrientationSensorStatics2 const&), SimpleOrientationSensor, ISimpleOrientationSensorStatics2>([](ISimpleOrientationSensorStatics2 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto SimpleOrientationSensor::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<SimpleOrientationSensor, ISimpleOrientationSensorStatics2>([&](ISimpleOrientationSensorStatics2 const& f) { return f.FromIdAsync(deviceId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAdaptiveDimmingOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompass> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompass2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompass3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompass4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ICompassStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceFeatures2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorReadingUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSensorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IHumanPresenceSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensor3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ILockOnLeaveOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensor3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISensorDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISensorQuaternion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISensorRotationMatrix> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::IWakeOnApproachOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Accelerometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AdaptiveDimmingOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Altimeter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AltimeterReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Barometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::BarometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::BarometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Compass> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::CompassDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::CompassReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Gyrometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::GyrometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::GyrometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HingeAngleReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HingeAngleSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HumanPresenceFeatures> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HumanPresenceSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HumanPresenceSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HumanPresenceSensorReadingUpdate> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::HumanPresenceSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Inclinometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::InclinometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::InclinometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::LightSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::LightSensorDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::LightSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::LockOnLeaveOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Magnetometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::MagnetometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::MagnetometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::OrientationSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::OrientationSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Pedometer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::PedometerDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::PedometerReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::SensorQuaternion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::SensorRotationMatrix> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::SimpleOrientationSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::WakeOnApproachOptions> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
