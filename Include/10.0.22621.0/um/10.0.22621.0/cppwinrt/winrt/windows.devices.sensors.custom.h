// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Sensors_Custom_H
#define WINRT_Windows_Devices_Sensors_Custom_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Sensors.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Sensors.Custom.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Custom::CustomSensorReading) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::GetCurrentReading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->GetCurrentReading(&value));
        return winrt::Windows::Devices::Sensors::Custom::CustomSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::MinimumReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->get_MinimumReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReportInterval(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->put_ReportInterval(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReportInterval() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->get_ReportInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Custom::CustomSensor, winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->add_ReadingChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Custom::CustomSensor, winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor)->remove_ReadingChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>::ReportLatency(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor2)->put_ReportLatency(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>::ReportLatency() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor2)->get_ReportLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>::MaxBatchSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensor2)->get_MaxBatchSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Sensors_Custom_ICustomSensorReading<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Devices_Sensors_Custom_ICustomSensorReading<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Sensors_Custom_ICustomSensorReading2<D>::PerformanceCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2)->get_PerformanceCount(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Custom::CustomSensorReading) consume_Windows_Devices_Sensors_Custom_ICustomSensorReadingChangedEventArgs<D>::Reading() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs)->get_Reading(&value));
        return winrt::Windows::Devices::Sensors::Custom::CustomSensorReading{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Sensors_Custom_ICustomSensorStatics<D>::GetDeviceSelector(winrt::guid const& interfaceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics)->GetDeviceSelector(impl::bind_in(interfaceId), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Custom::CustomSensor>) consume_Windows_Devices_Sensors_Custom_ICustomSensorStatics<D>::FromIdAsync(param::hstring const& sensorId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics)->FromIdAsync(*(void**)(&sensorId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Custom::CustomSensor>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensor> : produce_base<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensor>
    {
        int32_t __stdcall GetCurrentReading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading>(this->shim().GetCurrentReading());
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
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Custom::CustomSensor, winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const*>(&handler)));
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
    struct produce<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensor2> : produce_base<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensor2>
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
    struct produce<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading> : produce_base<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
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
    struct produce<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2> : produce_base<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2>
    {
        int32_t __stdcall get_PerformanceCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs>
    {
        int32_t __stdcall get_Reading(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics> : produce_base<D, winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics>
    {
        int32_t __stdcall GetDeviceSelector(winrt::guid interfaceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::guid const*>(&interfaceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* sensorId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Custom::CustomSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Sensors::Custom
{
    inline auto CustomSensor::GetDeviceSelector(winrt::guid const& interfaceId)
    {
        return impl::call_factory<CustomSensor, ICustomSensorStatics>([&](ICustomSensorStatics const& f) { return f.GetDeviceSelector(interfaceId); });
    }
    inline auto CustomSensor::FromIdAsync(param::hstring const& sensorId)
    {
        return impl::call_factory<CustomSensor, ICustomSensorStatics>([&](ICustomSensorStatics const& f) { return f.FromIdAsync(sensorId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::CustomSensor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
