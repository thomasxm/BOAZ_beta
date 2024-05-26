// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Power_H
#define WINRT_Windows_Devices_Power_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Power.2.h"
#include "winrt/impl/Windows.Devices.Power.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Power_IBattery<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBattery)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Power::BatteryReport) consume_Windows_Devices_Power_IBattery<D>::GetReport() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBattery)->GetReport(&result));
        return winrt::Windows::Devices::Power::BatteryReport{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Power_IBattery<D>::ReportUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Power::Battery, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBattery)->add_ReportUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Power_IBattery<D>::ReportUpdated_revoker consume_Windows_Devices_Power_IBattery<D>::ReportUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Power::Battery, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ReportUpdated_revoker>(this, ReportUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Power_IBattery<D>::ReportUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBattery)->remove_ReportUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Devices_Power_IBatteryReport<D>::ChargeRateInMilliwatts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryReport)->get_ChargeRateInMilliwatts(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Devices_Power_IBatteryReport<D>::DesignCapacityInMilliwattHours() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryReport)->get_DesignCapacityInMilliwattHours(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Devices_Power_IBatteryReport<D>::FullChargeCapacityInMilliwattHours() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryReport)->get_FullChargeCapacityInMilliwattHours(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Devices_Power_IBatteryReport<D>::RemainingCapacityInMilliwattHours() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryReport)->get_RemainingCapacityInMilliwattHours(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Power::BatteryStatus) consume_Windows_Devices_Power_IBatteryReport<D>::Status() const
    {
        winrt::Windows::System::Power::BatteryStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryReport)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Power::Battery) consume_Windows_Devices_Power_IBatteryStatics<D>::AggregateBattery() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryStatics)->get_AggregateBattery(&result));
        return winrt::Windows::Devices::Power::Battery{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Power::Battery>) consume_Windows_Devices_Power_IBatteryStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryStatics)->FromIdAsync(*(void**)(&deviceId), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Power::Battery>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Power_IBatteryStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Power::IBatteryStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Power::IBattery> : produce_base<D, winrt::Windows::Devices::Power::IBattery>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetReport(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Power::BatteryReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ReportUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ReportUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Power::Battery, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ReportUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Power::IBatteryReport> : produce_base<D, winrt::Windows::Devices::Power::IBatteryReport>
    {
        int32_t __stdcall get_ChargeRateInMilliwatts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().ChargeRateInMilliwatts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesignCapacityInMilliwattHours(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().DesignCapacityInMilliwattHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FullChargeCapacityInMilliwattHours(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().FullChargeCapacityInMilliwattHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemainingCapacityInMilliwattHours(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().RemainingCapacityInMilliwattHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Power::BatteryStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Power::IBatteryStatics> : produce_base<D, winrt::Windows::Devices::Power::IBatteryStatics>
    {
        int32_t __stdcall get_AggregateBattery(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Power::Battery>(this->shim().AggregateBattery());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Power::Battery>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
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
}
WINRT_EXPORT namespace winrt::Windows::Devices::Power
{
    inline auto Battery::AggregateBattery()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Power::Battery(*)(IBatteryStatics const&), Battery, IBatteryStatics>([](IBatteryStatics const& f) { return f.AggregateBattery(); });
    }
    inline auto Battery::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Battery, IBatteryStatics>([&](IBatteryStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Battery::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IBatteryStatics const&), Battery, IBatteryStatics>([](IBatteryStatics const& f) { return f.GetDeviceSelector(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Power::IBattery> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Power::IBatteryReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Power::IBatteryStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Power::Battery> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Power::BatteryReport> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
