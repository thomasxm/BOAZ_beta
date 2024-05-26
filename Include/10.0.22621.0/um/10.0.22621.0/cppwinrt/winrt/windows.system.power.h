// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Power_H
#define WINRT_Windows_System_Power_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Power.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::LowUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_LowUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::NearMaxAcceptableUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_NearMaxAcceptableUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::MaxAcceptableUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_MaxAcceptableUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::ExcessiveUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_ExcessiveUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::NearTerminationUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_NearTerminationUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::TerminationUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_TerminationUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsage() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_RecentEnergyUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->get_RecentEnergyUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->add_RecentEnergyUsageIncreased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased_revoker consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RecentEnergyUsageIncreased_revoker>(this, RecentEnergyUsageIncreased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->remove_RecentEnergyUsageIncreased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->add_RecentEnergyUsageReturnedToLow(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow_revoker consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RecentEnergyUsageReturnedToLow_revoker>(this, RecentEnergyUsageReturnedToLow(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IBackgroundEnergyManagerStatics)->remove_RecentEnergyUsageReturnedToLow(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::LowUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->get_LowUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::NearMaxAcceptableUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->get_NearMaxAcceptableUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::MaxAcceptableUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->get_MaxAcceptableUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::ExcessiveUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->get_ExcessiveUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsage() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->get_RecentEnergyUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageLevel() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->get_RecentEnergyUsageLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->add_RecentEnergyUsageIncreased(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased_revoker consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RecentEnergyUsageIncreased_revoker>(this, RecentEnergyUsageIncreased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->remove_RecentEnergyUsageIncreased(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->add_RecentEnergyUsageReturnedToLow(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow_revoker consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RecentEnergyUsageReturnedToLow_revoker>(this, RecentEnergyUsageReturnedToLow(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IForegroundEnergyManagerStatics)->remove_RecentEnergyUsageReturnedToLow(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Power::EnergySaverStatus) consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatus() const
    {
        winrt::Windows::System::Power::EnergySaverStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->get_EnergySaverStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->add_EnergySaverStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnergySaverStatusChanged_revoker>(this, EnergySaverStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->remove_EnergySaverStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Power::BatteryStatus) consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatus() const
    {
        winrt::Windows::System::Power::BatteryStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->get_BatteryStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->add_BatteryStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, BatteryStatusChanged_revoker>(this, BatteryStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->remove_BatteryStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Power::PowerSupplyStatus) consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatus() const
    {
        winrt::Windows::System::Power::PowerSupplyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->get_PowerSupplyStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->add_PowerSupplyStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PowerSupplyStatusChanged_revoker>(this, PowerSupplyStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->remove_PowerSupplyStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercent() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->get_RemainingChargePercent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->add_RemainingChargePercentChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RemainingChargePercentChanged_revoker>(this, RemainingChargePercentChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->remove_RemainingChargePercentChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->get_RemainingDischargeTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->add_RemainingDischargeTimeChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RemainingDischargeTimeChanged_revoker>(this, RemainingDischargeTimeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Power::IPowerManagerStatics)->remove_RemainingDischargeTimeChanged(impl::bind_in(token));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Power::IBackgroundEnergyManagerStatics> : produce_base<D, winrt::Windows::System::Power::IBackgroundEnergyManagerStatics>
    {
        int32_t __stdcall get_LowUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LowUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NearMaxAcceptableUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().NearMaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAcceptableUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExcessiveUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExcessiveUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NearTerminationUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().NearTerminationUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TerminationUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TerminationUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecentEnergyUsage(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecentEnergyUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RecentEnergyUsageIncreased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecentEnergyUsageIncreased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RecentEnergyUsageReturnedToLow(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecentEnergyUsageReturnedToLow(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Power::IForegroundEnergyManagerStatics> : produce_base<D, winrt::Windows::System::Power::IForegroundEnergyManagerStatics>
    {
        int32_t __stdcall get_LowUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().LowUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NearMaxAcceptableUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().NearMaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAcceptableUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExcessiveUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ExcessiveUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecentEnergyUsage(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RecentEnergyUsageLevel(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RecentEnergyUsageIncreased(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecentEnergyUsageIncreased(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RecentEnergyUsageReturnedToLow(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecentEnergyUsageReturnedToLow(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Power::IPowerManagerStatics> : produce_base<D, winrt::Windows::System::Power::IPowerManagerStatics>
    {
        int32_t __stdcall get_EnergySaverStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Power::EnergySaverStatus>(this->shim().EnergySaverStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_EnergySaverStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnergySaverStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnergySaverStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnergySaverStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_BatteryStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Power::BatteryStatus>(this->shim().BatteryStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_BatteryStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BatteryStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BatteryStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BatteryStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_PowerSupplyStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Power::PowerSupplyStatus>(this->shim().PowerSupplyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PowerSupplyStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PowerSupplyStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PowerSupplyStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PowerSupplyStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_RemainingChargePercent(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RemainingChargePercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RemainingChargePercentChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemainingChargePercentChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemainingChargePercentChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemainingChargePercentChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_RemainingDischargeTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RemainingDischargeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RemainingDischargeTimeChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RemainingDischargeTimeChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RemainingDischargeTimeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemainingDischargeTimeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Power
{
    inline auto BackgroundEnergyManager::LowUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.LowUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::NearMaxAcceptableUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.NearMaxAcceptableUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::MaxAcceptableUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.MaxAcceptableUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::ExcessiveUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.ExcessiveUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::NearTerminationUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.NearTerminationUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::TerminationUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.TerminationUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::RecentEnergyUsage()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.RecentEnergyUsage(); });
    }
    inline auto BackgroundEnergyManager::RecentEnergyUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IBackgroundEnergyManagerStatics const&), BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([](IBackgroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageLevel(); });
    }
    inline auto BackgroundEnergyManager::RecentEnergyUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([&](IBackgroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageIncreased(handler); });
    }
    inline BackgroundEnergyManager::RecentEnergyUsageIncreased_revoker BackgroundEnergyManager::RecentEnergyUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<BackgroundEnergyManager, winrt::Windows::System::Power::IBackgroundEnergyManagerStatics>();
        return { f, f.RecentEnergyUsageIncreased(handler) };
    }
    inline auto BackgroundEnergyManager::RecentEnergyUsageIncreased(winrt::event_token const& token)
    {
        impl::call_factory<BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([&](IBackgroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageIncreased(token); });
    }
    inline auto BackgroundEnergyManager::RecentEnergyUsageReturnedToLow(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([&](IBackgroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageReturnedToLow(handler); });
    }
    inline BackgroundEnergyManager::RecentEnergyUsageReturnedToLow_revoker BackgroundEnergyManager::RecentEnergyUsageReturnedToLow(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<BackgroundEnergyManager, winrt::Windows::System::Power::IBackgroundEnergyManagerStatics>();
        return { f, f.RecentEnergyUsageReturnedToLow(handler) };
    }
    inline auto BackgroundEnergyManager::RecentEnergyUsageReturnedToLow(winrt::event_token const& token)
    {
        impl::call_factory<BackgroundEnergyManager, IBackgroundEnergyManagerStatics>([&](IBackgroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageReturnedToLow(token); });
    }
    inline auto ForegroundEnergyManager::LowUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IForegroundEnergyManagerStatics const&), ForegroundEnergyManager, IForegroundEnergyManagerStatics>([](IForegroundEnergyManagerStatics const& f) { return f.LowUsageLevel(); });
    }
    inline auto ForegroundEnergyManager::NearMaxAcceptableUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IForegroundEnergyManagerStatics const&), ForegroundEnergyManager, IForegroundEnergyManagerStatics>([](IForegroundEnergyManagerStatics const& f) { return f.NearMaxAcceptableUsageLevel(); });
    }
    inline auto ForegroundEnergyManager::MaxAcceptableUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IForegroundEnergyManagerStatics const&), ForegroundEnergyManager, IForegroundEnergyManagerStatics>([](IForegroundEnergyManagerStatics const& f) { return f.MaxAcceptableUsageLevel(); });
    }
    inline auto ForegroundEnergyManager::ExcessiveUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IForegroundEnergyManagerStatics const&), ForegroundEnergyManager, IForegroundEnergyManagerStatics>([](IForegroundEnergyManagerStatics const& f) { return f.ExcessiveUsageLevel(); });
    }
    inline auto ForegroundEnergyManager::RecentEnergyUsage()
    {
        return impl::call_factory_cast<uint32_t(*)(IForegroundEnergyManagerStatics const&), ForegroundEnergyManager, IForegroundEnergyManagerStatics>([](IForegroundEnergyManagerStatics const& f) { return f.RecentEnergyUsage(); });
    }
    inline auto ForegroundEnergyManager::RecentEnergyUsageLevel()
    {
        return impl::call_factory_cast<uint32_t(*)(IForegroundEnergyManagerStatics const&), ForegroundEnergyManager, IForegroundEnergyManagerStatics>([](IForegroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageLevel(); });
    }
    inline auto ForegroundEnergyManager::RecentEnergyUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<ForegroundEnergyManager, IForegroundEnergyManagerStatics>([&](IForegroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageIncreased(handler); });
    }
    inline ForegroundEnergyManager::RecentEnergyUsageIncreased_revoker ForegroundEnergyManager::RecentEnergyUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<ForegroundEnergyManager, winrt::Windows::System::Power::IForegroundEnergyManagerStatics>();
        return { f, f.RecentEnergyUsageIncreased(handler) };
    }
    inline auto ForegroundEnergyManager::RecentEnergyUsageIncreased(winrt::event_token const& token)
    {
        impl::call_factory<ForegroundEnergyManager, IForegroundEnergyManagerStatics>([&](IForegroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageIncreased(token); });
    }
    inline auto ForegroundEnergyManager::RecentEnergyUsageReturnedToLow(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<ForegroundEnergyManager, IForegroundEnergyManagerStatics>([&](IForegroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageReturnedToLow(handler); });
    }
    inline ForegroundEnergyManager::RecentEnergyUsageReturnedToLow_revoker ForegroundEnergyManager::RecentEnergyUsageReturnedToLow(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<ForegroundEnergyManager, winrt::Windows::System::Power::IForegroundEnergyManagerStatics>();
        return { f, f.RecentEnergyUsageReturnedToLow(handler) };
    }
    inline auto ForegroundEnergyManager::RecentEnergyUsageReturnedToLow(winrt::event_token const& token)
    {
        impl::call_factory<ForegroundEnergyManager, IForegroundEnergyManagerStatics>([&](IForegroundEnergyManagerStatics const& f) { return f.RecentEnergyUsageReturnedToLow(token); });
    }
    inline auto PowerManager::EnergySaverStatus()
    {
        return impl::call_factory_cast<winrt::Windows::System::Power::EnergySaverStatus(*)(IPowerManagerStatics const&), PowerManager, IPowerManagerStatics>([](IPowerManagerStatics const& f) { return f.EnergySaverStatus(); });
    }
    inline auto PowerManager::EnergySaverStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.EnergySaverStatusChanged(handler); });
    }
    inline PowerManager::EnergySaverStatusChanged_revoker PowerManager::EnergySaverStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<PowerManager, winrt::Windows::System::Power::IPowerManagerStatics>();
        return { f, f.EnergySaverStatusChanged(handler) };
    }
    inline auto PowerManager::EnergySaverStatusChanged(winrt::event_token const& token)
    {
        impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.EnergySaverStatusChanged(token); });
    }
    inline auto PowerManager::BatteryStatus()
    {
        return impl::call_factory_cast<winrt::Windows::System::Power::BatteryStatus(*)(IPowerManagerStatics const&), PowerManager, IPowerManagerStatics>([](IPowerManagerStatics const& f) { return f.BatteryStatus(); });
    }
    inline auto PowerManager::BatteryStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.BatteryStatusChanged(handler); });
    }
    inline PowerManager::BatteryStatusChanged_revoker PowerManager::BatteryStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<PowerManager, winrt::Windows::System::Power::IPowerManagerStatics>();
        return { f, f.BatteryStatusChanged(handler) };
    }
    inline auto PowerManager::BatteryStatusChanged(winrt::event_token const& token)
    {
        impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.BatteryStatusChanged(token); });
    }
    inline auto PowerManager::PowerSupplyStatus()
    {
        return impl::call_factory_cast<winrt::Windows::System::Power::PowerSupplyStatus(*)(IPowerManagerStatics const&), PowerManager, IPowerManagerStatics>([](IPowerManagerStatics const& f) { return f.PowerSupplyStatus(); });
    }
    inline auto PowerManager::PowerSupplyStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.PowerSupplyStatusChanged(handler); });
    }
    inline PowerManager::PowerSupplyStatusChanged_revoker PowerManager::PowerSupplyStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<PowerManager, winrt::Windows::System::Power::IPowerManagerStatics>();
        return { f, f.PowerSupplyStatusChanged(handler) };
    }
    inline auto PowerManager::PowerSupplyStatusChanged(winrt::event_token const& token)
    {
        impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.PowerSupplyStatusChanged(token); });
    }
    inline auto PowerManager::RemainingChargePercent()
    {
        return impl::call_factory_cast<int32_t(*)(IPowerManagerStatics const&), PowerManager, IPowerManagerStatics>([](IPowerManagerStatics const& f) { return f.RemainingChargePercent(); });
    }
    inline auto PowerManager::RemainingChargePercentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.RemainingChargePercentChanged(handler); });
    }
    inline PowerManager::RemainingChargePercentChanged_revoker PowerManager::RemainingChargePercentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<PowerManager, winrt::Windows::System::Power::IPowerManagerStatics>();
        return { f, f.RemainingChargePercentChanged(handler) };
    }
    inline auto PowerManager::RemainingChargePercentChanged(winrt::event_token const& token)
    {
        impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.RemainingChargePercentChanged(token); });
    }
    inline auto PowerManager::RemainingDischargeTime()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::TimeSpan(*)(IPowerManagerStatics const&), PowerManager, IPowerManagerStatics>([](IPowerManagerStatics const& f) { return f.RemainingDischargeTime(); });
    }
    inline auto PowerManager::RemainingDischargeTimeChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.RemainingDischargeTimeChanged(handler); });
    }
    inline PowerManager::RemainingDischargeTimeChanged_revoker PowerManager::RemainingDischargeTimeChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<PowerManager, winrt::Windows::System::Power::IPowerManagerStatics>();
        return { f, f.RemainingDischargeTimeChanged(handler) };
    }
    inline auto PowerManager::RemainingDischargeTimeChanged(winrt::event_token const& token)
    {
        impl::call_factory<PowerManager, IPowerManagerStatics>([&](IPowerManagerStatics const& f) { return f.RemainingDischargeTimeChanged(token); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::IForegroundEnergyManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::IPowerManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::BackgroundEnergyManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::ForegroundEnergyManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::PowerManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
