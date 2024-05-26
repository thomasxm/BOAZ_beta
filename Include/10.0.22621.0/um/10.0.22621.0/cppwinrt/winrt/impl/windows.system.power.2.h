// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Power_2_H
#define WINRT_Windows_System_Power_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.Power.1.h"
WINRT_EXPORT namespace winrt::Windows::System::Power
{
    struct BackgroundEnergyManager
    {
        BackgroundEnergyManager() = delete;
        [[nodiscard]] static auto LowUsageLevel();
        [[nodiscard]] static auto NearMaxAcceptableUsageLevel();
        [[nodiscard]] static auto MaxAcceptableUsageLevel();
        [[nodiscard]] static auto ExcessiveUsageLevel();
        [[nodiscard]] static auto NearTerminationUsageLevel();
        [[nodiscard]] static auto TerminationUsageLevel();
        [[nodiscard]] static auto RecentEnergyUsage();
        [[nodiscard]] static auto RecentEnergyUsageLevel();
        static auto RecentEnergyUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RecentEnergyUsageIncreased_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics>::remove_RecentEnergyUsageIncreased>;
        [[nodiscard]] static RecentEnergyUsageIncreased_revoker RecentEnergyUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RecentEnergyUsageIncreased(winrt::event_token const& token);
        static auto RecentEnergyUsageReturnedToLow(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RecentEnergyUsageReturnedToLow_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics>::remove_RecentEnergyUsageReturnedToLow>;
        [[nodiscard]] static RecentEnergyUsageReturnedToLow_revoker RecentEnergyUsageReturnedToLow(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RecentEnergyUsageReturnedToLow(winrt::event_token const& token);
    };
    struct ForegroundEnergyManager
    {
        ForegroundEnergyManager() = delete;
        [[nodiscard]] static auto LowUsageLevel();
        [[nodiscard]] static auto NearMaxAcceptableUsageLevel();
        [[nodiscard]] static auto MaxAcceptableUsageLevel();
        [[nodiscard]] static auto ExcessiveUsageLevel();
        [[nodiscard]] static auto RecentEnergyUsage();
        [[nodiscard]] static auto RecentEnergyUsageLevel();
        static auto RecentEnergyUsageIncreased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RecentEnergyUsageIncreased_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IForegroundEnergyManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IForegroundEnergyManagerStatics>::remove_RecentEnergyUsageIncreased>;
        [[nodiscard]] static RecentEnergyUsageIncreased_revoker RecentEnergyUsageIncreased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RecentEnergyUsageIncreased(winrt::event_token const& token);
        static auto RecentEnergyUsageReturnedToLow(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RecentEnergyUsageReturnedToLow_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IForegroundEnergyManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IForegroundEnergyManagerStatics>::remove_RecentEnergyUsageReturnedToLow>;
        [[nodiscard]] static RecentEnergyUsageReturnedToLow_revoker RecentEnergyUsageReturnedToLow(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RecentEnergyUsageReturnedToLow(winrt::event_token const& token);
    };
    struct PowerManager
    {
        PowerManager() = delete;
        [[nodiscard]] static auto EnergySaverStatus();
        static auto EnergySaverStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using EnergySaverStatusChanged_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IPowerManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IPowerManagerStatics>::remove_EnergySaverStatusChanged>;
        [[nodiscard]] static EnergySaverStatusChanged_revoker EnergySaverStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto EnergySaverStatusChanged(winrt::event_token const& token);
        [[nodiscard]] static auto BatteryStatus();
        static auto BatteryStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using BatteryStatusChanged_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IPowerManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IPowerManagerStatics>::remove_BatteryStatusChanged>;
        [[nodiscard]] static BatteryStatusChanged_revoker BatteryStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto BatteryStatusChanged(winrt::event_token const& token);
        [[nodiscard]] static auto PowerSupplyStatus();
        static auto PowerSupplyStatusChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using PowerSupplyStatusChanged_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IPowerManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IPowerManagerStatics>::remove_PowerSupplyStatusChanged>;
        [[nodiscard]] static PowerSupplyStatusChanged_revoker PowerSupplyStatusChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto PowerSupplyStatusChanged(winrt::event_token const& token);
        [[nodiscard]] static auto RemainingChargePercent();
        static auto RemainingChargePercentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RemainingChargePercentChanged_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IPowerManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IPowerManagerStatics>::remove_RemainingChargePercentChanged>;
        [[nodiscard]] static RemainingChargePercentChanged_revoker RemainingChargePercentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RemainingChargePercentChanged(winrt::event_token const& token);
        [[nodiscard]] static auto RemainingDischargeTime();
        static auto RemainingDischargeTimeChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RemainingDischargeTimeChanged_revoker = impl::factory_event_revoker<winrt::Windows::System::Power::IPowerManagerStatics, &impl::abi_t<winrt::Windows::System::Power::IPowerManagerStatics>::remove_RemainingDischargeTimeChanged>;
        [[nodiscard]] static RemainingDischargeTimeChanged_revoker RemainingDischargeTimeChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RemainingDischargeTimeChanged(winrt::event_token const& token);
    };
}
#endif
