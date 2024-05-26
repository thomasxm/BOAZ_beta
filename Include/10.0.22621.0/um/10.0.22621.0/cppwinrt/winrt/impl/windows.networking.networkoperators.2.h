// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_NetworkOperators_2_H
#define WINRT_Windows_Networking_NetworkOperators_2_H
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Networking.NetworkOperators.1.h"
WINRT_EXPORT namespace winrt::Windows::Networking::NetworkOperators
{
    struct ESimProfileInstallProgress
    {
        int32_t TotalSizeInBytes;
        int32_t InstalledSizeInBytes;
    };
    inline bool operator==(ESimProfileInstallProgress const& left, ESimProfileInstallProgress const& right) noexcept
    {
        return left.TotalSizeInBytes == right.TotalSizeInBytes && left.InstalledSizeInBytes == right.InstalledSizeInBytes;
    }
    inline bool operator!=(ESimProfileInstallProgress const& left, ESimProfileInstallProgress const& right) noexcept
    {
        return !(left == right);
    }
    struct ProfileUsage
    {
        uint32_t UsageInMegabytes;
        winrt::Windows::Foundation::DateTime LastSyncTime;
    };
    inline bool operator==(ProfileUsage const& left, ProfileUsage const& right) noexcept
    {
        return left.UsageInMegabytes == right.UsageInMegabytes && left.LastSyncTime == right.LastSyncTime;
    }
    inline bool operator!=(ProfileUsage const& left, ProfileUsage const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) ESim : winrt::Windows::Networking::NetworkOperators::IESim,
        impl::require<ESim, winrt::Windows::Networking::NetworkOperators::IESim2, winrt::Windows::Networking::NetworkOperators::IESim3>
    {
        ESim(std::nullptr_t) noexcept {}
        ESim(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESim(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimAddedEventArgs : winrt::Windows::Networking::NetworkOperators::IESimAddedEventArgs
    {
        ESimAddedEventArgs(std::nullptr_t) noexcept {}
        ESimAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimAddedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimDiscoverEvent : winrt::Windows::Networking::NetworkOperators::IESimDiscoverEvent
    {
        ESimDiscoverEvent(std::nullptr_t) noexcept {}
        ESimDiscoverEvent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimDiscoverEvent(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimDiscoverResult : winrt::Windows::Networking::NetworkOperators::IESimDiscoverResult
    {
        ESimDiscoverResult(std::nullptr_t) noexcept {}
        ESimDiscoverResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimDiscoverResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimDownloadProfileMetadataResult : winrt::Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult
    {
        ESimDownloadProfileMetadataResult(std::nullptr_t) noexcept {}
        ESimDownloadProfileMetadataResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult(ptr, take_ownership_from_abi) {}
    };
    struct ESimManager
    {
        ESimManager() = delete;
        [[nodiscard]] static auto ServiceInfo();
        static auto TryCreateESimWatcher();
        static auto ServiceInfoChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using ServiceInfoChanged_revoker = impl::factory_event_revoker<winrt::Windows::Networking::NetworkOperators::IESimManagerStatics, &impl::abi_t<winrt::Windows::Networking::NetworkOperators::IESimManagerStatics>::remove_ServiceInfoChanged>;
        [[nodiscard]] static ServiceInfoChanged_revoker ServiceInfoChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto ServiceInfoChanged(winrt::event_token const& token);
    };
    struct __declspec(empty_bases) ESimOperationResult : winrt::Windows::Networking::NetworkOperators::IESimOperationResult
    {
        ESimOperationResult(std::nullptr_t) noexcept {}
        ESimOperationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimOperationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimPolicy : winrt::Windows::Networking::NetworkOperators::IESimPolicy
    {
        ESimPolicy(std::nullptr_t) noexcept {}
        ESimPolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimPolicy(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimProfile : winrt::Windows::Networking::NetworkOperators::IESimProfile
    {
        ESimProfile(std::nullptr_t) noexcept {}
        ESimProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimProfile(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimProfileMetadata : winrt::Windows::Networking::NetworkOperators::IESimProfileMetadata
    {
        ESimProfileMetadata(std::nullptr_t) noexcept {}
        ESimProfileMetadata(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimProfileMetadata(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimProfilePolicy : winrt::Windows::Networking::NetworkOperators::IESimProfilePolicy
    {
        ESimProfilePolicy(std::nullptr_t) noexcept {}
        ESimProfilePolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimProfilePolicy(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimRemovedEventArgs : winrt::Windows::Networking::NetworkOperators::IESimRemovedEventArgs
    {
        ESimRemovedEventArgs(std::nullptr_t) noexcept {}
        ESimRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimRemovedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimServiceInfo : winrt::Windows::Networking::NetworkOperators::IESimServiceInfo
    {
        ESimServiceInfo(std::nullptr_t) noexcept {}
        ESimServiceInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimServiceInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimUpdatedEventArgs : winrt::Windows::Networking::NetworkOperators::IESimUpdatedEventArgs
    {
        ESimUpdatedEventArgs(std::nullptr_t) noexcept {}
        ESimUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimUpdatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ESimWatcher : winrt::Windows::Networking::NetworkOperators::IESimWatcher
    {
        ESimWatcher(std::nullptr_t) noexcept {}
        ESimWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IESimWatcher(ptr, take_ownership_from_abi) {}
    };
    struct FdnAccessManager
    {
        FdnAccessManager() = delete;
        static auto RequestUnlockAsync(param::hstring const& contactListId);
    };
    struct __declspec(empty_bases) HotspotAuthenticationContext : winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext,
        impl::require<HotspotAuthenticationContext, winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>
    {
        HotspotAuthenticationContext(std::nullptr_t) noexcept {}
        HotspotAuthenticationContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext(ptr, take_ownership_from_abi) {}
        static auto TryGetAuthenticationContext(param::hstring const& evenToken, winrt::Windows::Networking::NetworkOperators::HotspotAuthenticationContext& context);
    };
    struct __declspec(empty_bases) HotspotAuthenticationEventDetails : winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails
    {
        HotspotAuthenticationEventDetails(std::nullptr_t) noexcept {}
        HotspotAuthenticationEventDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HotspotCredentialsAuthenticationResult : winrt::Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult
    {
        HotspotCredentialsAuthenticationResult(std::nullptr_t) noexcept {}
        HotspotCredentialsAuthenticationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult(ptr, take_ownership_from_abi) {}
    };
    struct KnownCSimFilePaths
    {
        KnownCSimFilePaths() = delete;
        [[nodiscard]] static auto EFSpn();
        [[nodiscard]] static auto Gid1();
        [[nodiscard]] static auto Gid2();
    };
    struct KnownRuimFilePaths
    {
        KnownRuimFilePaths() = delete;
        [[nodiscard]] static auto EFSpn();
        [[nodiscard]] static auto Gid1();
        [[nodiscard]] static auto Gid2();
    };
    struct KnownSimFilePaths
    {
        KnownSimFilePaths() = delete;
        [[nodiscard]] static auto EFOns();
        [[nodiscard]] static auto EFSpn();
        [[nodiscard]] static auto Gid1();
        [[nodiscard]] static auto Gid2();
    };
    struct KnownUSimFilePaths
    {
        KnownUSimFilePaths() = delete;
        [[nodiscard]] static auto EFSpn();
        [[nodiscard]] static auto EFOpl();
        [[nodiscard]] static auto EFPnn();
        [[nodiscard]] static auto Gid1();
        [[nodiscard]] static auto Gid2();
    };
    struct __declspec(empty_bases) MobileBroadbandAccount : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount,
        impl::require<MobileBroadbandAccount, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount2, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>
    {
        MobileBroadbandAccount(std::nullptr_t) noexcept {}
        MobileBroadbandAccount(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto AvailableNetworkAccountIds();
        static auto CreateFromNetworkAccountId(param::hstring const& networkAccountId);
    };
    struct __declspec(empty_bases) MobileBroadbandAccountEventArgs : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs
    {
        MobileBroadbandAccountEventArgs(std::nullptr_t) noexcept {}
        MobileBroadbandAccountEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandAccountUpdatedEventArgs : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs
    {
        MobileBroadbandAccountUpdatedEventArgs(std::nullptr_t) noexcept {}
        MobileBroadbandAccountUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandAccountWatcher : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher
    {
        MobileBroadbandAccountWatcher(std::nullptr_t) noexcept {}
        MobileBroadbandAccountWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher(ptr, take_ownership_from_abi) {}
        MobileBroadbandAccountWatcher();
    };
    struct __declspec(empty_bases) MobileBroadbandAntennaSar : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar
    {
        MobileBroadbandAntennaSar(std::nullptr_t) noexcept {}
        MobileBroadbandAntennaSar(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar(ptr, take_ownership_from_abi) {}
        MobileBroadbandAntennaSar(int32_t antennaIndex, int32_t sarBackoffIndex);
    };
    struct __declspec(empty_bases) MobileBroadbandCellCdma : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma
    {
        MobileBroadbandCellCdma(std::nullptr_t) noexcept {}
        MobileBroadbandCellCdma(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCellGsm : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm
    {
        MobileBroadbandCellGsm(std::nullptr_t) noexcept {}
        MobileBroadbandCellGsm(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCellLte : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellLte
    {
        MobileBroadbandCellLte(std::nullptr_t) noexcept {}
        MobileBroadbandCellLte(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellLte(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCellNR : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellNR
    {
        MobileBroadbandCellNR(std::nullptr_t) noexcept {}
        MobileBroadbandCellNR(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellNR(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCellTdscdma : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma
    {
        MobileBroadbandCellTdscdma(std::nullptr_t) noexcept {}
        MobileBroadbandCellTdscdma(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCellUmts : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts
    {
        MobileBroadbandCellUmts(std::nullptr_t) noexcept {}
        MobileBroadbandCellUmts(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCellsInfo : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo,
        impl::require<MobileBroadbandCellsInfo, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo2>
    {
        MobileBroadbandCellsInfo(std::nullptr_t) noexcept {}
        MobileBroadbandCellsInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandCurrentSlotIndexChangedEventArgs : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCurrentSlotIndexChangedEventArgs
    {
        MobileBroadbandCurrentSlotIndexChangedEventArgs(std::nullptr_t) noexcept {}
        MobileBroadbandCurrentSlotIndexChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCurrentSlotIndexChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceInformation : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation,
        impl::require<MobileBroadbandDeviceInformation, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation4>
    {
        MobileBroadbandDeviceInformation(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceService : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService
    {
        MobileBroadbandDeviceService(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceService(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceCommandResult : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult
    {
        MobileBroadbandDeviceServiceCommandResult(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceCommandResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceCommandSession : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession
    {
        MobileBroadbandDeviceServiceCommandSession(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceCommandSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceDataReceivedEventArgs : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs
    {
        MobileBroadbandDeviceServiceDataReceivedEventArgs(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceDataReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceDataSession : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession
    {
        MobileBroadbandDeviceServiceDataSession(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceDataSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceInformation : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation
    {
        MobileBroadbandDeviceServiceInformation(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandDeviceServiceTriggerDetails : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails,
        impl::require<MobileBroadbandDeviceServiceTriggerDetails, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails2>
    {
        MobileBroadbandDeviceServiceTriggerDetails(std::nullptr_t) noexcept {}
        MobileBroadbandDeviceServiceTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandModem : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem,
        impl::require<MobileBroadbandModem, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem2, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem3, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem4>
    {
        MobileBroadbandModem(std::nullptr_t) noexcept {}
        MobileBroadbandModem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem(ptr, take_ownership_from_abi) {}
        using impl::consume_t<MobileBroadbandModem, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem2>::GetIsPassthroughEnabledAsync;
        using impl::consume_t<MobileBroadbandModem, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem4>::GetIsPassthroughEnabledAsync;
        using impl::consume_t<MobileBroadbandModem, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem2>::SetIsPassthroughEnabledAsync;
        using impl::consume_t<MobileBroadbandModem, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem4>::SetIsPassthroughEnabledAsync;
        static auto GetDeviceSelector();
        static auto FromId(param::hstring const& deviceId);
        static auto GetDefault();
    };
    struct __declspec(empty_bases) MobileBroadbandModemConfiguration : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration,
        impl::require<MobileBroadbandModemConfiguration, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>
    {
        MobileBroadbandModemConfiguration(std::nullptr_t) noexcept {}
        MobileBroadbandModemConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandModemIsolation : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation
    {
        MobileBroadbandModemIsolation(std::nullptr_t) noexcept {}
        MobileBroadbandModemIsolation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation(ptr, take_ownership_from_abi) {}
        MobileBroadbandModemIsolation(param::hstring const& modemDeviceId, param::hstring const& ruleGroupId);
    };
    struct __declspec(empty_bases) MobileBroadbandNetwork : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork,
        impl::require<MobileBroadbandNetwork, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>
    {
        MobileBroadbandNetwork(std::nullptr_t) noexcept {}
        MobileBroadbandNetwork(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandNetworkRegistrationStateChange : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange
    {
        MobileBroadbandNetworkRegistrationStateChange(std::nullptr_t) noexcept {}
        MobileBroadbandNetworkRegistrationStateChange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandNetworkRegistrationStateChangeTriggerDetails : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails
    {
        MobileBroadbandNetworkRegistrationStateChangeTriggerDetails(std::nullptr_t) noexcept {}
        MobileBroadbandNetworkRegistrationStateChangeTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPco : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPco
    {
        MobileBroadbandPco(std::nullptr_t) noexcept {}
        MobileBroadbandPco(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPco(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPcoDataChangeTriggerDetails : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails
    {
        MobileBroadbandPcoDataChangeTriggerDetails(std::nullptr_t) noexcept {}
        MobileBroadbandPcoDataChangeTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPin : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPin
    {
        MobileBroadbandPin(std::nullptr_t) noexcept {}
        MobileBroadbandPin(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPin(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPinLockStateChange : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange
    {
        MobileBroadbandPinLockStateChange(std::nullptr_t) noexcept {}
        MobileBroadbandPinLockStateChange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPinLockStateChangeTriggerDetails : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails
    {
        MobileBroadbandPinLockStateChangeTriggerDetails(std::nullptr_t) noexcept {}
        MobileBroadbandPinLockStateChangeTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPinManager : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinManager
    {
        MobileBroadbandPinManager(std::nullptr_t) noexcept {}
        MobileBroadbandPinManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinManager(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandPinOperationResult : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult
    {
        MobileBroadbandPinOperationResult(std::nullptr_t) noexcept {}
        MobileBroadbandPinOperationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandRadioStateChange : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange
    {
        MobileBroadbandRadioStateChange(std::nullptr_t) noexcept {}
        MobileBroadbandRadioStateChange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandRadioStateChangeTriggerDetails : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails
    {
        MobileBroadbandRadioStateChangeTriggerDetails(std::nullptr_t) noexcept {}
        MobileBroadbandRadioStateChangeTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandSarManager : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSarManager
    {
        MobileBroadbandSarManager(std::nullptr_t) noexcept {}
        MobileBroadbandSarManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSarManager(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandSlotInfo : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotInfo,
        impl::require<MobileBroadbandSlotInfo, winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotInfo2>
    {
        MobileBroadbandSlotInfo(std::nullptr_t) noexcept {}
        MobileBroadbandSlotInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandSlotInfoChangedEventArgs : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotInfoChangedEventArgs
    {
        MobileBroadbandSlotInfoChangedEventArgs(std::nullptr_t) noexcept {}
        MobileBroadbandSlotInfoChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotInfoChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandSlotManager : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotManager
    {
        MobileBroadbandSlotManager(std::nullptr_t) noexcept {}
        MobileBroadbandSlotManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSlotManager(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandTransmissionStateChangedEventArgs : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs
    {
        MobileBroadbandTransmissionStateChangedEventArgs(std::nullptr_t) noexcept {}
        MobileBroadbandTransmissionStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandUicc : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUicc
    {
        MobileBroadbandUicc(std::nullptr_t) noexcept {}
        MobileBroadbandUicc(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUicc(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandUiccApp : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp
    {
        MobileBroadbandUiccApp(std::nullptr_t) noexcept {}
        MobileBroadbandUiccApp(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandUiccAppReadRecordResult : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult
    {
        MobileBroadbandUiccAppReadRecordResult(std::nullptr_t) noexcept {}
        MobileBroadbandUiccAppReadRecordResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandUiccAppRecordDetailsResult : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult
    {
        MobileBroadbandUiccAppRecordDetailsResult(std::nullptr_t) noexcept {}
        MobileBroadbandUiccAppRecordDetailsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MobileBroadbandUiccAppsResult : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult
    {
        MobileBroadbandUiccAppsResult(std::nullptr_t) noexcept {}
        MobileBroadbandUiccAppsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) NetworkOperatorDataUsageTriggerDetails : winrt::Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails
    {
        NetworkOperatorDataUsageTriggerDetails(std::nullptr_t) noexcept {}
        NetworkOperatorDataUsageTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) NetworkOperatorNotificationEventDetails : winrt::Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails,
        impl::require<NetworkOperatorNotificationEventDetails, winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>
    {
        NetworkOperatorNotificationEventDetails(std::nullptr_t) noexcept {}
        NetworkOperatorNotificationEventDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) NetworkOperatorTetheringAccessPointConfiguration : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration,
        impl::require<NetworkOperatorTetheringAccessPointConfiguration, winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration2>
    {
        NetworkOperatorTetheringAccessPointConfiguration(std::nullptr_t) noexcept {}
        NetworkOperatorTetheringAccessPointConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration(ptr, take_ownership_from_abi) {}
        NetworkOperatorTetheringAccessPointConfiguration();
    };
    struct __declspec(empty_bases) NetworkOperatorTetheringClient : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient
    {
        NetworkOperatorTetheringClient(std::nullptr_t) noexcept {}
        NetworkOperatorTetheringClient(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) NetworkOperatorTetheringManager : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager,
        impl::require<NetworkOperatorTetheringManager, winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>
    {
        NetworkOperatorTetheringManager(std::nullptr_t) noexcept {}
        NetworkOperatorTetheringManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager(ptr, take_ownership_from_abi) {}
        static auto GetTetheringCapability(param::hstring const& networkAccountId);
        static auto CreateFromNetworkAccountId(param::hstring const& networkAccountId);
        static auto GetTetheringCapabilityFromConnectionProfile(winrt::Windows::Networking::Connectivity::ConnectionProfile const& profile);
        static auto CreateFromConnectionProfile(winrt::Windows::Networking::Connectivity::ConnectionProfile const& profile);
        static auto CreateFromConnectionProfile(winrt::Windows::Networking::Connectivity::ConnectionProfile const& profile, winrt::Windows::Networking::Connectivity::NetworkAdapter const& adapter);
        static auto IsNoConnectionsTimeoutEnabled();
        static auto EnableNoConnectionsTimeout();
        static auto EnableNoConnectionsTimeoutAsync();
        static auto DisableNoConnectionsTimeout();
        static auto DisableNoConnectionsTimeoutAsync();
    };
    struct __declspec(empty_bases) NetworkOperatorTetheringOperationResult : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult
    {
        NetworkOperatorTetheringOperationResult(std::nullptr_t) noexcept {}
        NetworkOperatorTetheringOperationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProvisionFromXmlDocumentResults : winrt::Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults
    {
        ProvisionFromXmlDocumentResults(std::nullptr_t) noexcept {}
        ProvisionFromXmlDocumentResults(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProvisionedProfile : winrt::Windows::Networking::NetworkOperators::IProvisionedProfile
    {
        ProvisionedProfile(std::nullptr_t) noexcept {}
        ProvisionedProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IProvisionedProfile(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProvisioningAgent : winrt::Windows::Networking::NetworkOperators::IProvisioningAgent
    {
        ProvisioningAgent(std::nullptr_t) noexcept {}
        ProvisioningAgent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IProvisioningAgent(ptr, take_ownership_from_abi) {}
        ProvisioningAgent();
        static auto CreateFromNetworkAccountId(param::hstring const& networkAccountId);
    };
    struct __declspec(empty_bases) TetheringEntitlementCheckTriggerDetails : winrt::Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails
    {
        TetheringEntitlementCheckTriggerDetails(std::nullptr_t) noexcept {}
        TetheringEntitlementCheckTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UssdMessage : winrt::Windows::Networking::NetworkOperators::IUssdMessage
    {
        UssdMessage(std::nullptr_t) noexcept {}
        UssdMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IUssdMessage(ptr, take_ownership_from_abi) {}
        explicit UssdMessage(param::hstring const& messageText);
    };
    struct __declspec(empty_bases) UssdReply : winrt::Windows::Networking::NetworkOperators::IUssdReply
    {
        UssdReply(std::nullptr_t) noexcept {}
        UssdReply(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IUssdReply(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) UssdSession : winrt::Windows::Networking::NetworkOperators::IUssdSession
    {
        UssdSession(std::nullptr_t) noexcept {}
        UssdSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::NetworkOperators::IUssdSession(ptr, take_ownership_from_abi) {}
        static auto CreateFromNetworkAccountId(param::hstring const& networkAccountId);
        static auto CreateFromNetworkInterfaceId(param::hstring const& networkInterfaceId);
    };
}
#endif
