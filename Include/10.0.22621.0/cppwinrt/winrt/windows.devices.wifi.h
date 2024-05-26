// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_WiFi_H
#define WINRT_Windows_Devices_WiFi_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Devices.WiFi.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Connectivity::NetworkAdapter) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::NetworkAdapter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->get_NetworkAdapter(&value));
        return winrt::Windows::Networking::Connectivity::NetworkAdapter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ScanAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->ScanAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiNetworkReport) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::NetworkReport() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->get_NetworkReport(&value));
        return winrt::Windows::Devices::WiFi::WiFiNetworkReport{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFi::WiFiAdapter, winrt::Windows::Foundation::IInspectable> const& args) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->add_AvailableNetworksChanged(*(void**)(&args), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged_revoker consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFi::WiFiAdapter, winrt::Windows::Foundation::IInspectable> const& args) const
    {
        return impl::make_event_revoker<D, AvailableNetworksChanged_revoker>(this, AvailableNetworksChanged(args));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->remove_AvailableNetworksChanged(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ConnectAsync(winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, winrt::Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->ConnectAsync(*(void**)(&availableNetwork), static_cast<int32_t>(reconnectionKind), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ConnectAsync(winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, winrt::Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind, winrt::Windows::Security::Credentials::PasswordCredential const& passwordCredential) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->ConnectWithPasswordCredentialAsync(*(void**)(&availableNetwork), static_cast<int32_t>(reconnectionKind), *(void**)(&passwordCredential), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ConnectAsync(winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, winrt::Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind, winrt::Windows::Security::Credentials::PasswordCredential const& passwordCredential, param::hstring const& ssid) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->ConnectWithPasswordCredentialAndSsidAsync(*(void**)(&availableNetwork), static_cast<int32_t>(reconnectionKind), *(void**)(&passwordCredential), *(void**)(&ssid), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiAdapter<D>::Disconnect() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter)->Disconnect());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationResult>) consume_Windows_Devices_WiFi_IWiFiAdapter2<D>::GetWpsConfigurationAsync(winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter2)->GetWpsConfigurationAsync(*(void**)(&availableNetwork), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>) consume_Windows_Devices_WiFi_IWiFiAdapter2<D>::ConnectAsync(winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, winrt::Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind, winrt::Windows::Security::Credentials::PasswordCredential const& passwordCredential, param::hstring const& ssid, winrt::Windows::Devices::WiFi::WiFiConnectionMethod const& connectionMethod) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapter2)->ConnectWithPasswordCredentialAndSsidAndConnectionMethodAsync(*(void**)(&availableNetwork), static_cast<int32_t>(reconnectionKind), *(void**)(&passwordCredential), *(void**)(&ssid), static_cast<int32_t>(connectionMethod), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAdapter>>) consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::FindAllAdaptersAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapterStatics)->FindAllAdaptersAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAdapter>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::GetDeviceSelector() const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapterStatics)->GetDeviceSelector(&deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAdapter>) consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapterStatics)->FromIdAsync(*(void**)(&deviceId), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAdapter>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAccessStatus>) consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::RequestAccessAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAdapterStatics)->RequestAccessAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAccessStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::Uptime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_Uptime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::Ssid() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_Ssid(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::Bssid() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_Bssid(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::ChannelCenterFrequencyInKilohertz() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_ChannelCenterFrequencyInKilohertz(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::NetworkRssiInDecibelMilliwatts() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_NetworkRssiInDecibelMilliwatts(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::SignalBars() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_SignalBars(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiNetworkKind) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::NetworkKind() const
    {
        winrt::Windows::Devices::WiFi::WiFiNetworkKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_NetworkKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiPhyKind) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::PhyKind() const
    {
        winrt::Windows::Devices::WiFi::WiFiPhyKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_PhyKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Connectivity::NetworkSecuritySettings) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::SecuritySettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_SecuritySettings(&value));
        return winrt::Windows::Networking::Connectivity::NetworkSecuritySettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::BeaconInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_BeaconInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::IsWiFiDirect() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_IsWiFiDirect(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiConnectionStatus) consume_Windows_Devices_WiFi_IWiFiConnectionResult<D>::ConnectionStatus() const
    {
        winrt::Windows::Devices::WiFi::WiFiConnectionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiConnectionResult)->get_ConnectionStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_WiFi_IWiFiNetworkReport<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiNetworkReport)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork>) consume_Windows_Devices_WiFi_IWiFiNetworkReport<D>::AvailableNetworks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiNetworkReport)->get_AvailableNetworks(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotConnectTriggerDetails<D>::RequestedNetwork() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails)->get_RequestedNetwork(&value));
        return winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotConnectTriggerDetails<D>::ReportError(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectStatus const& status) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails)->ReportError(static_cast<int32_t>(status)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult>) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotConnectTriggerDetails<D>::ConnectAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails)->ConnectAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotConnectTriggerDetails<D>::Connect() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails)->Connect(&result));
        return winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectStatus) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotConnectionResult<D>::Status() const
    {
        winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectionResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetworkProperties) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetwork<D>::GetProperties() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetwork)->GetProperties(&result));
        return winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetworkProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetwork<D>::UpdateProperties(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetworkProperties const& newProperties) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetwork)->UpdateProperties(*(void**)(&newProperties)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetwork<D>::Id() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetwork)->get_Id(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::DisplayName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_DisplayName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotAvailability) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::Availability() const
    {
        winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotAvailability value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_Availability(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::Availability(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotAvailability const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_Availability(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::RemainingBatteryPercent() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_RemainingBatteryPercent(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::RemainingBatteryPercent(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_RemainingBatteryPercent(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotCellularBars>) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::CellularBars() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_CellularBars(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotCellularBars>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::CellularBars(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotCellularBars> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_CellularBars(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::IsMetered() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_IsMetered(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::IsMetered(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_IsMetered(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::Ssid() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_Ssid(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::Ssid(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_Ssid(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::Password() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->get_Password(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkProperties<D>::Password(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties)->put_Password(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork) consume_Windows_Devices_WiFi_IWiFiOnDemandHotspotNetworkStatics<D>::GetOrCreateById(winrt::guid const& networkId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkStatics)->GetOrCreateById(impl::bind_in(networkId), &result));
        return winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFi::WiFiWpsConfigurationStatus) consume_Windows_Devices_WiFi_IWiFiWpsConfigurationResult<D>::Status() const
    {
        winrt::Windows::Devices::WiFi::WiFiWpsConfigurationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiWpsKind>) consume_Windows_Devices_WiFi_IWiFiWpsConfigurationResult<D>::SupportedWpsKinds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult)->get_SupportedWpsKinds(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiWpsKind>{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiAdapter> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiAdapter>
    {
        int32_t __stdcall get_NetworkAdapter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Connectivity::NetworkAdapter>(this->shim().NetworkAdapter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ScanAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ScanAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NetworkReport(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiNetworkReport>(this->shim().NetworkReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AvailableNetworksChanged(void* args, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().AvailableNetworksChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFi::WiFiAdapter, winrt::Windows::Foundation::IInspectable> const*>(&args)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AvailableNetworksChanged(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AvailableNetworksChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall ConnectAsync(void* availableNetwork, int32_t reconnectionKind, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithPasswordCredentialAsync(void* availableNetwork, int32_t reconnectionKind, void* passwordCredential, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind), *reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithPasswordCredentialAndSsidAsync(void* availableNetwork, int32_t reconnectionKind, void* passwordCredential, void* ssid, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind), *reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential), *reinterpret_cast<hstring const*>(&ssid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Disconnect() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disconnect();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiAdapter2> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiAdapter2>
    {
        int32_t __stdcall GetWpsConfigurationAsync(void* availableNetwork, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationResult>>(this->shim().GetWpsConfigurationAsync(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectWithPasswordCredentialAndSsidAndConnectionMethodAsync(void* availableNetwork, int32_t reconnectionKind, void* passwordCredential, void* ssid, int32_t connectionMethod, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind), *reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential), *reinterpret_cast<hstring const*>(&ssid), *reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiConnectionMethod const*>(&connectionMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiAdapterStatics> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiAdapterStatics>
    {
        int32_t __stdcall FindAllAdaptersAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAdapter>>>(this->shim().FindAllAdaptersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** asyncOp) noexcept final try
        {
            clear_abi(asyncOp);
            typename D::abi_guard guard(this->shim());
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAdapter>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork>
    {
        int32_t __stdcall get_Uptime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Uptime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ssid(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Ssid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bssid(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Bssid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChannelCenterFrequencyInKilohertz(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ChannelCenterFrequencyInKilohertz());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NetworkRssiInDecibelMilliwatts(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NetworkRssiInDecibelMilliwatts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignalBars(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().SignalBars());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NetworkKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiNetworkKind>(this->shim().NetworkKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhyKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiPhyKind>(this->shim().PhyKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SecuritySettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Connectivity::NetworkSecuritySettings>(this->shim().SecuritySettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BeaconInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().BeaconInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsWiFiDirect(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsWiFiDirect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiConnectionResult> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiConnectionResult>
    {
        int32_t __stdcall get_ConnectionStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiConnectionStatus>(this->shim().ConnectionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiNetworkReport> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiNetworkReport>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AvailableNetworks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork>>(this->shim().AvailableNetworks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails>
    {
        int32_t __stdcall get_RequestedNetwork(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork>(this->shim().RequestedNetwork());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportError(int32_t status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportError(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConnectAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult>>(this->shim().ConnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Connect(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult>(this->shim().Connect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectionResult> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectionResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetwork> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetwork>
    {
        int32_t __stdcall GetProperties(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetworkProperties>(this->shim().GetProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateProperties(void* newProperties) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateProperties(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetworkProperties const*>(&newProperties));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Availability(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotAvailability>(this->shim().Availability());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Availability(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Availability(*reinterpret_cast<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotAvailability const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemainingBatteryPercent(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().RemainingBatteryPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemainingBatteryPercent(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemainingBatteryPercent(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CellularBars(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotCellularBars>>(this->shim().CellularBars());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CellularBars(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CellularBars(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotCellularBars> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMetered(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMetered());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsMetered(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMetered(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ssid(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Ssid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Ssid(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Ssid(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Password(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().Password());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Password(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Password(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkStatics> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkStatics>
    {
        int32_t __stdcall GetOrCreateById(winrt::guid networkId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork>(this->shim().GetOrCreateById(*reinterpret_cast<winrt::guid const*>(&networkId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult> : produce_base<D, winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedWpsKinds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiWpsKind>>(this->shim().SupportedWpsKinds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::WiFi
{
    inline auto WiFiAdapter::FindAllAdaptersAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::WiFi::WiFiAdapter>>(*)(IWiFiAdapterStatics const&), WiFiAdapter, IWiFiAdapterStatics>([](IWiFiAdapterStatics const& f) { return f.FindAllAdaptersAsync(); });
    }
    inline auto WiFiAdapter::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IWiFiAdapterStatics const&), WiFiAdapter, IWiFiAdapterStatics>([](IWiFiAdapterStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto WiFiAdapter::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<WiFiAdapter, IWiFiAdapterStatics>([&](IWiFiAdapterStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto WiFiAdapter::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFi::WiFiAccessStatus>(*)(IWiFiAdapterStatics const&), WiFiAdapter, IWiFiAdapterStatics>([](IWiFiAdapterStatics const& f) { return f.RequestAccessAsync(); });
    }
    inline auto WiFiOnDemandHotspotNetwork::GetOrCreateById(winrt::guid const& networkId)
    {
        return impl::call_factory<WiFiOnDemandHotspotNetwork, IWiFiOnDemandHotspotNetworkStatics>([&](IWiFiOnDemandHotspotNetworkStatics const& f) { return f.GetOrCreateById(networkId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAdapter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAdapter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAdapterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiConnectionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiNetworkReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotConnectionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetwork> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiOnDemandHotspotNetworkStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiAdapter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiConnectionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiNetworkReport> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotConnectionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetwork> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiOnDemandHotspotNetworkProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationResult> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
