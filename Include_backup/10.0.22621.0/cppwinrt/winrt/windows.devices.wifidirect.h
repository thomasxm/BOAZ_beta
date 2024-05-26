// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_WiFiDirect_H
#define WINRT_Windows_Devices_WiFiDirect_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.WiFiDirect.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::InformationElements() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->get_InformationElements(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::InformationElements(param::vector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->put_InformationElements(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementListenStateDiscoverability) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::ListenStateDiscoverability() const
    {
        winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementListenStateDiscoverability value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->get_ListenStateDiscoverability(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::ListenStateDiscoverability(winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementListenStateDiscoverability const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->put_ListenStateDiscoverability(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::IsAutonomousGroupOwnerEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->get_IsAutonomousGroupOwnerEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::IsAutonomousGroupOwnerEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->put_IsAutonomousGroupOwnerEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectLegacySettings) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement<D>::LegacySettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement)->get_LegacySettings(&value));
        return winrt::Windows::Devices::WiFiDirect::WiFiDirectLegacySettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod>) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisement2<D>::SupportedConfigurationMethods() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement2)->get_SupportedConfigurationMethods(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisement) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::Advertisement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher)->get_Advertisement(&value));
        return winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::Status() const
    {
        winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher, winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher)->add_StatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::StatusChanged_revoker consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher, winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectError) consume_Windows_Devices_WiFiDirect_IWiFiDirectAdvertisementPublisherStatusChangedEventArgs<D>::Error() const
    {
        winrt::Windows::Devices::WiFiDirect::WiFiDirectError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs)->get_Error(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionListener<D>::ConnectionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener, winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener)->add_ConnectionRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionListener<D>::ConnectionRequested_revoker consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionListener<D>::ConnectionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener, winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionRequested_revoker>(this, ConnectionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionListener<D>::ConnectionRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener)->remove_ConnectionRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(int16_t) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionParameters<D>::GroupOwnerIntent() const
    {
        int16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters)->get_GroupOwnerIntent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionParameters<D>::GroupOwnerIntent(int16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters)->put_GroupOwnerIntent(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod>) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionParameters2<D>::PreferenceOrderedConfigurationMethods() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2)->get_PreferenceOrderedConfigurationMethods(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectPairingProcedure) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionParameters2<D>::PreferredPairingProcedure() const
    {
        winrt::Windows::Devices::WiFiDirect::WiFiDirectPairingProcedure value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2)->get_PreferredPairingProcedure(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionParameters2<D>::PreferredPairingProcedure(winrt::Windows::Devices::WiFiDirect::WiFiDirectPairingProcedure const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2)->put_PreferredPairingProcedure(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DevicePairingKinds) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionParametersStatics<D>::GetDevicePairingKinds(winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod const& configurationMethod) const
    {
        winrt::Windows::Devices::Enumeration::DevicePairingKinds result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParametersStatics)->GetDevicePairingKinds(static_cast<int32_t>(configurationMethod), reinterpret_cast<uint32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionRequest<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequest)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequest) consume_Windows_Devices_WiFiDirect_IWiFiDirectConnectionRequestedEventArgs<D>::GetConnectionRequest() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs)->GetConnectionRequest(&result));
        return winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequest{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionStatus) consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::ConnectionStatus() const
    {
        winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice)->get_ConnectionStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::ConnectionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice)->add_ConnectionStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::ConnectionStatusChanged_revoker consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::ConnectionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionStatusChanged_revoker>(this, ConnectionStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::ConnectionStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice)->remove_ConnectionStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>) consume_Windows_Devices_WiFiDirect_IWiFiDirectDevice<D>::GetConnectionEndpointPairs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice)->GetConnectionEndpointPairs(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_IWiFiDirectDeviceStatics<D>::GetDeviceSelector() const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics)->GetDeviceSelector(&deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice>) consume_Windows_Devices_WiFiDirect_IWiFiDirectDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* asyncOp{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics)->FromIdAsync(*(void**)(&deviceId), &asyncOp));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice>{ asyncOp, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_IWiFiDirectDeviceStatics2<D>::GetDeviceSelector(winrt::Windows::Devices::WiFiDirect::WiFiDirectDeviceSelectorType const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics2)->GetDeviceSelector(static_cast<int32_t>(type), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice>) consume_Windows_Devices_WiFiDirect_IWiFiDirectDeviceStatics2<D>::FromIdAsync(param::hstring const& deviceId, winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters const& connectionParameters) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics2)->FromIdAsync(*(void**)(&deviceId), *(void**)(&connectionParameters), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElement<D>::Oui() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement)->get_Oui(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElement<D>::Oui(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement)->put_Oui(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElement<D>::OuiType() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement)->get_OuiType(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElement<D>::OuiType(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement)->put_OuiType(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElement<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement)->get_Value(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElement<D>::Value(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElementStatics<D>::CreateFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElementStatics)->CreateFromBuffer(*(void**)(&buffer), &result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>) consume_Windows_Devices_WiFiDirect_IWiFiDirectInformationElementStatics<D>::CreateFromDeviceInformation(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInformation) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElementStatics)->CreateFromDeviceInformation(*(void**)(&deviceInformation), &result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_WiFiDirect_IWiFiDirectLegacySettings<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectLegacySettings<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_WiFiDirect_IWiFiDirectLegacySettings<D>::Ssid() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings)->get_Ssid(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectLegacySettings<D>::Ssid(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings)->put_Ssid(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Devices_WiFiDirect_IWiFiDirectLegacySettings<D>::Passphrase() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings)->get_Passphrase(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_WiFiDirect_IWiFiDirectLegacySettings<D>::Passphrase(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings)->put_Passphrase(*(void**)(&value)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement>
    {
        int32_t __stdcall get_InformationElements(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>>(this->shim().InformationElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InformationElements(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InformationElements(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ListenStateDiscoverability(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementListenStateDiscoverability>(this->shim().ListenStateDiscoverability());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ListenStateDiscoverability(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ListenStateDiscoverability(*reinterpret_cast<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementListenStateDiscoverability const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAutonomousGroupOwnerEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAutonomousGroupOwnerEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAutonomousGroupOwnerEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAutonomousGroupOwnerEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LegacySettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectLegacySettings>(this->shim().LegacySettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement2> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement2>
    {
        int32_t __stdcall get_SupportedConfigurationMethods(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod>>(this->shim().SupportedConfigurationMethods());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher>
    {
        int32_t __stdcall get_Advertisement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisement>(this->shim().Advertisement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher, winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Error(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener>
    {
        int32_t __stdcall add_ConnectionRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener, winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters>
    {
        int32_t __stdcall get_GroupOwnerIntent(int16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int16_t>(this->shim().GroupOwnerIntent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_GroupOwnerIntent(int16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GroupOwnerIntent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2>
    {
        int32_t __stdcall get_PreferenceOrderedConfigurationMethods(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod>>(this->shim().PreferenceOrderedConfigurationMethods());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreferredPairingProcedure(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectPairingProcedure>(this->shim().PreferredPairingProcedure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferredPairingProcedure(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferredPairingProcedure(*reinterpret_cast<winrt::Windows::Devices::WiFiDirect::WiFiDirectPairingProcedure const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParametersStatics> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParametersStatics>
    {
        int32_t __stdcall GetDevicePairingKinds(int32_t configurationMethod, uint32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Enumeration::DevicePairingKinds>(this->shim().GetDevicePairingKinds(*reinterpret_cast<winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod const*>(&configurationMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequest> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequest>
    {
        int32_t __stdcall get_DeviceInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs>
    {
        int32_t __stdcall GetConnectionRequest(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequest>(this->shim().GetConnectionRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice>
    {
        int32_t __stdcall get_ConnectionStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionStatus>(this->shim().ConnectionStatus());
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
        int32_t __stdcall add_ConnectionStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetConnectionEndpointPairs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::EndpointPair>>(this->shim().GetConnectionEndpointPairs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics>
    {
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
            *asyncOp = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics2> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics2>
    {
        int32_t __stdcall GetDeviceSelector(int32_t type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::Windows::Devices::WiFiDirect::WiFiDirectDeviceSelectorType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void* connectionParameters, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters const*>(&connectionParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement>
    {
        int32_t __stdcall get_Oui(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Oui());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Oui(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Oui(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OuiType(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().OuiType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OuiType(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OuiType(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElementStatics> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElementStatics>
    {
        int32_t __stdcall CreateFromBuffer(void* buffer, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>>(this->shim().CreateFromBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromDeviceInformation(void* deviceInformation, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement>>(this->shim().CreateFromDeviceInformation(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&deviceInformation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings> : produce_base<D, winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
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
        int32_t __stdcall get_Passphrase(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().Passphrase());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Passphrase(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Passphrase(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::WiFiDirect
{
    inline WiFiDirectAdvertisementPublisher::WiFiDirectAdvertisementPublisher() :
        WiFiDirectAdvertisementPublisher(impl::call_factory_cast<WiFiDirectAdvertisementPublisher(*)(winrt::Windows::Foundation::IActivationFactory const&), WiFiDirectAdvertisementPublisher>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WiFiDirectAdvertisementPublisher>(); }))
    {
    }
    inline WiFiDirectConnectionListener::WiFiDirectConnectionListener() :
        WiFiDirectConnectionListener(impl::call_factory_cast<WiFiDirectConnectionListener(*)(winrt::Windows::Foundation::IActivationFactory const&), WiFiDirectConnectionListener>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WiFiDirectConnectionListener>(); }))
    {
    }
    inline WiFiDirectConnectionParameters::WiFiDirectConnectionParameters() :
        WiFiDirectConnectionParameters(impl::call_factory_cast<WiFiDirectConnectionParameters(*)(winrt::Windows::Foundation::IActivationFactory const&), WiFiDirectConnectionParameters>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WiFiDirectConnectionParameters>(); }))
    {
    }
    inline auto WiFiDirectConnectionParameters::GetDevicePairingKinds(winrt::Windows::Devices::WiFiDirect::WiFiDirectConfigurationMethod const& configurationMethod)
    {
        return impl::call_factory<WiFiDirectConnectionParameters, IWiFiDirectConnectionParametersStatics>([&](IWiFiDirectConnectionParametersStatics const& f) { return f.GetDevicePairingKinds(configurationMethod); });
    }
    inline auto WiFiDirectDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IWiFiDirectDeviceStatics const&), WiFiDirectDevice, IWiFiDirectDeviceStatics>([](IWiFiDirectDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto WiFiDirectDevice::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<WiFiDirectDevice, IWiFiDirectDeviceStatics>([&](IWiFiDirectDeviceStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto WiFiDirectDevice::GetDeviceSelector(winrt::Windows::Devices::WiFiDirect::WiFiDirectDeviceSelectorType const& type)
    {
        return impl::call_factory<WiFiDirectDevice, IWiFiDirectDeviceStatics2>([&](IWiFiDirectDeviceStatics2 const& f) { return f.GetDeviceSelector(type); });
    }
    inline auto WiFiDirectDevice::FromIdAsync(param::hstring const& deviceId, winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters const& connectionParameters)
    {
        return impl::call_factory<WiFiDirectDevice, IWiFiDirectDeviceStatics2>([&](IWiFiDirectDeviceStatics2 const& f) { return f.FromIdAsync(deviceId, connectionParameters); });
    }
    inline WiFiDirectInformationElement::WiFiDirectInformationElement() :
        WiFiDirectInformationElement(impl::call_factory_cast<WiFiDirectInformationElement(*)(winrt::Windows::Foundation::IActivationFactory const&), WiFiDirectInformationElement>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WiFiDirectInformationElement>(); }))
    {
    }
    inline auto WiFiDirectInformationElement::CreateFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer)
    {
        return impl::call_factory<WiFiDirectInformationElement, IWiFiDirectInformationElementStatics>([&](IWiFiDirectInformationElementStatics const& f) { return f.CreateFromBuffer(buffer); });
    }
    inline auto WiFiDirectInformationElement::CreateFromDeviceInformation(winrt::Windows::Devices::Enumeration::DeviceInformation const& deviceInformation)
    {
        return impl::call_factory<WiFiDirectInformationElement, IWiFiDirectInformationElementStatics>([&](IWiFiDirectInformationElementStatics const& f) { return f.CreateFromDeviceInformation(deviceInformation); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisement2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectAdvertisementPublisherStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParameters2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionParametersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectConnectionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectDeviceStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectInformationElementStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::IWiFiDirectLegacySettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectAdvertisementPublisherStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectConnectionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectInformationElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::WiFiDirect::WiFiDirectLegacySettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
