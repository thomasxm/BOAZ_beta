// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_H
#define WINRT_Windows_Devices_Bluetooth_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.Bluetooth.GenericAttributeProfile.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Rfcomm.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Devices.Radios.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::BluetoothAddress() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_BluetoothAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsClassicSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsClassicSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsLowEnergySupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsLowEnergySupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsPeripheralRoleSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsPeripheralRoleSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsCentralRoleSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsCentralRoleSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsAdvertisementOffloadSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsAdvertisementOffloadSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>) consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::GetRadioAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter)->GetRadioAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter2<D>::AreClassicSecureConnectionsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2)->get_AreClassicSecureConnectionsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter2<D>::AreLowEnergySecureConnectionsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2)->get_AreLowEnergySecureConnectionsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothAdapter3<D>::IsExtendedAdvertisingSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3)->get_IsExtendedAdvertisingSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Bluetooth_IBluetoothAdapter3<D>::MaxAdvertisementDataLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3)->get_MaxAdvertisementDataLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>) consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>) consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::RawValue() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_RawValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothMajorClass) consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::MajorClass() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothMajorClass value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_MajorClass(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothMinorClass) consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::MinorClass() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothMinorClass value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_MinorClass(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities) consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::ServiceCapabilities() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_ServiceCapabilities(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice) consume_Windows_Devices_Bluetooth_IBluetoothClassOfDeviceStatics<D>::FromRawValue(uint32_t rawValue) const
    {
        void* classOfDevice{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics)->FromRawValue(rawValue, &classOfDevice));
        return winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice{ classOfDevice, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice) consume_Windows_Devices_Bluetooth_IBluetoothClassOfDeviceStatics<D>::FromParts(winrt::Windows::Devices::Bluetooth::BluetoothMajorClass const& majorClass, winrt::Windows::Devices::Bluetooth::BluetoothMinorClass const& minorClass, winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& serviceCapabilities) const
    {
        void* classOfDevice{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics)->FromParts(static_cast<int32_t>(majorClass), static_cast<int32_t>(minorClass), static_cast<uint32_t>(serviceCapabilities), &classOfDevice));
        return winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice{ classOfDevice, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::HostName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_HostName(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ClassOfDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_ClassOfDevice(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecords() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_SdpRecords(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Streams::IBuffer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::RfcommServices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_RfcommServices(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatus() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_ConnectionStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::BluetoothAddress() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->get_BluetoothAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->add_NameChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, NameChanged_revoker>(this, NameChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->remove_NameChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->add_SdpRecordsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SdpRecordsChanged_revoker>(this, SdpRecordsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->remove_SdpRecordsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->add_ConnectionStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionStatusChanged_revoker>(this, ConnectionStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice)->remove_ConnectionStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Bluetooth_IBluetoothDevice2<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice2)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::DeviceAccessInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice3)->get_DeviceAccessInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceAccessInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>) consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::RequestAccessAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice3)->RequestAccessAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesAsync(winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesWithCacheModeAsync(static_cast<int32_t>(cacheMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesForIdAsync(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesForIdAsync(*(void**)(&serviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesForIdAsync(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId, winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesForIdWithCacheModeAsync(*(void**)(&serviceId), static_cast<int32_t>(cacheMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDeviceId) consume_Windows_Devices_Bluetooth_IBluetoothDevice4<D>::BluetoothDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice4)->get_BluetoothDeviceId(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothDeviceId{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothDevice5<D>::WasSecureConnectionUsedForPairing() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDevice5)->get_WasSecureConnectionUsedForPairing(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>::IsClassicDevice() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId)->get_IsClassicDevice(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>::IsLowEnergyDevice() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId)->get_IsLowEnergyDevice(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDeviceId) consume_Windows_Devices_Bluetooth_IBluetoothDeviceIdStatics<D>::FromId(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics)->FromId(*(void**)(&deviceId), &result));
        return winrt::Windows::Devices::Bluetooth::BluetoothDeviceId{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::FromHostNameAsync(winrt::Windows::Networking::HostName const& hostName) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->FromHostNameAsync(*(void**)(&hostName), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::FromBluetoothAddressAsync(uint64_t address) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->FromBluetoothAddressAsync(address, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::GetDeviceSelector() const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->GetDeviceSelector(&deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromPairingState(bool pairingState) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromPairingState(pairingState, &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromConnectionStatus(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromConnectionStatus(static_cast<int32_t>(connectionStatus), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromDeviceName(*(void**)(&deviceName), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromClassOfDevice(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice const& classOfDevice) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromClassOfDevice(*(void**)(&classOfDevice), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>::RawValue() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance)->get_RawValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>::Category() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance)->get_Category(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>::SubCategory() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance)->get_SubCategory(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Uncategorized() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Uncategorized(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Phone() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Phone(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Computer() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Computer(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Watch() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Watch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Clock() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Clock(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Display() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Display(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::RemoteControl() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_RemoteControl(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::EyeGlasses() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_EyeGlasses(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Tag() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Tag(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Keyring() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Keyring(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::MediaPlayer() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_MediaPlayer(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::BarcodeScanner() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_BarcodeScanner(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Thermometer() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Thermometer(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::HeartRate() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_HeartRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::BloodPressure() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_BloodPressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::HumanInterfaceDevice() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_HumanInterfaceDevice(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::GlucoseMeter() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_GlucoseMeter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::RunningWalking() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_RunningWalking(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Cycling() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Cycling(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::PulseOximeter() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_PulseOximeter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::WeightScale() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_WeightScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::OutdoorSportActivity() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_OutdoorSportActivity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceStatics<D>::FromRawValue(uint16_t rawValue) const
    {
        void* appearance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics)->FromRawValue(rawValue, &appearance));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance{ appearance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceStatics<D>::FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory) const
    {
        void* appearance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics)->FromParts(appearanceCategory, appearanceSubCategory, &appearance));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance{ appearance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Generic() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Generic(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::SportsWatch() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_SportsWatch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::ThermometerEar() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_ThermometerEar(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::HeartRateBelt() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_HeartRateBelt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::BloodPressureArm() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_BloodPressureArm(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::BloodPressureWrist() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_BloodPressureWrist(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Keyboard() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Keyboard(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Mouse() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Mouse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Joystick() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Joystick(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Gamepad() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Gamepad(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::DigitizerTablet() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_DigitizerTablet(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CardReader() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CardReader(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::DigitalPen() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_DigitalPen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::BarcodeScanner() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_BarcodeScanner(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::RunningWalkingInShoe() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_RunningWalkingInShoe(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::RunningWalkingOnShoe() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_RunningWalkingOnShoe(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::RunningWalkingOnHip() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_RunningWalkingOnHip(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingComputer() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingComputer(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingSpeedSensor() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingSpeedSensor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingCadenceSensor() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingCadenceSensor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingPowerSensor() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingPowerSensor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingSpeedCadenceSensor() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingSpeedCadenceSensor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::OximeterFingertip() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_OximeterFingertip(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::OximeterWristWorn() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_OximeterWristWorn(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationDisplay() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationDisplay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationNavigationDisplay() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationNavigationDisplay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationPod() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationPod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationNavigationPod() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationNavigationPod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionParameters<D>::LinkTimeout() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters)->get_LinkTimeout(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionParameters<D>::ConnectionLatency() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters)->get_ConnectionLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionParameters<D>::ConnectionInterval() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters)->get_ConnectionInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhy<D>::TransmitInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy)->get_TransmitInfo(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhy<D>::ReceiveInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy)->get_ReceiveInfo(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhyInfo<D>::IsUncoded1MPhy() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo)->get_IsUncoded1MPhy(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhyInfo<D>::IsUncoded2MPhy() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo)->get_IsUncoded2MPhy(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhyInfo<D>::IsCodedPhy() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo)->get_IsCodedPhy(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_GattServices(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatus() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_ConnectionStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::BluetoothAddress() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_BluetoothAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GetGattService(winrt::guid const& serviceUuid) const
    {
        void* service{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->GetGattService(impl::bind_in(serviceUuid), &service));
        return winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService{ service, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->add_NameChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, NameChanged_revoker>(this, NameChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->remove_NameChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->add_GattServicesChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, GattServicesChanged_revoker>(this, GattServicesChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->remove_GattServicesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->add_ConnectionStatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionStatusChanged_revoker>(this, ConnectionStatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice)->remove_ConnectionStatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>::Appearance() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2)->get_Appearance(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothAddressType) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>::BluetoothAddressType() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothAddressType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2)->get_BluetoothAddressType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::DeviceAccessInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3)->get_DeviceAccessInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceAccessInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesAsync(winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesWithCacheModeAsync(static_cast<int32_t>(cacheMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesForUuidAsync(winrt::guid const& serviceUuid) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesForUuidAsync(impl::bind_in(serviceUuid), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesForUuidAsync(winrt::guid const& serviceUuid, winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesForUuidWithCacheModeAsync(impl::bind_in(serviceUuid), static_cast<int32_t>(cacheMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDeviceId) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice4<D>::BluetoothDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4)->get_BluetoothDeviceId(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothDeviceId{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice5<D>::WasSecureConnectionUsedForPairing() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5)->get_WasSecureConnectionUsedForPairing(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::GetConnectionParameters() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->GetConnectionParameters(&result));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::GetConnectionPhy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->GetConnectionPhy(&result));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::RequestPreferredConnectionParameters(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters const& preferredConnectionParameters) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->RequestPreferredConnectionParameters(*(void**)(&preferredConnectionParameters), &result));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionParametersChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->add_ConnectionParametersChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionParametersChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionParametersChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionParametersChanged_revoker>(this, ConnectionParametersChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionParametersChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->remove_ConnectionParametersChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionPhyChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->add_ConnectionPhyChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionPhyChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionPhyChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionPhyChanged_revoker>(this, ConnectionPhyChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>::ConnectionPhyChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6)->remove_ConnectionPhyChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>::FromBluetoothAddressAsync(uint64_t bluetoothAddress) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics)->FromBluetoothAddressAsync(bluetoothAddress, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromPairingState(bool pairingState) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromPairingState(pairingState, &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromConnectionStatus(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromConnectionStatus(static_cast<int32_t>(connectionStatus), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromDeviceName(*(void**)(&deviceName), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, winrt::Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromBluetoothAddressWithBluetoothAddressType(bluetoothAddress, static_cast<int32_t>(bluetoothAddressType), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromAppearance(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance const& appearance) const
    {
        void* deviceSelector{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromAppearance(*(void**)(&appearance), &deviceSelector));
        return hstring{ deviceSelector, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>) consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::FromBluetoothAddressAsync(uint64_t bluetoothAddress, winrt::Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->FromBluetoothAddressWithBluetoothAddressTypeAsync(bluetoothAddress, static_cast<int32_t>(bluetoothAddressType), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParameters<D>::LinkTimeout() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters)->get_LinkTimeout(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParameters<D>::ConnectionLatency() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters)->get_ConnectionLatency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParameters<D>::MinConnectionInterval() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters)->get_MinConnectionInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParameters<D>::MaxConnectionInterval() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters)->get_MaxConnectionInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequestStatus) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersRequest<D>::Status() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequestStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersStatics<D>::Balanced() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics)->get_Balanced(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersStatics<D>::ThroughputOptimized() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics)->get_ThroughputOptimized(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters) consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersStatics<D>::PowerOptimized() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics)->get_PowerOptimized(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::InRangeThresholdInDBm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_InRangeThresholdInDBm(&value));
        return winrt::Windows::Foundation::IReference<int16_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::InRangeThresholdInDBm(winrt::Windows::Foundation::IReference<int16_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_InRangeThresholdInDBm(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeThresholdInDBm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_OutOfRangeThresholdInDBm(&value));
        return winrt::Windows::Foundation::IReference<int16_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeThresholdInDBm(winrt::Windows::Foundation::IReference<int16_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_OutOfRangeThresholdInDBm(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeTimeout() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_OutOfRangeTimeout(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeTimeout(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_OutOfRangeTimeout(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::SamplingInterval() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_SamplingInterval(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::SamplingInterval(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_SamplingInterval(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Devices_Bluetooth_IBluetoothUuidHelperStatics<D>::FromShortId(uint32_t shortId) const
    {
        winrt::guid result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics)->FromShortId(shortId, put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Devices_Bluetooth_IBluetoothUuidHelperStatics<D>::TryGetShortId(winrt::guid const& uuid) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics)->TryGetShortId(impl::bind_in(uuid), &result));
        return winrt::Windows::Foundation::IReference<uint32_t>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapter> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapter>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BluetoothAddress(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsClassicSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsClassicSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLowEnergySupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLowEnergySupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPeripheralRoleSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPeripheralRoleSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCentralRoleSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCentralRoleSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAdvertisementOffloadSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAdvertisementOffloadSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRadioAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>>(this->shim().GetRadioAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2>
    {
        int32_t __stdcall get_AreClassicSecureConnectionsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreClassicSecureConnectionsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AreLowEnergySecureConnectionsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreLowEnergySecureConnectionsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3>
    {
        int32_t __stdcall get_IsExtendedAdvertisingSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsExtendedAdvertisingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAdvertisementDataLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxAdvertisementDataLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics>
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
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice>
    {
        int32_t __stdcall get_RawValue(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RawValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MajorClass(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothMajorClass>(this->shim().MajorClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinorClass(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothMinorClass>(this->shim().MinorClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceCapabilities(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities>(this->shim().ServiceCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>
    {
        int32_t __stdcall FromRawValue(uint32_t rawValue, void** classOfDevice) noexcept final try
        {
            clear_abi(classOfDevice);
            typename D::abi_guard guard(this->shim());
            *classOfDevice = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice>(this->shim().FromRawValue(rawValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromParts(int32_t majorClass, int32_t minorClass, uint32_t serviceCapabilities, void** classOfDevice) noexcept final try
        {
            clear_abi(classOfDevice);
            typename D::abi_guard guard(this->shim());
            *classOfDevice = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice>(this->shim().FromParts(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothMajorClass const*>(&majorClass), *reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothMinorClass const*>(&minorClass), *reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities const*>(&serviceCapabilities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HostName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().HostName());
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
        int32_t __stdcall get_ClassOfDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice>(this->shim().ClassOfDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SdpRecords(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().SdpRecords());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RfcommServices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>>(this->shim().RfcommServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus>(this->shim().ConnectionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BluetoothAddress(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_NameChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NameChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NameChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SdpRecordsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SdpRecordsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SdpRecordsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SdpRecordsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ConnectionStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice2> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice2>
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
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice3> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice3>
    {
        int32_t __stdcall get_DeviceAccessInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().DeviceAccessInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRfcommServicesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRfcommServicesWithCacheModeAsync(int32_t cacheMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesAsync(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRfcommServicesForIdAsync(void* serviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesForIdAsync(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRfcommServicesForIdWithCacheModeAsync(void* serviceId, int32_t cacheMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesForIdAsync(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId), *reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice4> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice4>
    {
        int32_t __stdcall get_BluetoothDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().BluetoothDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice5> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDevice5>
    {
        int32_t __stdcall get_WasSecureConnectionUsedForPairing(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasSecureConnectionUsedForPairing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsClassicDevice(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsClassicDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLowEnergyDevice(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLowEnergyDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>
    {
        int32_t __stdcall FromId(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromHostNameAsync(void* hostName, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>>(this->shim().FromHostNameAsync(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&hostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromBluetoothAddressAsync(uint64_t address, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>>(this->shim().FromBluetoothAddressAsync(address));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>
    {
        int32_t __stdcall GetDeviceSelectorFromPairingState(bool pairingState, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromPairingState(pairingState));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromConnectionStatus(int32_t connectionStatus, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromConnectionStatus(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const*>(&connectionStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromDeviceName(void* deviceName, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromDeviceName(*reinterpret_cast<hstring const*>(&deviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromBluetoothAddress(bluetoothAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromClassOfDevice(void* classOfDevice, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromClassOfDevice(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice const*>(&classOfDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance>
    {
        int32_t __stdcall get_RawValue(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RawValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Category(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubCategory(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().SubCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>
    {
        int32_t __stdcall get_Uncategorized(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Uncategorized());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Phone(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Phone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Computer(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Computer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Watch(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Watch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Clock(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Clock());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Display(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Display());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteControl(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RemoteControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EyeGlasses(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().EyeGlasses());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Keyring(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Keyring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaPlayer(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BarcodeScanner(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BarcodeScanner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thermometer(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Thermometer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeartRate(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().HeartRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BloodPressure(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BloodPressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HumanInterfaceDevice(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().HumanInterfaceDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GlucoseMeter(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().GlucoseMeter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RunningWalking(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RunningWalking());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cycling(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Cycling());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PulseOximeter(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().PulseOximeter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WeightScale(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().WeightScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutdoorSportActivity(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().OutdoorSportActivity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>
    {
        int32_t __stdcall FromRawValue(uint16_t rawValue, void** appearance) noexcept final try
        {
            clear_abi(appearance);
            typename D::abi_guard guard(this->shim());
            *appearance = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance>(this->shim().FromRawValue(rawValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory, void** appearance) noexcept final try
        {
            clear_abi(appearance);
            typename D::abi_guard guard(this->shim());
            *appearance = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance>(this->shim().FromParts(appearanceCategory, appearanceSubCategory));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>
    {
        int32_t __stdcall get_Generic(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Generic());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SportsWatch(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().SportsWatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThermometerEar(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ThermometerEar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HeartRateBelt(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().HeartRateBelt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BloodPressureArm(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BloodPressureArm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BloodPressureWrist(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BloodPressureWrist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Keyboard(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Keyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mouse(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Mouse());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Joystick(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Joystick());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gamepad(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Gamepad());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DigitizerTablet(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().DigitizerTablet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CardReader(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CardReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DigitalPen(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().DigitalPen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BarcodeScanner(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BarcodeScanner());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RunningWalkingInShoe(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RunningWalkingInShoe());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RunningWalkingOnShoe(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RunningWalkingOnShoe());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RunningWalkingOnHip(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RunningWalkingOnHip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CyclingComputer(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CyclingComputer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CyclingSpeedSensor(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CyclingSpeedSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CyclingCadenceSensor(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CyclingCadenceSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CyclingPowerSensor(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CyclingPowerSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CyclingSpeedCadenceSensor(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CyclingSpeedCadenceSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OximeterFingertip(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().OximeterFingertip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OximeterWristWorn(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().OximeterWristWorn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocationDisplay(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().LocationDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocationNavigationDisplay(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().LocationNavigationDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocationPod(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().LocationPod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocationNavigationPod(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().LocationNavigationPod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters>
    {
        int32_t __stdcall get_LinkTimeout(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().LinkTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionLatency(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ConnectionLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionInterval(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ConnectionInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy>
    {
        int32_t __stdcall get_TransmitInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo>(this->shim().TransmitInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReceiveInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo>(this->shim().ReceiveInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo>
    {
        int32_t __stdcall get_IsUncoded1MPhy(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUncoded1MPhy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsUncoded2MPhy(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUncoded2MPhy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCodedPhy(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCodedPhy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
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
        int32_t __stdcall get_GattServices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().GattServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus>(this->shim().ConnectionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BluetoothAddress(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGattService(winrt::guid serviceUuid, void** service) noexcept final try
        {
            clear_abi(service);
            typename D::abi_guard guard(this->shim());
            *service = detach_from<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>(this->shim().GetGattService(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_NameChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NameChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NameChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_GattServicesChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().GattServicesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GattServicesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GattServicesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ConnectionStatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionStatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2>
    {
        int32_t __stdcall get_DeviceInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Appearance(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BluetoothAddressType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothAddressType>(this->shim().BluetoothAddressType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3>
    {
        int32_t __stdcall get_DeviceAccessInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().DeviceAccessInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGattServicesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGattServicesWithCacheModeAsync(int32_t cacheMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesAsync(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGattServicesForUuidAsync(winrt::guid serviceUuid, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesForUuidAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGattServicesForUuidWithCacheModeAsync(winrt::guid serviceUuid, int32_t cacheMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesForUuidAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid), *reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4>
    {
        int32_t __stdcall get_BluetoothDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().BluetoothDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5>
    {
        int32_t __stdcall get_WasSecureConnectionUsedForPairing(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().WasSecureConnectionUsedForPairing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>
    {
        int32_t __stdcall GetConnectionParameters(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters>(this->shim().GetConnectionParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConnectionPhy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy>(this->shim().GetConnectionPhy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestPreferredConnectionParameters(void* preferredConnectionParameters, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest>(this->shim().RequestPreferredConnectionParameters(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters const*>(&preferredConnectionParameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ConnectionParametersChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionParametersChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionParametersChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionParametersChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ConnectionPhyChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionPhyChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionPhyChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionPhyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromBluetoothAddressAsync(uint64_t bluetoothAddress, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>>(this->shim().FromBluetoothAddressAsync(bluetoothAddress));
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
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>
    {
        int32_t __stdcall GetDeviceSelectorFromPairingState(bool pairingState, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromPairingState(pairingState));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromConnectionStatus(int32_t connectionStatus, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromConnectionStatus(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const*>(&connectionStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromDeviceName(void* deviceName, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromDeviceName(*reinterpret_cast<hstring const*>(&deviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromBluetoothAddress(bluetoothAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromBluetoothAddressWithBluetoothAddressType(uint64_t bluetoothAddress, int32_t bluetoothAddressType, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, *reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothAddressType const*>(&bluetoothAddressType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromAppearance(void* appearance, void** deviceSelector) noexcept final try
        {
            clear_abi(deviceSelector);
            typename D::abi_guard guard(this->shim());
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromAppearance(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance const*>(&appearance)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromBluetoothAddressWithBluetoothAddressTypeAsync(uint64_t bluetoothAddress, int32_t bluetoothAddressType, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>>(this->shim().FromBluetoothAddressAsync(bluetoothAddress, *reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothAddressType const*>(&bluetoothAddressType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters>
    {
        int32_t __stdcall get_LinkTimeout(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().LinkTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionLatency(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ConnectionLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinConnectionInterval(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().MinConnectionInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxConnectionInterval(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().MaxConnectionInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequestStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics>
    {
        int32_t __stdcall get_Balanced(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters>(this->shim().Balanced());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ThroughputOptimized(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters>(this->shim().ThroughputOptimized());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PowerOptimized(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters>(this->shim().PowerOptimized());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter>
    {
        int32_t __stdcall get_InRangeThresholdInDBm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int16_t>>(this->shim().InRangeThresholdInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InRangeThresholdInDBm(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InRangeThresholdInDBm(*reinterpret_cast<winrt::Windows::Foundation::IReference<int16_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutOfRangeThresholdInDBm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int16_t>>(this->shim().OutOfRangeThresholdInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutOfRangeThresholdInDBm(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutOfRangeThresholdInDBm(*reinterpret_cast<winrt::Windows::Foundation::IReference<int16_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutOfRangeTimeout(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().OutOfRangeTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutOfRangeTimeout(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutOfRangeTimeout(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SamplingInterval(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().SamplingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SamplingInterval(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SamplingInterval(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>
    {
        int32_t __stdcall FromShortId(uint32_t shortId, winrt::guid* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::guid>(this->shim().FromShortId(shortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetShortId(winrt::guid uuid, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().TryGetShortId(*reinterpret_cast<winrt::guid const*>(&uuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth
{
    constexpr auto operator|(BluetoothServiceCapabilities const left, BluetoothServiceCapabilities const right) noexcept
    {
        return static_cast<BluetoothServiceCapabilities>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(BluetoothServiceCapabilities& left, BluetoothServiceCapabilities const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(BluetoothServiceCapabilities const left, BluetoothServiceCapabilities const right) noexcept
    {
        return static_cast<BluetoothServiceCapabilities>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(BluetoothServiceCapabilities& left, BluetoothServiceCapabilities const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(BluetoothServiceCapabilities const value) noexcept
    {
        return static_cast<BluetoothServiceCapabilities>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(BluetoothServiceCapabilities const left, BluetoothServiceCapabilities const right) noexcept
    {
        return static_cast<BluetoothServiceCapabilities>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(BluetoothServiceCapabilities& left, BluetoothServiceCapabilities const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto BluetoothAdapter::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IBluetoothAdapterStatics const&), BluetoothAdapter, IBluetoothAdapterStatics>([](IBluetoothAdapterStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto BluetoothAdapter::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<BluetoothAdapter, IBluetoothAdapterStatics>([&](IBluetoothAdapterStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto BluetoothAdapter::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>(*)(IBluetoothAdapterStatics const&), BluetoothAdapter, IBluetoothAdapterStatics>([](IBluetoothAdapterStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto BluetoothClassOfDevice::FromRawValue(uint32_t rawValue)
    {
        return impl::call_factory<BluetoothClassOfDevice, IBluetoothClassOfDeviceStatics>([&](IBluetoothClassOfDeviceStatics const& f) { return f.FromRawValue(rawValue); });
    }
    inline auto BluetoothClassOfDevice::FromParts(winrt::Windows::Devices::Bluetooth::BluetoothMajorClass const& majorClass, winrt::Windows::Devices::Bluetooth::BluetoothMinorClass const& minorClass, winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& serviceCapabilities)
    {
        return impl::call_factory<BluetoothClassOfDevice, IBluetoothClassOfDeviceStatics>([&](IBluetoothClassOfDeviceStatics const& f) { return f.FromParts(majorClass, minorClass, serviceCapabilities); });
    }
    inline auto BluetoothDevice::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics>([&](IBluetoothDeviceStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto BluetoothDevice::FromHostNameAsync(winrt::Windows::Networking::HostName const& hostName)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics>([&](IBluetoothDeviceStatics const& f) { return f.FromHostNameAsync(hostName); });
    }
    inline auto BluetoothDevice::FromBluetoothAddressAsync(uint64_t address)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics>([&](IBluetoothDeviceStatics const& f) { return f.FromBluetoothAddressAsync(address); });
    }
    inline auto BluetoothDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IBluetoothDeviceStatics const&), BluetoothDevice, IBluetoothDeviceStatics>([](IBluetoothDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto BluetoothDevice::GetDeviceSelectorFromPairingState(bool pairingState)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics2>([&](IBluetoothDeviceStatics2 const& f) { return f.GetDeviceSelectorFromPairingState(pairingState); });
    }
    inline auto BluetoothDevice::GetDeviceSelectorFromConnectionStatus(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics2>([&](IBluetoothDeviceStatics2 const& f) { return f.GetDeviceSelectorFromConnectionStatus(connectionStatus); });
    }
    inline auto BluetoothDevice::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics2>([&](IBluetoothDeviceStatics2 const& f) { return f.GetDeviceSelectorFromDeviceName(deviceName); });
    }
    inline auto BluetoothDevice::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics2>([&](IBluetoothDeviceStatics2 const& f) { return f.GetDeviceSelectorFromBluetoothAddress(bluetoothAddress); });
    }
    inline auto BluetoothDevice::GetDeviceSelectorFromClassOfDevice(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice const& classOfDevice)
    {
        return impl::call_factory<BluetoothDevice, IBluetoothDeviceStatics2>([&](IBluetoothDeviceStatics2 const& f) { return f.GetDeviceSelectorFromClassOfDevice(classOfDevice); });
    }
    inline auto BluetoothDeviceId::FromId(param::hstring const& deviceId)
    {
        return impl::call_factory<BluetoothDeviceId, IBluetoothDeviceIdStatics>([&](IBluetoothDeviceIdStatics const& f) { return f.FromId(deviceId); });
    }
    inline auto BluetoothLEAppearance::FromRawValue(uint16_t rawValue)
    {
        return impl::call_factory<BluetoothLEAppearance, IBluetoothLEAppearanceStatics>([&](IBluetoothLEAppearanceStatics const& f) { return f.FromRawValue(rawValue); });
    }
    inline auto BluetoothLEAppearance::FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory)
    {
        return impl::call_factory<BluetoothLEAppearance, IBluetoothLEAppearanceStatics>([&](IBluetoothLEAppearanceStatics const& f) { return f.FromParts(appearanceCategory, appearanceSubCategory); });
    }
    inline auto BluetoothLEAppearanceCategories::Uncategorized()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Uncategorized(); });
    }
    inline auto BluetoothLEAppearanceCategories::Phone()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Phone(); });
    }
    inline auto BluetoothLEAppearanceCategories::Computer()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Computer(); });
    }
    inline auto BluetoothLEAppearanceCategories::Watch()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Watch(); });
    }
    inline auto BluetoothLEAppearanceCategories::Clock()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Clock(); });
    }
    inline auto BluetoothLEAppearanceCategories::Display()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Display(); });
    }
    inline auto BluetoothLEAppearanceCategories::RemoteControl()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.RemoteControl(); });
    }
    inline auto BluetoothLEAppearanceCategories::EyeGlasses()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.EyeGlasses(); });
    }
    inline auto BluetoothLEAppearanceCategories::Tag()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Tag(); });
    }
    inline auto BluetoothLEAppearanceCategories::Keyring()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Keyring(); });
    }
    inline auto BluetoothLEAppearanceCategories::MediaPlayer()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.MediaPlayer(); });
    }
    inline auto BluetoothLEAppearanceCategories::BarcodeScanner()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.BarcodeScanner(); });
    }
    inline auto BluetoothLEAppearanceCategories::Thermometer()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Thermometer(); });
    }
    inline auto BluetoothLEAppearanceCategories::HeartRate()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.HeartRate(); });
    }
    inline auto BluetoothLEAppearanceCategories::BloodPressure()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.BloodPressure(); });
    }
    inline auto BluetoothLEAppearanceCategories::HumanInterfaceDevice()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.HumanInterfaceDevice(); });
    }
    inline auto BluetoothLEAppearanceCategories::GlucoseMeter()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.GlucoseMeter(); });
    }
    inline auto BluetoothLEAppearanceCategories::RunningWalking()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.RunningWalking(); });
    }
    inline auto BluetoothLEAppearanceCategories::Cycling()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.Cycling(); });
    }
    inline auto BluetoothLEAppearanceCategories::PulseOximeter()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.PulseOximeter(); });
    }
    inline auto BluetoothLEAppearanceCategories::WeightScale()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.WeightScale(); });
    }
    inline auto BluetoothLEAppearanceCategories::OutdoorSportActivity()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceCategoriesStatics const&), BluetoothLEAppearanceCategories, IBluetoothLEAppearanceCategoriesStatics>([](IBluetoothLEAppearanceCategoriesStatics const& f) { return f.OutdoorSportActivity(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::Generic()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.Generic(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::SportsWatch()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.SportsWatch(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::ThermometerEar()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.ThermometerEar(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::HeartRateBelt()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.HeartRateBelt(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::BloodPressureArm()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.BloodPressureArm(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::BloodPressureWrist()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.BloodPressureWrist(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::Keyboard()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.Keyboard(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::Mouse()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.Mouse(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::Joystick()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.Joystick(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::Gamepad()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.Gamepad(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::DigitizerTablet()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.DigitizerTablet(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::CardReader()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.CardReader(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::DigitalPen()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.DigitalPen(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::BarcodeScanner()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.BarcodeScanner(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::RunningWalkingInShoe()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.RunningWalkingInShoe(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::RunningWalkingOnShoe()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.RunningWalkingOnShoe(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::RunningWalkingOnHip()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.RunningWalkingOnHip(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::CyclingComputer()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.CyclingComputer(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::CyclingSpeedSensor()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.CyclingSpeedSensor(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::CyclingCadenceSensor()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.CyclingCadenceSensor(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::CyclingPowerSensor()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.CyclingPowerSensor(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::CyclingSpeedCadenceSensor()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.CyclingSpeedCadenceSensor(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::OximeterFingertip()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.OximeterFingertip(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::OximeterWristWorn()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.OximeterWristWorn(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::LocationDisplay()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.LocationDisplay(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::LocationNavigationDisplay()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.LocationNavigationDisplay(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::LocationPod()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.LocationPod(); });
    }
    inline auto BluetoothLEAppearanceSubcategories::LocationNavigationPod()
    {
        return impl::call_factory_cast<uint16_t(*)(IBluetoothLEAppearanceSubcategoriesStatics const&), BluetoothLEAppearanceSubcategories, IBluetoothLEAppearanceSubcategoriesStatics>([](IBluetoothLEAppearanceSubcategoriesStatics const& f) { return f.LocationNavigationPod(); });
    }
    inline auto BluetoothLEDevice::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics>([&](IBluetoothLEDeviceStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto BluetoothLEDevice::FromBluetoothAddressAsync(uint64_t bluetoothAddress)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics>([&](IBluetoothLEDeviceStatics const& f) { return f.FromBluetoothAddressAsync(bluetoothAddress); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IBluetoothLEDeviceStatics const&), BluetoothLEDevice, IBluetoothLEDeviceStatics>([](IBluetoothLEDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelectorFromPairingState(bool pairingState)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.GetDeviceSelectorFromPairingState(pairingState); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelectorFromConnectionStatus(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.GetDeviceSelectorFromConnectionStatus(connectionStatus); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.GetDeviceSelectorFromDeviceName(deviceName); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.GetDeviceSelectorFromBluetoothAddress(bluetoothAddress); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, winrt::Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, bluetoothAddressType); });
    }
    inline auto BluetoothLEDevice::GetDeviceSelectorFromAppearance(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance const& appearance)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.GetDeviceSelectorFromAppearance(appearance); });
    }
    inline auto BluetoothLEDevice::FromBluetoothAddressAsync(uint64_t bluetoothAddress, winrt::Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType)
    {
        return impl::call_factory<BluetoothLEDevice, IBluetoothLEDeviceStatics2>([&](IBluetoothLEDeviceStatics2 const& f) { return f.FromBluetoothAddressAsync(bluetoothAddress, bluetoothAddressType); });
    }
    inline auto BluetoothLEPreferredConnectionParameters::Balanced()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters(*)(IBluetoothLEPreferredConnectionParametersStatics const&), BluetoothLEPreferredConnectionParameters, IBluetoothLEPreferredConnectionParametersStatics>([](IBluetoothLEPreferredConnectionParametersStatics const& f) { return f.Balanced(); });
    }
    inline auto BluetoothLEPreferredConnectionParameters::ThroughputOptimized()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters(*)(IBluetoothLEPreferredConnectionParametersStatics const&), BluetoothLEPreferredConnectionParameters, IBluetoothLEPreferredConnectionParametersStatics>([](IBluetoothLEPreferredConnectionParametersStatics const& f) { return f.ThroughputOptimized(); });
    }
    inline auto BluetoothLEPreferredConnectionParameters::PowerOptimized()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters(*)(IBluetoothLEPreferredConnectionParametersStatics const&), BluetoothLEPreferredConnectionParameters, IBluetoothLEPreferredConnectionParametersStatics>([](IBluetoothLEPreferredConnectionParametersStatics const& f) { return f.PowerOptimized(); });
    }
    inline BluetoothSignalStrengthFilter::BluetoothSignalStrengthFilter() :
        BluetoothSignalStrengthFilter(impl::call_factory_cast<BluetoothSignalStrengthFilter(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothSignalStrengthFilter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothSignalStrengthFilter>(); }))
    {
    }
    inline auto BluetoothUuidHelper::FromShortId(uint32_t shortId)
    {
        return impl::call_factory<BluetoothUuidHelper, IBluetoothUuidHelperStatics>([&](IBluetoothUuidHelperStatics const& f) { return f.FromShortId(shortId); });
    }
    inline auto BluetoothUuidHelper::TryGetShortId(winrt::guid const& uuid)
    {
        return impl::call_factory<BluetoothUuidHelper, IBluetoothUuidHelperStatics>([&](IBluetoothUuidHelperStatics const& f) { return f.TryGetShortId(uuid); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothAdapter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceCategories> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceSubcategories> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothUuidHelper> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
