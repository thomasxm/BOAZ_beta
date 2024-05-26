// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_Advertisement_H
#define WINRT_Windows_Devices_Bluetooth_Advertisement_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Bluetooth.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Advertisement.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::Flags() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_Flags(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::Flags(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->put_Flags(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::LocalName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_LocalName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::LocalName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->put_LocalName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::guid>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::ServiceUuids() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_ServiceUuids(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::guid>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::ManufacturerData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_ManufacturerData(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::DataSections() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_DataSections(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::GetManufacturerDataByCompanyId(uint16_t companyId) const
    {
        void* dataList{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->GetManufacturerDataByCompanyId(companyId, &dataList));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>{ dataList, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::GetSectionsByType(uint8_t type) const
    {
        void* sectionList{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->GetSectionsByType(type, &sectionList));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>{ sectionList, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::DataType() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->get_DataType(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::DataType(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->put_DataType(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int16_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Offset() const
    {
        int16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->get_Offset(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Offset(int16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->put_Offset(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Data(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePatternFactory<D>::Create(uint8_t dataType, int16_t offset, winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory)->Create(dataType, offset, *(void**)(&data), &value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::DataType() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->get_DataType(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::DataType(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->put_DataType(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::Data(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSectionFactory<D>::Create(uint8_t dataType, winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory)->Create(dataType, *(void**)(&data), &value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::Flags() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_Flags(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::IncompleteService16BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_IncompleteService16BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteService16BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteService16BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::IncompleteService32BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_IncompleteService32BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteService32BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteService32BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::IncompleteService128BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_IncompleteService128BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteService128BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteService128BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ShortenedLocalName() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ShortenedLocalName(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteLocalName() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteLocalName(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::TxPowerLevel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_TxPowerLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::PeripheralConnectionIntervalRange() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_PeripheralConnectionIntervalRange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceSolicitation16BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceSolicitation16BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceSolicitation32BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceSolicitation32BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceSolicitation128BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceSolicitation128BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceData16BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceData16BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceData32BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceData32BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceData128BitUuids() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceData128BitUuids(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::PublicTargetAddress() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_PublicTargetAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::RandomTargetAddress() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_RandomTargetAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::Appearance() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_Appearance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::AdvertisingInterval() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_AdvertisingInterval(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ManufacturerSpecificData() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ManufacturerSpecificData(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>::Advertisement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter)->get_Advertisement(&value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>::Advertisement(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter)->put_Advertisement(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>::BytePatterns() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter)->get_BytePatterns(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Status() const
    {
        winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Advertisement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->get_Advertisement(&value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->add_StatusChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged_revoker consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->remove_StatusChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::PreferredTransmitPowerLevelInDBm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->get_PreferredTransmitPowerLevelInDBm(&value));
        return winrt::Windows::Foundation::IReference<int16_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::PreferredTransmitPowerLevelInDBm(winrt::Windows::Foundation::IReference<int16_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->put_PreferredTransmitPowerLevelInDBm(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::UseExtendedAdvertisement() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->get_UseExtendedAdvertisement(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::UseExtendedAdvertisement(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->put_UseExtendedAdvertisement(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::IsAnonymous() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->get_IsAnonymous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::IsAnonymous(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->put_IsAnonymous(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::IncludeTransmitPowerLevel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->get_IncludeTransmitPowerLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>::IncludeTransmitPowerLevel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2)->put_IncludeTransmitPowerLevel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherFactory<D>::Create(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& advertisement) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory)->Create(*(void**)(&advertisement), &value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs<D>::Error() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs)->get_Error(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2<D>::SelectedTransmitPowerLevelInDBm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2)->get_SelectedTransmitPowerLevelInDBm(&value));
        return winrt::Windows::Foundation::IReference<int16_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int16_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::RawSignalStrengthInDBm() const
    {
        int16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_RawSignalStrengthInDBm(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::BluetoothAddress() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_BluetoothAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::AdvertisementType() const
    {
        winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_AdvertisementType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::Timestamp() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::Advertisement() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_Advertisement(&value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothAddressType) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::BluetoothAddressType() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothAddressType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_BluetoothAddressType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::TransmitPowerLevelInDBm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_TransmitPowerLevelInDBm(&value));
        return winrt::Windows::Foundation::IReference<int16_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::IsAnonymous() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_IsAnonymous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::IsConnectable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_IsConnectable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::IsScannable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_IsScannable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::IsDirected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_IsDirected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>::IsScanResponse() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2)->get_IsScanResponse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MinSamplingInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MinSamplingInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MaxSamplingInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MaxSamplingInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MinOutOfRangeTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MinOutOfRangeTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MaxOutOfRangeTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MaxOutOfRangeTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Status() const
    {
        winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::ScanningMode() const
    {
        winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_ScanningMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::ScanningMode(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->put_ScanningMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::SignalStrengthFilter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_SignalStrengthFilter(&value));
        return winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::SignalStrengthFilter(winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->put_SignalStrengthFilter(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::AdvertisementFilter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_AdvertisementFilter(&value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::AdvertisementFilter(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->put_AdvertisementFilter(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->add_Received(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received_revoker consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Received_revoker>(this, Received(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->remove_Received(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped_revoker consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher2<D>::AllowExtendedAdvertisements() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2)->get_AllowExtendedAdvertisements(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher2<D>::AllowExtendedAdvertisements(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2)->put_AllowExtendedAdvertisements(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherFactory<D>::Create(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& advertisementFilter) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory)->Create(*(void**)(&advertisementFilter), &value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherStoppedEventArgs<D>::Error() const
    {
        winrt::Windows::Devices::Bluetooth::BluetoothError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs)->get_Error(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::CompanyId() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->get_CompanyId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::CompanyId(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->put_CompanyId(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::Data(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData) consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerDataFactory<D>::Create(uint16_t companyId, winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory)->Create(companyId, *(void**)(&data), &value));
        return winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement>
    {
        int32_t __stdcall get_Flags(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>>(this->shim().Flags());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Flags(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Flags(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LocalName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LocalName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceUuids(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::guid>>(this->shim().ServiceUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManufacturerData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>>(this->shim().ManufacturerData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataSections(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>>(this->shim().DataSections());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetManufacturerDataByCompanyId(uint16_t companyId, void** dataList) noexcept final try
        {
            clear_abi(dataList);
            typename D::abi_guard guard(this->shim());
            *dataList = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>>(this->shim().GetManufacturerDataByCompanyId(companyId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSectionsByType(uint8_t type, void** sectionList) noexcept final try
        {
            clear_abi(sectionList);
            typename D::abi_guard guard(this->shim());
            *sectionList = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>>(this->shim().GetSectionsByType(type));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern>
    {
        int32_t __stdcall get_DataType(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataType(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataType(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Offset(int16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int16_t>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Offset(int16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Offset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>
    {
        int32_t __stdcall Create(uint8_t dataType, int16_t offset, void* data, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>(this->shim().Create(dataType, offset, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection>
    {
        int32_t __stdcall get_DataType(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DataType(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataType(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>
    {
        int32_t __stdcall Create(uint8_t dataType, void* data, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>(this->shim().Create(dataType, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>
    {
        int32_t __stdcall get_Flags(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Flags());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncompleteService16BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().IncompleteService16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompleteService16BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().CompleteService16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncompleteService32BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().IncompleteService32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompleteService32BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().CompleteService32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncompleteService128BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().IncompleteService128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompleteService128BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().CompleteService128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShortenedLocalName(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ShortenedLocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CompleteLocalName(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().CompleteLocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TxPowerLevel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().TxPowerLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PeripheralConnectionIntervalRange(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().PeripheralConnectionIntervalRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceSolicitation16BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ServiceSolicitation16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceSolicitation32BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ServiceSolicitation32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceSolicitation128BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ServiceSolicitation128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceData16BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ServiceData16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceData32BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ServiceData32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ServiceData128BitUuids(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ServiceData128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublicTargetAddress(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().PublicTargetAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RandomTargetAddress(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().RandomTargetAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Appearance(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AdvertisingInterval(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().AdvertisingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManufacturerSpecificData(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ManufacturerSpecificData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter>
    {
        int32_t __stdcall get_Advertisement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>(this->shim().Advertisement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Advertisement(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Advertisement(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BytePatterns(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>>(this->shim().BytePatterns());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Advertisement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>(this->shim().Advertisement());
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
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StatusChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StatusChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2>
    {
        int32_t __stdcall get_PreferredTransmitPowerLevelInDBm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int16_t>>(this->shim().PreferredTransmitPowerLevelInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferredTransmitPowerLevelInDBm(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferredTransmitPowerLevelInDBm(*reinterpret_cast<winrt::Windows::Foundation::IReference<int16_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UseExtendedAdvertisement(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UseExtendedAdvertisement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UseExtendedAdvertisement(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UseExtendedAdvertisement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAnonymous(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAnonymous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAnonymous(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAnonymous(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeTransmitPowerLevel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IncludeTransmitPowerLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncludeTransmitPowerLevel(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncludeTransmitPowerLevel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>
    {
        int32_t __stdcall Create(void* advertisement, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const*>(&advertisement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Error(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2>
    {
        int32_t __stdcall get_SelectedTransmitPowerLevelInDBm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int16_t>>(this->shim().SelectedTransmitPowerLevelInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs>
    {
        int32_t __stdcall get_RawSignalStrengthInDBm(int16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int16_t>(this->shim().RawSignalStrengthInDBm());
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
        int32_t __stdcall get_AdvertisementType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType>(this->shim().AdvertisementType());
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
        int32_t __stdcall get_Advertisement(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>(this->shim().Advertisement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2>
    {
        int32_t __stdcall get_BluetoothAddressType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothAddressType>(this->shim().BluetoothAddressType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TransmitPowerLevelInDBm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int16_t>>(this->shim().TransmitPowerLevelInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAnonymous(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAnonymous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConnectable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConnectable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsScannable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScannable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDirected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDirected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsScanResponse(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScanResponse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>
    {
        int32_t __stdcall get_MinSamplingInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MinSamplingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSamplingInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MaxSamplingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinOutOfRangeTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MinOutOfRangeTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxOutOfRangeTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MaxOutOfRangeTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScanningMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode>(this->shim().ScanningMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScanningMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScanningMode(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignalStrengthFilter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter>(this->shim().SignalStrengthFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SignalStrengthFilter(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignalStrengthFilter(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AdvertisementFilter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter>(this->shim().AdvertisementFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AdvertisementFilter(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AdvertisementFilter(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const*>(&value));
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
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Received(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Received(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Received(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Received(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2>
    {
        int32_t __stdcall get_AllowExtendedAdvertisements(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AllowExtendedAdvertisements());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AllowExtendedAdvertisements(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AllowExtendedAdvertisements(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>
    {
        int32_t __stdcall Create(void* advertisementFilter, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const*>(&advertisementFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs>
    {
        int32_t __stdcall get_Error(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData>
    {
        int32_t __stdcall get_CompanyId(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().CompanyId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CompanyId(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompanyId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory> : produce_base<D, winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>
    {
        int32_t __stdcall Create(uint16_t companyId, void* data, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>(this->shim().Create(companyId, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Advertisement
{
    constexpr auto operator|(BluetoothLEAdvertisementFlags const left, BluetoothLEAdvertisementFlags const right) noexcept
    {
        return static_cast<BluetoothLEAdvertisementFlags>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(BluetoothLEAdvertisementFlags& left, BluetoothLEAdvertisementFlags const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(BluetoothLEAdvertisementFlags const left, BluetoothLEAdvertisementFlags const right) noexcept
    {
        return static_cast<BluetoothLEAdvertisementFlags>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(BluetoothLEAdvertisementFlags& left, BluetoothLEAdvertisementFlags const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(BluetoothLEAdvertisementFlags const value) noexcept
    {
        return static_cast<BluetoothLEAdvertisementFlags>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(BluetoothLEAdvertisementFlags const left, BluetoothLEAdvertisementFlags const right) noexcept
    {
        return static_cast<BluetoothLEAdvertisementFlags>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(BluetoothLEAdvertisementFlags& left, BluetoothLEAdvertisementFlags const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline BluetoothLEAdvertisement::BluetoothLEAdvertisement() :
        BluetoothLEAdvertisement(impl::call_factory_cast<BluetoothLEAdvertisement(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEAdvertisement>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEAdvertisement>(); }))
    {
    }
    inline BluetoothLEAdvertisementBytePattern::BluetoothLEAdvertisementBytePattern() :
        BluetoothLEAdvertisementBytePattern(impl::call_factory_cast<BluetoothLEAdvertisementBytePattern(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEAdvertisementBytePattern>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEAdvertisementBytePattern>(); }))
    {
    }
    inline BluetoothLEAdvertisementBytePattern::BluetoothLEAdvertisementBytePattern(uint8_t dataType, int16_t offset, winrt::Windows::Storage::Streams::IBuffer const& data) :
        BluetoothLEAdvertisementBytePattern(impl::call_factory<BluetoothLEAdvertisementBytePattern, IBluetoothLEAdvertisementBytePatternFactory>([&](IBluetoothLEAdvertisementBytePatternFactory const& f) { return f.Create(dataType, offset, data); }))
    {
    }
    inline BluetoothLEAdvertisementDataSection::BluetoothLEAdvertisementDataSection() :
        BluetoothLEAdvertisementDataSection(impl::call_factory_cast<BluetoothLEAdvertisementDataSection(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEAdvertisementDataSection>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEAdvertisementDataSection>(); }))
    {
    }
    inline BluetoothLEAdvertisementDataSection::BluetoothLEAdvertisementDataSection(uint8_t dataType, winrt::Windows::Storage::Streams::IBuffer const& data) :
        BluetoothLEAdvertisementDataSection(impl::call_factory<BluetoothLEAdvertisementDataSection, IBluetoothLEAdvertisementDataSectionFactory>([&](IBluetoothLEAdvertisementDataSectionFactory const& f) { return f.Create(dataType, data); }))
    {
    }
    inline auto BluetoothLEAdvertisementDataTypes::Flags()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.Flags(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::IncompleteService16BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.IncompleteService16BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::CompleteService16BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.CompleteService16BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::IncompleteService32BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.IncompleteService32BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::CompleteService32BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.CompleteService32BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::IncompleteService128BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.IncompleteService128BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::CompleteService128BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.CompleteService128BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ShortenedLocalName()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ShortenedLocalName(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::CompleteLocalName()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.CompleteLocalName(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::TxPowerLevel()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.TxPowerLevel(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::PeripheralConnectionIntervalRange()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.PeripheralConnectionIntervalRange(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ServiceSolicitation16BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ServiceSolicitation16BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ServiceSolicitation32BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ServiceSolicitation32BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ServiceSolicitation128BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ServiceSolicitation128BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ServiceData16BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ServiceData16BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ServiceData32BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ServiceData32BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ServiceData128BitUuids()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ServiceData128BitUuids(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::PublicTargetAddress()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.PublicTargetAddress(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::RandomTargetAddress()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.RandomTargetAddress(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::Appearance()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.Appearance(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::AdvertisingInterval()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.AdvertisingInterval(); });
    }
    inline auto BluetoothLEAdvertisementDataTypes::ManufacturerSpecificData()
    {
        return impl::call_factory_cast<uint8_t(*)(IBluetoothLEAdvertisementDataTypesStatics const&), BluetoothLEAdvertisementDataTypes, IBluetoothLEAdvertisementDataTypesStatics>([](IBluetoothLEAdvertisementDataTypesStatics const& f) { return f.ManufacturerSpecificData(); });
    }
    inline BluetoothLEAdvertisementFilter::BluetoothLEAdvertisementFilter() :
        BluetoothLEAdvertisementFilter(impl::call_factory_cast<BluetoothLEAdvertisementFilter(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEAdvertisementFilter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEAdvertisementFilter>(); }))
    {
    }
    inline BluetoothLEAdvertisementPublisher::BluetoothLEAdvertisementPublisher() :
        BluetoothLEAdvertisementPublisher(impl::call_factory_cast<BluetoothLEAdvertisementPublisher(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEAdvertisementPublisher>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEAdvertisementPublisher>(); }))
    {
    }
    inline BluetoothLEAdvertisementPublisher::BluetoothLEAdvertisementPublisher(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& advertisement) :
        BluetoothLEAdvertisementPublisher(impl::call_factory<BluetoothLEAdvertisementPublisher, IBluetoothLEAdvertisementPublisherFactory>([&](IBluetoothLEAdvertisementPublisherFactory const& f) { return f.Create(advertisement); }))
    {
    }
    inline BluetoothLEAdvertisementWatcher::BluetoothLEAdvertisementWatcher() :
        BluetoothLEAdvertisementWatcher(impl::call_factory_cast<BluetoothLEAdvertisementWatcher(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEAdvertisementWatcher>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEAdvertisementWatcher>(); }))
    {
    }
    inline BluetoothLEAdvertisementWatcher::BluetoothLEAdvertisementWatcher(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& advertisementFilter) :
        BluetoothLEAdvertisementWatcher(impl::call_factory<BluetoothLEAdvertisementWatcher, IBluetoothLEAdvertisementWatcherFactory>([&](IBluetoothLEAdvertisementWatcherFactory const& f) { return f.Create(advertisementFilter); }))
    {
    }
    inline BluetoothLEManufacturerData::BluetoothLEManufacturerData() :
        BluetoothLEManufacturerData(impl::call_factory_cast<BluetoothLEManufacturerData(*)(winrt::Windows::Foundation::IActivationFactory const&), BluetoothLEManufacturerData>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BluetoothLEManufacturerData>(); }))
    {
    }
    inline BluetoothLEManufacturerData::BluetoothLEManufacturerData(uint16_t companyId, winrt::Windows::Storage::Streams::IBuffer const& data) :
        BluetoothLEManufacturerData(impl::call_factory<BluetoothLEManufacturerData, IBluetoothLEManufacturerDataFactory>([&](IBluetoothLEManufacturerDataFactory const& f) { return f.Create(companyId, data); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataTypes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
