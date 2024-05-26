// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_Background_0_H
#define WINRT_Windows_Devices_Bluetooth_Background_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth
{
    struct BluetoothDevice;
    enum class BluetoothError : int32_t;
    enum class BluetoothServiceCapabilities : uint32_t;
    struct BluetoothSignalStrengthFilter;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Advertisement
{
    enum class BluetoothLEAdvertisementPublisherStatus : int32_t;
    struct BluetoothLEAdvertisementReceivedEventArgs;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile
{
    struct GattCharacteristic;
    struct GattLocalService;
    struct GattValueChangedEventArgs;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Rfcomm
{
    struct RfcommServiceId;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) IReference;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Networking::Sockets
{
    struct StreamSocket;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Background
{
    enum class BluetoothEventTriggeringMode : int32_t
    {
        Serial = 0,
        Batch = 1,
        KeepLatest = 2,
    };
    struct IBluetoothLEAdvertisementPublisherTriggerDetails;
    struct IBluetoothLEAdvertisementPublisherTriggerDetails2;
    struct IBluetoothLEAdvertisementWatcherTriggerDetails;
    struct IGattCharacteristicNotificationTriggerDetails;
    struct IGattCharacteristicNotificationTriggerDetails2;
    struct IGattServiceProviderConnection;
    struct IGattServiceProviderConnectionStatics;
    struct IGattServiceProviderTriggerDetails;
    struct IRfcommConnectionTriggerDetails;
    struct IRfcommInboundConnectionInformation;
    struct IRfcommOutboundConnectionInformation;
    struct BluetoothLEAdvertisementPublisherTriggerDetails;
    struct BluetoothLEAdvertisementWatcherTriggerDetails;
    struct GattCharacteristicNotificationTriggerDetails;
    struct GattServiceProviderConnection;
    struct GattServiceProviderTriggerDetails;
    struct RfcommConnectionTriggerDetails;
    struct RfcommInboundConnectionInformation;
    struct RfcommOutboundConnectionInformation;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementPublisherTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementWatcherTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::GattCharacteristicNotificationTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::RfcommConnectionTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::RfcommInboundConnectionInformation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::RfcommOutboundConnectionInformation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementPublisherTriggerDetails> = L"Windows.Devices.Bluetooth.Background.BluetoothLEAdvertisementPublisherTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementWatcherTriggerDetails> = L"Windows.Devices.Bluetooth.Background.BluetoothLEAdvertisementWatcherTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::GattCharacteristicNotificationTriggerDetails> = L"Windows.Devices.Bluetooth.Background.GattCharacteristicNotificationTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection> = L"Windows.Devices.Bluetooth.Background.GattServiceProviderConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderTriggerDetails> = L"Windows.Devices.Bluetooth.Background.GattServiceProviderTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::RfcommConnectionTriggerDetails> = L"Windows.Devices.Bluetooth.Background.RfcommConnectionTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::RfcommInboundConnectionInformation> = L"Windows.Devices.Bluetooth.Background.RfcommInboundConnectionInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::RfcommOutboundConnectionInformation> = L"Windows.Devices.Bluetooth.Background.RfcommOutboundConnectionInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode> = L"Windows.Devices.Bluetooth.Background.BluetoothEventTriggeringMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails> = L"Windows.Devices.Bluetooth.Background.IBluetoothLEAdvertisementPublisherTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails2> = L"Windows.Devices.Bluetooth.Background.IBluetoothLEAdvertisementPublisherTriggerDetails2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails> = L"Windows.Devices.Bluetooth.Background.IBluetoothLEAdvertisementWatcherTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails> = L"Windows.Devices.Bluetooth.Background.IGattCharacteristicNotificationTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2> = L"Windows.Devices.Bluetooth.Background.IGattCharacteristicNotificationTriggerDetails2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection> = L"Windows.Devices.Bluetooth.Background.IGattServiceProviderConnection";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics> = L"Windows.Devices.Bluetooth.Background.IGattServiceProviderConnectionStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails> = L"Windows.Devices.Bluetooth.Background.IGattServiceProviderTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails> = L"Windows.Devices.Bluetooth.Background.IRfcommConnectionTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation> = L"Windows.Devices.Bluetooth.Background.IRfcommInboundConnectionInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation> = L"Windows.Devices.Bluetooth.Background.IRfcommOutboundConnectionInformation";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails>{ 0x610ECA86,0x3480,0x41C9,{ 0xA9,0x18,0x7D,0xDA,0xDF,0x20,0x7E,0x00 } }; // 610ECA86-3480-41C9-A918-7DDADF207E00
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails2>{ 0xD4A3D025,0xC601,0x42D6,{ 0x98,0x29,0x4C,0xCB,0x3F,0x5C,0xD7,0x7F } }; // D4A3D025-C601-42D6-9829-4CCB3F5CD77F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails>{ 0xA7DB5AD7,0x2257,0x4E69,{ 0x97,0x84,0xFE,0xE6,0x45,0xC1,0xDC,0xE0 } }; // A7DB5AD7-2257-4E69-9784-FEE645C1DCE0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails>{ 0x9BA03B18,0x0FEC,0x436A,{ 0x93,0xB1,0xF4,0x6C,0x69,0x75,0x32,0xA2 } }; // 9BA03B18-0FEC-436A-93B1-F46C697532A2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2>{ 0x727A50DC,0x949D,0x454A,{ 0xB1,0x92,0x98,0x34,0x67,0xE3,0xD5,0x0F } }; // 727A50DC-949D-454A-B192-983467E3D50F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection>{ 0x7FA1B9B9,0x2F13,0x40B5,{ 0x95,0x82,0x8E,0xB7,0x8E,0x98,0xEF,0x13 } }; // 7FA1B9B9-2F13-40B5-9582-8EB78E98EF13
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics>{ 0x3D509F4B,0x0B0E,0x4466,{ 0xB8,0xCD,0x6E,0xBD,0xDA,0x1F,0xA1,0x7D } }; // 3D509F4B-0B0E-4466-B8CD-6EBDDA1FA17D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails>{ 0xAE8C0625,0x05FF,0x4AFB,{ 0xB1,0x6A,0xDE,0x95,0xF3,0xCF,0x01,0x58 } }; // AE8C0625-05FF-4AFB-B16A-DE95F3CF0158
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails>{ 0xF922734D,0x2E3C,0x4EFC,{ 0xAB,0x59,0xFC,0x5C,0xF9,0x6F,0x97,0xE3 } }; // F922734D-2E3C-4EFC-AB59-FC5CF96F97E3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation>{ 0x6D3E75A8,0x5429,0x4059,{ 0x92,0xE3,0x1E,0x8B,0x65,0x52,0x87,0x07 } }; // 6D3E75A8-5429-4059-92E3-1E8B65528707
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation>{ 0xB091227B,0xF434,0x4CB0,{ 0x99,0xB1,0x4A,0xB8,0xCE,0xDA,0xED,0xD7 } }; // B091227B-F434-4CB0-99B1-4AB8CEDAEDD7
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementPublisherTriggerDetails>{ using type = winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementWatcherTriggerDetails>{ using type = winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::GattCharacteristicNotificationTriggerDetails>{ using type = winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection>{ using type = winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderTriggerDetails>{ using type = winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::RfcommConnectionTriggerDetails>{ using type = winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::RfcommInboundConnectionInformation>{ using type = winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Background::RfcommOutboundConnectionInformation>{ using type = winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation; };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Error(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SelectedTransmitPowerLevelInDBm(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Error(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Advertisements(void**) noexcept = 0;
            virtual int32_t __stdcall get_SignalStrengthFilter(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Characteristic(void**) noexcept = 0;
            virtual int32_t __stdcall get_Value(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Error(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_EventTriggeringMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ValueChangedEvents(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TriggerId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Service(void**) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllServices(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Connection(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Socket(void**) noexcept = 0;
            virtual int32_t __stdcall get_Incoming(bool*) noexcept = 0;
            virtual int32_t __stdcall get_RemoteDevice(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SdpRecord(void**) noexcept = 0;
            virtual int32_t __stdcall put_SdpRecord(void*) noexcept = 0;
            virtual int32_t __stdcall get_LocalServiceId(void**) noexcept = 0;
            virtual int32_t __stdcall put_LocalServiceId(void*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceCapabilities(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ServiceCapabilities(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RemoteServiceId(void**) noexcept = 0;
            virtual int32_t __stdcall put_RemoteServiceId(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementPublisherTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) Error() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementPublisherTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementPublisherTriggerDetails2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) SelectedTransmitPowerLevelInDBm() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementPublisherTriggerDetails2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementWatcherTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) Error() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs>) Advertisements() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter) SignalStrengthFilter() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementWatcherTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic) Characteristic() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Value() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) Error() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode) EventTriggeringMode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs>) ValueChangedEvents() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnection
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TriggerId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService) Service() const;
        WINRT_IMPL_AUTO(void) Start() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnection<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnectionStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection>) AllServices() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnectionStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection) Connection() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IRfcommConnectionTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::Sockets::StreamSocket) Socket() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Incoming() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDevice) RemoteDevice() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IRfcommConnectionTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) SdpRecord() const;
        WINRT_IMPL_AUTO(void) SdpRecord(winrt::Windows::Storage::Streams::IBuffer const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId) LocalServiceId() const;
        WINRT_IMPL_AUTO(void) LocalServiceId(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities) ServiceCapabilities() const;
        WINRT_IMPL_AUTO(void) ServiceCapabilities(winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Background_IRfcommOutboundConnectionInformation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId) RemoteServiceId() const;
        WINRT_IMPL_AUTO(void) RemoteServiceId(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Background_IRfcommOutboundConnectionInformation<D>;
    };
}
#endif
