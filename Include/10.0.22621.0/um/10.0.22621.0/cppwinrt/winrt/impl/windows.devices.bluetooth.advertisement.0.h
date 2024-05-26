// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_Advertisement_0_H
#define WINRT_Windows_Devices_Bluetooth_Advertisement_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth
{
    enum class BluetoothAddressType : int32_t;
    enum class BluetoothError : int32_t;
    struct BluetoothSignalStrengthFilter;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Advertisement
{
    enum class BluetoothLEAdvertisementFlags : uint32_t
    {
        None = 0,
        LimitedDiscoverableMode = 0x1,
        GeneralDiscoverableMode = 0x2,
        ClassicNotSupported = 0x4,
        DualModeControllerCapable = 0x8,
        DualModeHostCapable = 0x10,
    };
    enum class BluetoothLEAdvertisementPublisherStatus : int32_t
    {
        Created = 0,
        Waiting = 1,
        Started = 2,
        Stopping = 3,
        Stopped = 4,
        Aborted = 5,
    };
    enum class BluetoothLEAdvertisementType : int32_t
    {
        ConnectableUndirected = 0,
        ConnectableDirected = 1,
        ScannableUndirected = 2,
        NonConnectableUndirected = 3,
        ScanResponse = 4,
        Extended = 5,
    };
    enum class BluetoothLEAdvertisementWatcherStatus : int32_t
    {
        Created = 0,
        Started = 1,
        Stopping = 2,
        Stopped = 3,
        Aborted = 4,
    };
    enum class BluetoothLEScanningMode : int32_t
    {
        Passive = 0,
        Active = 1,
        None = 2,
    };
    struct IBluetoothLEAdvertisement;
    struct IBluetoothLEAdvertisementBytePattern;
    struct IBluetoothLEAdvertisementBytePatternFactory;
    struct IBluetoothLEAdvertisementDataSection;
    struct IBluetoothLEAdvertisementDataSectionFactory;
    struct IBluetoothLEAdvertisementDataTypesStatics;
    struct IBluetoothLEAdvertisementFilter;
    struct IBluetoothLEAdvertisementPublisher;
    struct IBluetoothLEAdvertisementPublisher2;
    struct IBluetoothLEAdvertisementPublisherFactory;
    struct IBluetoothLEAdvertisementPublisherStatusChangedEventArgs;
    struct IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2;
    struct IBluetoothLEAdvertisementReceivedEventArgs;
    struct IBluetoothLEAdvertisementReceivedEventArgs2;
    struct IBluetoothLEAdvertisementWatcher;
    struct IBluetoothLEAdvertisementWatcher2;
    struct IBluetoothLEAdvertisementWatcherFactory;
    struct IBluetoothLEAdvertisementWatcherStoppedEventArgs;
    struct IBluetoothLEManufacturerData;
    struct IBluetoothLEManufacturerDataFactory;
    struct BluetoothLEAdvertisement;
    struct BluetoothLEAdvertisementBytePattern;
    struct BluetoothLEAdvertisementDataSection;
    struct BluetoothLEAdvertisementDataTypes;
    struct BluetoothLEAdvertisementFilter;
    struct BluetoothLEAdvertisementPublisher;
    struct BluetoothLEAdvertisementPublisherStatusChangedEventArgs;
    struct BluetoothLEAdvertisementReceivedEventArgs;
    struct BluetoothLEAdvertisementWatcher;
    struct BluetoothLEAdvertisementWatcherStoppedEventArgs;
    struct BluetoothLEManufacturerData;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataTypes>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisement";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementBytePattern";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementDataSection";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataTypes> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementDataTypes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementFilter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementPublisher";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementPublisherStatusChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcherStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEManufacturerData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementFlags";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementPublisherStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcherStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode> = L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisement";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementBytePattern";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementBytePatternFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementDataSection";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementDataSectionFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementDataTypesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementFilter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementPublisher";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementPublisher2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementPublisherFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementPublisherStatusChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementReceivedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementWatcher";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementWatcher2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementWatcherFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEAdvertisementWatcherStoppedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEManufacturerData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory> = L"Windows.Devices.Bluetooth.Advertisement.IBluetoothLEManufacturerDataFactory";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement>{ 0x066FB2B7,0x33D1,0x4E7D,{ 0x83,0x67,0xCF,0x81,0xD0,0xF7,0x96,0x53 } }; // 066FB2B7-33D1-4E7D-8367-CF81D0F79653
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern>{ 0xFBFAD7F2,0xB9C5,0x4A08,{ 0xBC,0x51,0x50,0x2F,0x8E,0xF6,0x8A,0x79 } }; // FBFAD7F2-B9C5-4A08-BC51-502F8EF68A79
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>{ 0xC2E24D73,0xFD5C,0x4EC3,{ 0xBE,0x2A,0x9C,0xA6,0xFA,0x11,0xB7,0xBD } }; // C2E24D73-FD5C-4EC3-BE2A-9CA6FA11B7BD
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection>{ 0xD7213314,0x3A43,0x40F9,{ 0xB6,0xF0,0x92,0xBF,0xEF,0xC3,0x4A,0xE3 } }; // D7213314-3A43-40F9-B6F0-92BFEFC34AE3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>{ 0xE7A40942,0xA845,0x4045,{ 0xBF,0x7E,0x3E,0x99,0x71,0xDB,0x8A,0x6B } }; // E7A40942-A845-4045-BF7E-3E9971DB8A6B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>{ 0x3BB6472F,0x0606,0x434B,{ 0xA7,0x6E,0x74,0x15,0x9F,0x06,0x84,0xD3 } }; // 3BB6472F-0606-434B-A76E-74159F0684D3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter>{ 0x131EB0D3,0xD04E,0x47B1,{ 0x83,0x7E,0x49,0x40,0x5B,0xF6,0xF8,0x0F } }; // 131EB0D3-D04E-47B1-837E-49405BF6F80F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>{ 0xCDE820F9,0xD9FA,0x43D6,{ 0xA2,0x64,0xDD,0xD8,0xB7,0xDA,0x8B,0x78 } }; // CDE820F9-D9FA-43D6-A264-DDD8B7DA8B78
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2>{ 0xFBDB545E,0x56F1,0x510F,{ 0xA4,0x34,0x21,0x7F,0xBD,0x9E,0x7B,0xD2 } }; // FBDB545E-56F1-510F-A434-217FBD9E7BD2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>{ 0x5C5F065E,0xB863,0x4981,{ 0xA1,0xAF,0x1C,0x54,0x4D,0x8B,0x0C,0x0D } }; // 5C5F065E-B863-4981-A1AF-1C544D8B0C0D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs>{ 0x09C2BD9F,0x2DFF,0x4B23,{ 0x86,0xEE,0x0D,0x14,0xFB,0x94,0xAE,0xAE } }; // 09C2BD9F-2DFF-4B23-86EE-0D14FB94AEAE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2>{ 0x8F62790E,0xDC88,0x5C8B,{ 0xB3,0x4E,0x10,0xB3,0x21,0x85,0x0F,0x88 } }; // 8F62790E-DC88-5C8B-B34E-10B321850F88
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs>{ 0x27987DDF,0xE596,0x41BE,{ 0x8D,0x43,0x9E,0x67,0x31,0xD4,0xA9,0x13 } }; // 27987DDF-E596-41BE-8D43-9E6731D4A913
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2>{ 0x12D9C87B,0x0399,0x5F0E,{ 0xA3,0x48,0x53,0xB0,0x2B,0x6B,0x16,0x2E } }; // 12D9C87B-0399-5F0E-A348-53B02B6B162E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>{ 0xA6AC336F,0xF3D3,0x4297,{ 0x8D,0x6C,0xC8,0x1E,0xA6,0x62,0x3F,0x40 } }; // A6AC336F-F3D3-4297-8D6C-C81EA6623F40
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2>{ 0x01BF26BC,0xB164,0x5805,{ 0x90,0xA3,0xE8,0xA7,0x99,0x7F,0xF2,0x25 } }; // 01BF26BC-B164-5805-90A3-E8A7997FF225
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>{ 0x9AAF2D56,0x39AC,0x453E,{ 0xB3,0x2A,0x85,0xC6,0x57,0xE0,0x17,0xF1 } }; // 9AAF2D56-39AC-453E-B32A-85C657E017F1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs>{ 0xDD40F84D,0xE7B9,0x43E3,{ 0x9C,0x04,0x06,0x85,0xD0,0x85,0xFD,0x8C } }; // DD40F84D-E7B9-43E3-9C04-0685D085FD8C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData>{ 0x912DBA18,0x6963,0x4533,{ 0xB0,0x61,0x46,0x94,0xDA,0xFB,0x34,0xE5 } }; // 912DBA18-6963-4533-B061-4694DAFB34E5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>{ 0xC09B39F8,0x319A,0x441E,{ 0x8D,0xE5,0x66,0xA8,0x1E,0x87,0x7A,0x6C } }; // C09B39F8-319A-441E-8DE5-66A81E877A6C
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>{ using type = winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData; };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Flags(void**) noexcept = 0;
            virtual int32_t __stdcall put_Flags(void*) noexcept = 0;
            virtual int32_t __stdcall get_LocalName(void**) noexcept = 0;
            virtual int32_t __stdcall put_LocalName(void*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceUuids(void**) noexcept = 0;
            virtual int32_t __stdcall get_ManufacturerData(void**) noexcept = 0;
            virtual int32_t __stdcall get_DataSections(void**) noexcept = 0;
            virtual int32_t __stdcall GetManufacturerDataByCompanyId(uint16_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetSectionsByType(uint8_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DataType(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall put_DataType(uint8_t) noexcept = 0;
            virtual int32_t __stdcall get_Offset(int16_t*) noexcept = 0;
            virtual int32_t __stdcall put_Offset(int16_t) noexcept = 0;
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall put_Data(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(uint8_t, int16_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DataType(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall put_DataType(uint8_t) noexcept = 0;
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall put_Data(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(uint8_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Flags(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncompleteService16BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_CompleteService16BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncompleteService32BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_CompleteService32BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncompleteService128BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_CompleteService128BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ShortenedLocalName(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_CompleteLocalName(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_TxPowerLevel(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_PeripheralConnectionIntervalRange(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceSolicitation16BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceSolicitation32BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceSolicitation128BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceData16BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceData32BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceData128BitUuids(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_PublicTargetAddress(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_RandomTargetAddress(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_Appearance(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_AdvertisingInterval(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall get_ManufacturerSpecificData(uint8_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Advertisement(void**) noexcept = 0;
            virtual int32_t __stdcall put_Advertisement(void*) noexcept = 0;
            virtual int32_t __stdcall get_BytePatterns(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Advertisement(void**) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall add_StatusChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PreferredTransmitPowerLevelInDBm(void**) noexcept = 0;
            virtual int32_t __stdcall put_PreferredTransmitPowerLevelInDBm(void*) noexcept = 0;
            virtual int32_t __stdcall get_UseExtendedAdvertisement(bool*) noexcept = 0;
            virtual int32_t __stdcall put_UseExtendedAdvertisement(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsAnonymous(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAnonymous(bool) noexcept = 0;
            virtual int32_t __stdcall get_IncludeTransmitPowerLevel(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IncludeTransmitPowerLevel(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Error(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SelectedTransmitPowerLevelInDBm(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RawSignalStrengthInDBm(int16_t*) noexcept = 0;
            virtual int32_t __stdcall get_BluetoothAddress(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_AdvertisementType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Advertisement(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_BluetoothAddressType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TransmitPowerLevelInDBm(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsAnonymous(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsConnectable(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsScannable(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDirected(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsScanResponse(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MinSamplingInterval(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxSamplingInterval(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_MinOutOfRangeTimeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxOutOfRangeTimeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ScanningMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ScanningMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_SignalStrengthFilter(void**) noexcept = 0;
            virtual int32_t __stdcall put_SignalStrengthFilter(void*) noexcept = 0;
            virtual int32_t __stdcall get_AdvertisementFilter(void**) noexcept = 0;
            virtual int32_t __stdcall put_AdvertisementFilter(void*) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall add_Received(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Received(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Stopped(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Stopped(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowExtendedAdvertisements(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowExtendedAdvertisements(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Error(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CompanyId(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall put_CompanyId(uint16_t) noexcept = 0;
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall put_Data(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(uint16_t, void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>) Flags() const;
        WINRT_IMPL_AUTO(void) Flags(winrt::Windows::Foundation::IReference<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LocalName() const;
        WINRT_IMPL_AUTO(void) LocalName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::guid>) ServiceUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>) ManufacturerData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>) DataSections() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>) GetManufacturerDataByCompanyId(uint16_t companyId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>) GetSectionsByType(uint8_t type) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) DataType() const;
        WINRT_IMPL_AUTO(void) DataType(uint8_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int16_t) Offset() const;
        WINRT_IMPL_AUTO(void) Offset(int16_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Data() const;
        WINRT_IMPL_AUTO(void) Data(winrt::Windows::Storage::Streams::IBuffer const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePatternFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern) Create(uint8_t dataType, int16_t offset, winrt::Windows::Storage::Streams::IBuffer const& data) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePatternFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) DataType() const;
        WINRT_IMPL_AUTO(void) DataType(uint8_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Data() const;
        WINRT_IMPL_AUTO(void) Data(winrt::Windows::Storage::Streams::IBuffer const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSectionFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection) Create(uint8_t dataType, winrt::Windows::Storage::Streams::IBuffer const& data) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSectionFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) Flags() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) IncompleteService16BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) CompleteService16BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) IncompleteService32BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) CompleteService32BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) IncompleteService128BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) CompleteService128BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ShortenedLocalName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) CompleteLocalName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) TxPowerLevel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) PeripheralConnectionIntervalRange() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ServiceSolicitation16BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ServiceSolicitation32BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ServiceSolicitation128BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ServiceData16BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ServiceData32BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ServiceData128BitUuids() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) PublicTargetAddress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) RandomTargetAddress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) Appearance() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) AdvertisingInterval() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint8_t) ManufacturerSpecificData() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement) Advertisement() const;
        WINRT_IMPL_AUTO(void) Advertisement(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>) BytePatterns() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement) Advertisement() const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const& handler) const;
        using StatusChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher, &impl::abi_t<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>::remove_StatusChanged>;
        [[nodiscard]] StatusChanged_revoker StatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) PreferredTransmitPowerLevelInDBm() const;
        WINRT_IMPL_AUTO(void) PreferredTransmitPowerLevelInDBm(winrt::Windows::Foundation::IReference<int16_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) UseExtendedAdvertisement() const;
        WINRT_IMPL_AUTO(void) UseExtendedAdvertisement(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAnonymous() const;
        WINRT_IMPL_AUTO(void) IsAnonymous(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IncludeTransmitPowerLevel() const;
        WINRT_IMPL_AUTO(void) IncludeTransmitPowerLevel(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher) Create(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& advertisement) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) Error() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) SelectedTransmitPowerLevelInDBm() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int16_t) RawSignalStrengthInDBm() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) BluetoothAddress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType) AdvertisementType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement) Advertisement() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothAddressType) BluetoothAddressType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) TransmitPowerLevelInDBm() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAnonymous() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsConnectable() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScannable() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDirected() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScanResponse() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) MinSamplingInterval() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) MaxSamplingInterval() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) MinOutOfRangeTimeout() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) MaxOutOfRangeTimeout() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode) ScanningMode() const;
        WINRT_IMPL_AUTO(void) ScanningMode(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter) SignalStrengthFilter() const;
        WINRT_IMPL_AUTO(void) SignalStrengthFilter(winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter) AdvertisementFilter() const;
        WINRT_IMPL_AUTO(void) AdvertisementFilter(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& value) const;
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(winrt::event_token) Received(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const& handler) const;
        using Received_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher, &impl::abi_t<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>::remove_Received>;
        [[nodiscard]] Received_revoker Received(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Received(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const& handler) const;
        using Stopped_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher, &impl::abi_t<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>::remove_Stopped>;
        [[nodiscard]] Stopped_revoker Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Stopped(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowExtendedAdvertisements() const;
        WINRT_IMPL_AUTO(void) AllowExtendedAdvertisements(bool value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher) Create(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& advertisementFilter) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherStoppedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothError) Error() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherStoppedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CompanyId() const;
        WINRT_IMPL_AUTO(void) CompanyId(uint16_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Data() const;
        WINRT_IMPL_AUTO(void) Data(winrt::Windows::Storage::Streams::IBuffer const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerDataFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData) Create(uint16_t companyId, winrt::Windows::Storage::Streams::IBuffer const& data) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerDataFactory<D>;
    };
}
#endif
